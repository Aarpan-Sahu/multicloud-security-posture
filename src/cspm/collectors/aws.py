"""AWS collector built on boto3. Requires only read-only permissions (see terraform/aws)."""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from ..models import ScanResult, utc_now
from ..netutils import (
    ADMIN_PORTS,
    DATABASE_PORTS,
    is_all_ports,
    is_open_cidr,
    range_hits,
)
from ..rules import make_finding
from .base import BaseCollector

BOTO_CFG = Config(retries={"max_attempts": 8, "mode": "adaptive"}, user_agent_extra="mc-cspm/1.0")
KEY_MAX_AGE_DAYS = 90
PAB_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
# Protocols whose FromPort/ToPort are real ports (ICMP reuses those fields for type/code).
PORT_PROTOCOLS = {"tcp", "udp", "6", "17"}


class AWSCollector(BaseCollector):
    provider = "aws"

    def __init__(
        self,
        profile: str | None = None,
        regions: list[str] | None = None,
        role_arn: str | None = None,
        external_id: str | None = None,
    ) -> None:
        super().__init__()
        self.session = self._session(profile, role_arn, external_id)
        self.regions = regions or self._enabled_regions()
        self.account_id = ""

    # ---------- session / auth ----------
    @staticmethod
    def _session(profile, role_arn, external_id) -> boto3.Session:
        base = boto3.Session(profile_name=profile) if profile else boto3.Session()
        if not role_arn:
            return base
        params = {"RoleArn": role_arn, "RoleSessionName": "mc-cspm-scan", "DurationSeconds": 3600}
        if external_id:
            params["ExternalId"] = external_id
        creds = base.client("sts", config=BOTO_CFG).assume_role(**params)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def _client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region or "us-east-1", config=BOTO_CFG)

    def _enabled_regions(self) -> list[str]:
        ec2 = self._client("ec2")
        resp = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        return sorted(r["RegionName"] for r in resp["Regions"])

    # ---------- entry point ----------
    def collect(self) -> ScanResult:
        self.account_id = self._client("sts").get_caller_identity()["Account"]
        self.add_account(self.account_id)

        with self.check("iam:credential_report"):
            self._check_iam()
        with self.check("s3:buckets"):
            self._check_s3()
        with self.check("cloudtrail"):
            self._check_cloudtrail()
        for region in self.regions:
            with self.check(f"ec2:security_groups:{region}"):
                self._check_security_groups(region)
            with self.check(f"ec2:ebs_default_encryption:{region}"):
                self._check_ebs_default(region)
            with self.check(f"guardduty:{region}"):
                self._check_guardduty(region)
            with self.check(f"rds:{region}"):
                self._check_rds(region)

        self.result.finished_at = utc_now()
        return self.result

    def _emit(self, rule_id: str, region: str, resource_id: str, **evidence) -> None:
        self.emit(make_finding(rule_id, account_id=self.account_id, region=region,
                               resource_id=resource_id, evidence=evidence))

    # ---------- IAM ----------
    def _credential_report(self) -> list[dict]:
        iam = self._client("iam")
        for _ in range(15):
            if iam.generate_credential_report()["State"] == "COMPLETE":
                break
            time.sleep(2)
        content = iam.get_credential_report()["Content"].decode()
        return list(csv.DictReader(io.StringIO(content)))

    def _check_iam(self) -> None:
        now = datetime.now(timezone.utc)
        for row in self._credential_report():
            user = row["user"]
            arn = row["arn"]
            if user == "<root_account>":
                if row["access_key_1_active"] == "true" or row["access_key_2_active"] == "true":
                    self._emit("AWS-IAM-001", "global", arn)
                if row["mfa_active"] != "true":
                    self._emit("AWS-IAM-002", "global", arn)
                continue
            if row["password_enabled"] == "true" and row["mfa_active"] != "true":
                self._emit("AWS-IAM-003", "global", arn, user=user)
            for n in ("1", "2"):
                rotated = row.get(f"access_key_{n}_last_rotated", "N/A")
                if row.get(f"access_key_{n}_active") == "true" and rotated not in ("N/A", ""):
                    age = (now - datetime.fromisoformat(rotated.replace("Z", "+00:00"))).days
                    if age > KEY_MAX_AGE_DAYS:
                        self._emit("AWS-IAM-004", "global", arn, key_slot=n, age_days=age)

    # ---------- S3 ----------
    def _account_public_access_block(self) -> dict[str, bool]:
        try:
            return self._client("s3control").get_public_access_block(
                AccountId=self.account_id)["PublicAccessBlockConfiguration"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            return {}

    def _check_s3(self) -> None:
        # Account-level Block Public Access overrides bucket settings, so a bucket is only
        # at risk for a setting that is off at *both* levels.
        account_pab: dict[str, bool] = {}
        with self.check("s3:account_public_access_block"):
            account_pab = self._account_public_access_block()
        s3 = self._client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            arn = f"arn:aws:s3:::{name}"
            with self.check(f"s3:{name}"):
                location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                # Legacy API values: None means us-east-1 and "EU" means eu-west-1.
                region = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(location, location)
                regional = self._client("s3", region)
                try:
                    status = regional.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
                    if status.get("IsPublic"):
                        self._emit("AWS-S3-001", region, arn, internet_exposed=True, source="bucket policy")
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                        raise
                try:
                    cfg = regional.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                        raise
                    cfg = {}
                disabled = [k for k in PAB_SETTINGS if not (cfg.get(k) or account_pab.get(k))]
                if disabled:
                    self._emit("AWS-S3-002", region, arn, disabled_settings=disabled)

    # ---------- CloudTrail ----------
    def _check_cloudtrail(self) -> None:
        ct = self._client("cloudtrail")
        for trail in ct.describe_trails(includeShadowTrails=True).get("trailList", []):
            if not trail.get("IsMultiRegionTrail"):
                continue
            home = trail.get("HomeRegion", "us-east-1")
            status = self._client("cloudtrail", home).get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging"):
                return
        self._emit("AWS-CT-001", "global", f"arn:aws:cloudtrail:::account/{self.account_id}")

    # ---------- EC2 / network ----------
    def _check_security_groups(self, region: str) -> None:
        ec2 = self._client("ec2", region)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                arn = f"arn:aws:ec2:{region}:{self.account_id}:security-group/{sg['GroupId']}"
                for perm in sg.get("IpPermissions", []):
                    open_sources = [r["CidrIp"] for r in perm.get("IpRanges", []) if is_open_cidr(r.get("CidrIp"))]
                    open_sources += [
                        r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if is_open_cidr(r.get("CidrIpv6"))
                    ]
                    if not open_sources:
                        continue
                    self._evaluate_sg_permission(region, arn, sg, perm, open_sources)

    def _evaluate_sg_permission(self, region, arn, sg, perm, sources) -> None:
        ev = {"internet_exposed": True, "group_name": sg.get("GroupName"), "sources": sources}
        protocol = str(perm.get("IpProtocol", "")).lower()
        if protocol == "-1":
            self._emit("AWS-EC2-003", region, arn, **ev, ports="all")
            return
        if protocol not in PORT_PROTOCOLS:
            return
        rng = (perm.get("FromPort", 0), perm.get("ToPort", 65535))
        if is_all_ports(rng):
            self._emit("AWS-EC2-003", region, arn, **ev, ports=f"{rng[0]}-{rng[1]}")
            return
        if admin := range_hits(rng, ADMIN_PORTS):
            self._emit("AWS-EC2-001", region, arn, **ev, ports=sorted(admin))
        if db := range_hits(rng, DATABASE_PORTS):
            self._emit("AWS-EC2-002", region, arn, **ev, ports=sorted(db))

    def _check_ebs_default(self, region: str) -> None:
        if not self._client("ec2", region).get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
            self._emit("AWS-EC2-004", region, f"arn:aws:ec2:{region}:{self.account_id}:ebs-default")

    def _check_guardduty(self, region: str) -> None:
        if not self._client("guardduty", region).list_detectors().get("DetectorIds"):
            self._emit("AWS-GD-001", region, f"arn:aws:guardduty:{region}:{self.account_id}:detector")

    def _check_rds(self, region: str) -> None:
        rds = self._client("rds", region)
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                arn = db["DBInstanceArn"]
                if db.get("PubliclyAccessible"):
                    self._emit("AWS-RDS-001", region, arn, internet_exposed=True, engine=db.get("Engine"))
                if not db.get("StorageEncrypted"):
                    self._emit("AWS-RDS-002", region, arn, engine=db.get("Engine"))
