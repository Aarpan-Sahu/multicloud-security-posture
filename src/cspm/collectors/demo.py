"""Synthetic but realistic findings so the dashboard runs with zero cloud credentials.

Deterministic (seeded) so screenshots and tests are reproducible.
"""

from __future__ import annotations

import random
import zlib
from datetime import datetime, timedelta, timezone

from ..models import ScanResult, utc_now
from ..rules import RULES, make_finding
from .base import BaseCollector

ACCOUNTS = {
    "aws": ["111122223333", "444455556666"],
    "azure": ["0f3c8a4e-1b2d-4c5e-9f60-7a8b9c0d1e2f", "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"],
    "gcp": ["acme-prod-analytics", "acme-dev-sandbox"],
}
REGIONS = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1"],
    "azure": ["eastus", "westeurope", "canadacentral"],
    "gcp": ["us-central1", "europe-west1", "northamerica-northeast1"],
}
NAMES = ["payments", "billing", "customer-data", "ml-features", "logs", "backup", "web", "api",
         "etl", "reporting", "identity", "orders", "staging", "analytics", "vpn"]
# How often each rule tends to appear in a real estate (weight), so the demo looks plausible.
WEIGHTS = {"AWS-S3-002": 6, "AWS-EC2-001": 5, "AWS-IAM-003": 4, "AWS-IAM-004": 5, "AWS-EC2-004": 3,
           "AZ-ST-003": 6, "AZ-NSG-001": 4, "AZ-KV-001": 4, "GCP-GCS-002": 5, "GCP-IAM-001": 5,
           "GCP-FW-001": 4, "AWS-IAM-001": 1, "AWS-IAM-002": 1, "AWS-CT-001": 1}


def _resource_id(provider: str, rtype: str, account: str, region: str, name: str) -> str:
    if provider == "aws":
        svc = {"Object Storage": "s3", "Firewall Rule": "ec2", "Identity": "iam",
               "Managed Database": "rds"}.get(rtype, "ec2")
        if svc == "s3":
            return f"arn:aws:s3:::acme-{name}"
        if svc == "iam":
            return f"arn:aws:iam::{account}:user/{name}-svc"
        if svc == "rds":
            return f"arn:aws:rds:{region}:{account}:db:{name}-db"
        return f"arn:aws:ec2:{region}:{account}:security-group/sg-{zlib.crc32((account + name).encode()):08x}"
    if provider == "azure":
        typ = {"Object Storage": "Microsoft.Storage/storageAccounts", "Firewall Rule":
               "Microsoft.Network/networkSecurityGroups", "Managed Database": "Microsoft.Sql/servers",
               "Key Management": "Microsoft.KeyVault/vaults"}.get(rtype, "Microsoft.Resources/misc")
        return f"/subscriptions/{account}/resourceGroups/rg-{name}/providers/{typ}/{name}{region[:3]}"
    return {"Object Storage": f"//storage.googleapis.com/acme-{name}",
            "Firewall Rule": f"projects/{account}/global/firewalls/allow-{name}",
            "Identity": f"projects/{account}/serviceAccounts/{name}@{account}.iam.gserviceaccount.com",
            "Managed Database": f"projects/{account}/instances/{name}-sql"}.get(
                rtype, f"projects/{account}/{name}")


class DemoCollector(BaseCollector):
    provider = "demo"

    def __init__(self, seed: int = 42, count: int = 120) -> None:
        super().__init__()
        self.rng = random.Random(seed)
        self.count = count

    def collect(self) -> ScanResult:
        rules = list(RULES.values())
        weights = [WEIGHTS.get(r.rule_id, 2) for r in rules]
        now = datetime.now(timezone.utc)
        seen: set[str] = set()
        for p, accts in ACCOUNTS.items():
            self.result.scanned_accounts[p] = list(accts)
        while len(self.result.findings) < self.count:
            rule = self.rng.choices(rules, weights)[0]
            account = self.rng.choice(ACCOUNTS[rule.provider])
            region = "global" if rule.resource_type == "Identity" else self.rng.choice(REGIONS[rule.provider])
            name = self.rng.choice(NAMES)
            rid = _resource_id(rule.provider, rule.resource_type, account, region, name)
            evidence = {"internet_exposed": True} if rule.category == "Network Exposure" or \
                rule.rule_id in ("AWS-S3-001", "GCP-GCS-001", "AZ-ST-001", "GCP-IAM-003") else {}
            if "EC2-001" in rule.rule_id or "FW-001" in rule.rule_id or "NSG-001" in rule.rule_id:
                evidence["ports"] = [self.rng.choice([22, 3389])]
            f = make_finding(rule.rule_id, account_id=account, region=region, resource_id=rid, evidence=evidence)
            if f.finding_id in seen:
                continue
            seen.add(f.finding_id)
            f.detected_at = (now - timedelta(days=self.rng.randint(0, 45),
                                             hours=self.rng.randint(0, 23))).replace(microsecond=0).isoformat()
            self.result.findings.append(f)
        self.result.finished_at = utc_now()
        return self.result
