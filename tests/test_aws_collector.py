"""End-to-end test of the AWS collector against moto's in-memory AWS."""

import os

import boto3
import pytest

moto = pytest.importorskip("moto")


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(k, v)
    os.environ.pop("AWS_PROFILE", None)


@moto.mock_aws
def test_aws_collector_detects_misconfigurations():
    from cspm.collectors.aws import AWSCollector

    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="open", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ])
    safe = ec2.create_security_group(GroupName="safe", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=safe, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
    ])
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="no-pab-bucket")
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r-Secret-pw!")

    result = AWSCollector(regions=["us-east-1"]).collect()
    rules = {(f.rule_id, f.resource_id.rsplit("/", 1)[-1]) for f in result.findings}

    assert ("AWS-EC2-001", sg) in rules
    assert ("AWS-EC2-002", sg) in rules
    assert not any(rid == safe for _, rid in rules)
    assert ("AWS-S3-002", "arn:aws:s3:::no-pab-bucket") in {(f.rule_id, f.resource_id) for f in result.findings}
    assert any(f.rule_id == "AWS-IAM-003" for f in result.findings)
    assert any(f.rule_id == "AWS-CT-001" for f in result.findings)
    assert result.scanned_accounts["aws"]


@moto.mock_aws
def test_aws_collector_merges_rules_and_ignores_icmp():
    from cspm.collectors.aws import AWSCollector

    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="two-admin", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ])
    icmp = ec2.create_security_group(GroupName="ping", Description="d", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=icmp, IpPermissions=[
        {"IpProtocol": "icmp", "FromPort": 8, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ])

    result = AWSCollector(regions=["us-east-1"]).collect()
    admin = [f for f in result.findings if f.rule_id == "AWS-EC2-001" and f.resource_id.endswith(sg)]
    assert len(admin) == 1 and admin[0].evidence["ports"] == [22, 3389]
    assert not any(f.resource_id.endswith(icmp) for f in result.findings)


@moto.mock_aws
def test_account_level_block_public_access_suppresses_bucket_finding():
    from cspm.collectors.aws import AWSCollector

    account = boto3.client("sts").get_caller_identity()["Account"]
    boto3.client("s3control", region_name="us-east-1").put_public_access_block(
        AccountId=account, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="covered-by-account-pab")

    result = AWSCollector(regions=["us-east-1"]).collect()
    assert not any(f.rule_id == "AWS-S3-002" for f in result.findings)
