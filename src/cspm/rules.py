"""Rule catalog: the single source of truth for severity, category and remediation.

Collectors only decide *whether* a rule failed on a resource. Severity is never decided
by a collector or by the LLM, which keeps prioritization deterministic and auditable.
Compliance tags are indicative mappings to benchmark themes, not certified control IDs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding, Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    provider: str
    resource_type: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    compliance: tuple[str, ...] = ()


NET = "Network Exposure"
IAM = "Identity & Access"
DATA = "Data Protection"
LOG = "Logging & Detection"

_RULES: list[Rule] = [
    # ---------------- AWS ----------------
    Rule("AWS-S3-001", "aws", "Object Storage", "S3 bucket is publicly accessible", Severity.CRITICAL, DATA,
         "The bucket policy or ACL grants access to anonymous principals.",
         "Enable S3 Block Public Access at bucket and account level; remove Principal '*' statements.",
         ("CIS AWS: S3 public access", "NIST 800-53 AC-3")),
    Rule("AWS-S3-002", "aws", "Object Storage", "S3 Block Public Access not fully enabled", Severity.MEDIUM, DATA,
         "One or more of the four Block Public Access settings is off, so a future policy change could expose data.",
         "aws s3api put-public-access-block --bucket <name> --public-access-block-configuration "
         "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
         ("CIS AWS: S3 public access",)),
    Rule("AWS-EC2-001", "aws", "Firewall Rule", "Security group allows admin ports from the internet", Severity.HIGH, NET,
         "SSH (22) or RDP (3389) is reachable from 0.0.0.0/0 or ::/0.",
         "Restrict the ingress rule to known CIDRs, or remove it and use SSM Session Manager.",
         ("CIS AWS: Networking", "NIST 800-53 SC-7")),
    Rule("AWS-EC2-002", "aws", "Firewall Rule", "Security group exposes a database port to the internet", Severity.CRITICAL, NET,
         "A database or cache port (e.g. 3306, 5432, 1433, 6379, 27017, 9200) is open to the internet.",
         "Remove the public ingress rule; allow only application security groups.",
         ("NIST 800-53 SC-7",)),
    Rule("AWS-EC2-003", "aws", "Firewall Rule", "Security group allows all traffic from the internet", Severity.CRITICAL, NET,
         "An ingress rule allows all protocols and ports from 0.0.0.0/0 or ::/0.",
         "Replace with explicit, least-privilege port rules.",
         ("CIS AWS: Networking",)),
    Rule("AWS-EC2-004", "aws", "Block Storage", "EBS encryption by default is disabled", Severity.MEDIUM, DATA,
         "New EBS volumes in this region are not encrypted automatically.",
         "aws ec2 enable-ebs-encryption-by-default --region <region>",
         ("CIS AWS: EBS encryption",)),
    Rule("AWS-IAM-001", "aws", "Identity", "Root account has active access keys", Severity.CRITICAL, IAM,
         "Programmatic credentials exist for the root user.",
         "Delete root access keys; use IAM roles for automation.",
         ("CIS AWS: IAM root",)),
    Rule("AWS-IAM-002", "aws", "Identity", "Root account MFA is not enabled", Severity.CRITICAL, IAM,
         "The root user can sign in with a password alone.",
         "Enable a hardware or virtual MFA device on the root account.",
         ("CIS AWS: IAM root",)),
    Rule("AWS-IAM-003", "aws", "Identity", "Console user without MFA", Severity.HIGH, IAM,
         "An IAM user with a console password has no MFA device.",
         "Enforce MFA, or migrate the user to IAM Identity Center with SSO.",
         ("CIS AWS: IAM MFA",)),
    Rule("AWS-IAM-004", "aws", "Identity", "Access key older than 90 days", Severity.MEDIUM, IAM,
         "Long-lived access keys increase the blast radius of a leak.",
         "Rotate the key and prefer short-lived role credentials.",
         ("CIS AWS: Credential rotation",)),
    Rule("AWS-CT-001", "aws", "Audit Logging", "No multi-region CloudTrail is logging", Severity.HIGH, LOG,
         "API activity is not being captured across all regions.",
         "Create an organization or multi-region trail with log file validation enabled.",
         ("CIS AWS: Logging", "NIST 800-53 AU-2")),
    Rule("AWS-GD-001", "aws", "Threat Detection", "GuardDuty is not enabled in region", Severity.MEDIUM, LOG,
         "Threat detection is off in this region.",
         "Enable GuardDuty (ideally org-wide via a delegated administrator).",
         ("NIST 800-53 SI-4",)),
    Rule("AWS-RDS-001", "aws", "Managed Database", "RDS instance is publicly accessible", Severity.HIGH, NET,
         "The DB instance has a public endpoint.",
         "Set PubliclyAccessible=false and place the instance in private subnets.",
         ("NIST 800-53 SC-7",)),
    Rule("AWS-RDS-002", "aws", "Managed Database", "RDS storage is not encrypted", Severity.MEDIUM, DATA,
         "Data at rest for this DB instance is unencrypted.",
         "Snapshot, copy with encryption, and restore to an encrypted instance.",
         ("CIS AWS: RDS encryption",)),
    # ---------------- Azure ----------------
    Rule("AZ-ST-001", "azure", "Object Storage", "Storage account allows public blob access", Severity.HIGH, DATA,
         "Containers in this account can be made anonymously readable.",
         "az storage account update -n <name> -g <rg> --allow-blob-public-access false",
         ("CIS Azure: Storage",)),
    Rule("AZ-ST-002", "azure", "Object Storage", "Storage account permits insecure transport", Severity.MEDIUM, DATA,
         "HTTPS-only is disabled or the minimum TLS version is below 1.2.",
         "Enable 'Secure transfer required' and set minimum TLS to 1.2.",
         ("CIS Azure: Storage",)),
    Rule("AZ-ST-003", "azure", "Object Storage", "Storage account network default action is Allow", Severity.MEDIUM, NET,
         "The storage firewall accepts traffic from all networks.",
         "Set default action to Deny and allow specific VNets / private endpoints.",
         ("CIS Azure: Storage",)),
    Rule("AZ-NSG-001", "azure", "Firewall Rule", "NSG allows admin ports from the internet", Severity.HIGH, NET,
         "An inbound Allow rule exposes SSH (22) or RDP (3389) to Any/Internet.",
         "Restrict source ranges or use Azure Bastion / Just-in-Time VM access.",
         ("CIS Azure: Networking",)),
    Rule("AZ-NSG-002", "azure", "Firewall Rule", "NSG allows all inbound traffic from the internet", Severity.CRITICAL, NET,
         "An inbound Allow rule permits every port from Any/Internet.",
         "Replace with least-privilege port rules.",
         ("CIS Azure: Networking",)),
    Rule("AZ-SQL-001", "azure", "Managed Database", "SQL server firewall open to all IPs", Severity.CRITICAL, NET,
         "A firewall rule allows 0.0.0.0-255.255.255.255.",
         "Delete the rule; use private endpoints or specific client IPs.",
         ("CIS Azure: Database",)),
    Rule("AZ-SQL-002", "azure", "Managed Database", "SQL server allows all Azure services", Severity.LOW, NET,
         "The 0.0.0.0 rule allows any Azure-hosted workload, including other tenants.",
         "Remove 'Allow Azure services' and use private endpoints.",
         ("CIS Azure: Database",)),
    Rule("AZ-KV-001", "azure", "Key Management", "Key Vault purge protection disabled", Severity.MEDIUM, DATA,
         "Deleted keys and secrets can be permanently purged during the retention period.",
         "az keyvault update -n <name> --enable-purge-protection true",
         ("CIS Azure: Key Vault",)),
    # ---------------- GCP ----------------
    Rule("GCP-GCS-001", "gcp", "Object Storage", "Cloud Storage bucket is public", Severity.CRITICAL, DATA,
         "The bucket IAM policy grants a role to allUsers or allAuthenticatedUsers.",
         "Remove allUsers/allAuthenticatedUsers bindings and enforce public access prevention.",
         ("CIS GCP: Storage",)),
    Rule("GCP-GCS-002", "gcp", "Object Storage", "Uniform bucket-level access disabled", Severity.LOW, IAM,
         "Object ACLs can grant access outside of IAM.",
         "gcloud storage buckets update gs://<name> --uniform-bucket-level-access",
         ("CIS GCP: Storage",)),
    Rule("GCP-FW-001", "gcp", "Firewall Rule", "VPC firewall allows admin ports from the internet", Severity.HIGH, NET,
         "An ingress rule allows SSH (22) or RDP (3389) from 0.0.0.0/0.",
         "Restrict source ranges; use IAP TCP forwarding (35.235.240.0/20).",
         ("CIS GCP: Networking",)),
    Rule("GCP-FW-002", "gcp", "Firewall Rule", "VPC firewall allows all traffic from the internet", Severity.CRITICAL, NET,
         "An ingress rule allows all ports from 0.0.0.0/0.",
         "Replace with least-privilege port rules and target tags.",
         ("CIS GCP: Networking",)),
    Rule("GCP-IAM-001", "gcp", "Identity", "Service account has user-managed keys", Severity.MEDIUM, IAM,
         "Exported JSON keys are long-lived credentials that are easy to leak.",
         "Delete user-managed keys; use workload identity federation or attached service accounts.",
         ("CIS GCP: IAM",)),
    Rule("GCP-IAM-002", "gcp", "Identity", "Service account holds a primitive role", Severity.HIGH, IAM,
         "A service account is bound to roles/owner or roles/editor at project level.",
         "Replace with narrowly scoped predefined or custom roles.",
         ("CIS GCP: IAM",)),
    Rule("GCP-IAM-003", "gcp", "Identity", "Project IAM grants access to the public", Severity.CRITICAL, IAM,
         "A project-level binding includes allUsers or allAuthenticatedUsers.",
         "Remove the public member from the project IAM policy.",
         ("CIS GCP: IAM",)),
    Rule("GCP-SQL-001", "gcp", "Managed Database", "Cloud SQL authorized network is 0.0.0.0/0", Severity.CRITICAL, NET,
         "The instance accepts connections from any IPv4 address.",
         "Remove 0.0.0.0/0; use private IP or the Cloud SQL Auth Proxy.",
         ("CIS GCP: Cloud SQL",)),
]

RULES: dict[str, Rule] = {r.rule_id: r for r in _RULES}


def make_finding(
    rule_id: str,
    *,
    account_id: str,
    region: str,
    resource_id: str,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        provider=rule.provider,
        account_id=account_id,
        region=region,
        resource_type=rule.resource_type,
        resource_id=resource_id,
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        remediation=rule.remediation,
        compliance=list(rule.compliance),
        evidence=evidence or {},
    )
