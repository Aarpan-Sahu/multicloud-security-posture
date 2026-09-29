# Read-only IAM role the dashboard assumes to scan an AWS account.
# Deploy once per account (or via StackSets / an org module for many accounts).

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "AllowScannerPrincipal"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.trusted_principal_arns
    }
    # Confused-deputy protection: the caller must present the shared external ID.
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }

  dynamic "statement" {
    for_each = length(var.github_oidc_subjects) == 0 ? [] : [1]
    content {
      sid     = "AllowGitHubActionsOIDC"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [var.github_oidc_provider_arn]
      }
      condition {
        test     = "StringEquals"
        variable = "token.actions.githubusercontent.com:aud"
        values   = ["sts.amazonaws.com"]
      }
      condition {
        test     = "StringLike"
        variable = "token.actions.githubusercontent.com:sub"
        values   = var.github_oidc_subjects
      }
    }
  }
}

resource "aws_iam_role" "scanner" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  description          = "Read-only role for the multi-cloud security posture dashboard"
  tags                 = var.tags

  lifecycle {
    precondition {
      condition     = length(var.github_oidc_subjects) == 0 || var.github_oidc_provider_arn != ""
      error_message = "Set github_oidc_provider_arn when github_oidc_subjects is not empty."
    }
  }
}

# AWS-managed read-only audit policy covers describe/list/get across services.
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Explicit supplement for the exact calls the collector makes, so the scan keeps
# working even if the managed policy changes. Still strictly read-only.
data "aws_iam_policy_document" "supplement" {
  statement {
    sid = "ScannerReadOnly"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetAccountPublicAccessBlock",
      "ec2:DescribeRegions",
      "ec2:DescribeSecurityGroups",
      "ec2:GetEbsEncryptionByDefault",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "guardduty:ListDetectors",
      "rds:DescribeDBInstances",
    ]
    resources = ["*"]
  }

  # Belt and braces: never read object data or secrets, even if a broader policy is attached later.
  statement {
    sid    = "DenyDataPlane"
    effect = "Deny"
    actions = [
      "s3:GetObject*",
      "secretsmanager:GetSecretValue",
      "ssm:GetParameter*",
      "kms:Decrypt",
      "dynamodb:GetItem",
      "dynamodb:Scan",
      "dynamodb:Query",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "supplement" {
  name   = "mc-cspm-supplement"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.supplement.json
}
