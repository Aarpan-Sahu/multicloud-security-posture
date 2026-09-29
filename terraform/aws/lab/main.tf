# OPTIONAL: an intentionally misconfigured, low-cost lab so a live scan has something to find.
# Deploy only in a sandbox account. It creates no compute and stores no data.
#   terraform apply   -> scan -> screenshot -> terraform destroy

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

resource "random_id" "suffix" {
  byte_length = 4
}

data "aws_vpc" "default" {
  default = true
}

# Triggers AWS-EC2-001: SSH open to the internet. Not attached to any instance.
resource "aws_security_group" "open_ssh" {
  name        = "cspm-lab-open-ssh-${random_id.suffix.hex}"
  description = "CSPM lab - intentionally open SSH"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Intentional lab misconfiguration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Purpose = "cspm-lab" }
}

# Triggers AWS-S3-002: Block Public Access not fully enabled. The bucket stays private.
resource "aws_s3_bucket" "weak_pab" {
  bucket        = "cspm-lab-weak-pab-${random_id.suffix.hex}"
  force_destroy = true
  tags          = { Purpose = "cspm-lab" }
}

resource "aws_s3_bucket_public_access_block" "weak_pab" {
  bucket                  = aws_s3_bucket.weak_pab.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

output "lab_resources" {
  value = {
    security_group = aws_security_group.open_ssh.id
    bucket         = aws_s3_bucket.weak_pab.bucket
  }
}
