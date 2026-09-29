variable "region" {
  type    = string
  default = "us-east-1"
}

variable "role_name" {
  type    = string
  default = "mc-cspm-scanner"
}

variable "trusted_principal_arns" {
  description = "IAM principals (user/role ARNs) allowed to assume the scanner role."
  type        = list(string)
}

variable "external_id" {
  description = "Value required on AssumeRole (confused-deputy protection)."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.external_id) >= 16
    error_message = "Use an external ID of at least 16 characters."
  }
}

variable "github_oidc_provider_arn" {
  description = "Optional: ARN of the token.actions.githubusercontent.com OIDC provider."
  type        = string
  default     = ""
}

variable "github_oidc_subjects" {
  description = "Optional: allowed GitHub OIDC subjects, e.g. [\"repo:Aarpan-Sahu/multicloud-security-posture:ref:refs/heads/main\"]."
  type        = list(string)
  default     = []
}

variable "tags" {
  type    = map(string)
  default = { Project = "multicloud-security-posture", ManagedBy = "terraform" }
}
