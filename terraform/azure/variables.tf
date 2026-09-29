variable "subscription_ids" {
  description = "Subscriptions the scanner may read."
  type        = list(string)
  validation {
    condition     = length(var.subscription_ids) > 0
    error_message = "Provide at least one subscription ID."
  }
}

variable "app_name" {
  type    = string
  default = "mc-cspm-scanner"
}

variable "github_subject" {
  description = "Optional OIDC subject, e.g. repo:Aarpan-Sahu/multicloud-security-posture:ref:refs/heads/main"
  type        = string
  default     = ""
}
