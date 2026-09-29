variable "host_project_id" {
  description = "Project that owns the scanner service account."
  type        = string
}

variable "scanned_project_ids" {
  description = "Projects the scanner may read."
  type        = list(string)
}

variable "service_account_id" {
  type    = string
  default = "mc-cspm-scanner"
}

variable "impersonators" {
  description = "Members allowed to impersonate the SA, e.g. [\"user:me@example.com\"]."
  type        = list(string)
  default     = []
}

variable "github_repository" {
  description = "Optional owner/repo for Workload Identity Federation, e.g. Aarpan-Sahu/multicloud-security-posture."
  type        = string
  default     = ""
}
