# Service account with read-only roles for the scanner, plus optional GitHub OIDC
# (Workload Identity Federation) so no JSON key is ever created.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}

provider "google" {
  project = var.host_project_id
}

resource "google_service_account" "scanner" {
  account_id   = var.service_account_id
  display_name = "Multi-cloud CSPM scanner (read-only)"
}

locals {
  # viewer: list buckets, firewalls, Cloud SQL, SA keys. securityReviewer: read IAM policies.
  roles = ["roles/viewer", "roles/iam.securityReviewer"]
  bindings = {
    for pair in setproduct(var.scanned_project_ids, local.roles) :
    "${pair[0]}-${pair[1]}" => { project = pair[0], role = pair[1] }
  }
}

resource "google_project_iam_member" "scanner" {
  for_each = local.bindings
  project  = each.value.project
  role     = each.value.role
  member   = "serviceAccount:${google_service_account.scanner.email}"
}

# People or CI identities allowed to impersonate the scanner (short-lived tokens, no keys).
resource "google_service_account_iam_member" "impersonators" {
  for_each           = toset(var.impersonators)
  service_account_id = google_service_account.scanner.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = each.value
}

# ---------- optional: GitHub Actions Workload Identity Federation ----------
resource "google_iam_workload_identity_pool" "github" {
  count                     = var.github_repository == "" ? 0 : 1
  workload_identity_pool_id = "cspm-github"
  display_name              = "CSPM GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  count                              = var.github_repository == "" ? 0 : 1
  workload_identity_pool_id          = google_iam_workload_identity_pool.github[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  attribute_condition = "assertion.repository == \"${var.github_repository}\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "github_wif" {
  count              = var.github_repository == "" ? 0 : 1
  service_account_id = google_service_account.scanner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.repository/${var.github_repository}"
}
