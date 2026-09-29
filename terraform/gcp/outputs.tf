output "service_account_email" {
  description = "Use with: gcloud auth application-default login --impersonate-service-account=<email>"
  value       = google_service_account.scanner.email
}

output "workload_identity_provider" {
  value = var.github_repository == "" ? null : google_iam_workload_identity_pool_provider.github[0].name
}
