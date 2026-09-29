output "client_id" {
  description = "Set as AZURE_CLIENT_ID for workload identity / federated login."
  value       = azuread_application.scanner.client_id
}

output "service_principal_object_id" {
  value = azuread_service_principal.scanner.object_id
}
