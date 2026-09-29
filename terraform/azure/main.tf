# Entra ID application + service principal with read-only roles for the scanner.
# Keyless auth: GitHub Actions federated credential (OIDC), or run locally with `az login`.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
    azuread = { source = "hashicorp/azuread", version = "~> 3.0" }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_ids[0]
}

provider "azuread" {}

resource "azuread_application" "scanner" {
  display_name = var.app_name
}

resource "azuread_service_principal" "scanner" {
  client_id = azuread_application.scanner.client_id
}

locals {
  # Reader: list resources and config. Security Reader: Defender for Cloud and security settings.
  role_assignments = {
    for pair in setproduct(var.subscription_ids, ["Reader", "Security Reader"]) :
    "${pair[0]}-${pair[1]}" => { subscription_id = pair[0], role = pair[1] }
  }
}

resource "azurerm_role_assignment" "scanner" {
  for_each             = local.role_assignments
  scope                = "/subscriptions/${each.value.subscription_id}"
  role_definition_name = each.value.role
  principal_id         = azuread_service_principal.scanner.object_id
}

# Optional: keyless auth from a GitHub Actions workflow (no client secret to leak).
resource "azuread_application_federated_identity_credential" "github" {
  count          = var.github_subject == "" ? 0 : 1
  application_id = azuread_application.scanner.id
  display_name   = "github-actions"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = var.github_subject
}
