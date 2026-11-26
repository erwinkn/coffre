terraform {
  required_version = ">= 1.11"
  required_providers {
    coffre = {
      source  = "erwinkn/coffre"
      version = "~> 0.1"
    }
  }
}

# In GitHub Actions, with `permissions: id-token: write`: the run's ID token, traded for a
# credential of the service account `token:terraform`, whose trust binding takes this workflow.
provider "coffre" {
  url  = "https://secrets.acme.example"
  oidc = { service = "terraform" }
}

# Anywhere else: the service account's token, from an ephemeral variable, so that no saved
# plan keeps it (TF_VAR_coffre_token).
#
# provider "coffre" {
#   url   = "https://secrets.acme.example"
#   token = var.coffre_token
# }
#
# variable "coffre_token" {
#   type      = string
#   sensitive = true
#   ephemeral = true
# }
