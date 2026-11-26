variable "stripe_key" {
  type      = string
  sensitive = true
  # Ephemeral: a saved plan keeps no copy of it. Give it again to the apply of a saved plan.
  ephemeral = true
}

resource "coffre_secret" "stripe" {
  project          = "billing"
  environment      = "prod"
  key              = "STRIPE_KEY"
  value_wo         = var.stripe_key
  value_wo_version = 3 # bump it to write var.stripe_key again
  sensitivity      = "sensitive"
}
