# terraform-provider-coffre

A Terraform and OpenTofu provider that writes secrets into coffre and never
reads one back: one resource, `coffre_secret`, whose value is a write-only
argument, absent from state and plans. The design, its rules and why:
[docs/design/terraform-provider.md](../docs/design/terraform-provider.md).

```hcl
terraform {
  required_providers {
    coffre = { source = "erwinkn/coffre" }
  }
}

provider "coffre" {
  url     = "https://secrets.acme.example"
  service = "terraform-infra" # GitHub Actions' OIDC: the job has `permissions: id-token: write`
}

resource "coffre_secret" "backup_key" {
  project          = "infra"
  environment      = "prod"
  key              = "SCW_BACKUP_SECRET_KEY"
  sensitivity      = "sensitive"
  value_wo         = var.backup_secret_key # an ephemeral variable, or an ephemeral resource's attribute
  value_wo_version = "1"                   # bump to write it again
}
```

Section 1 and section 7 of the design show where values come from: a
source must keep them out of state and plans too (Scaleway's API key does,
its `scaleway_secret_version.data_wo` does not yet).

It needs Terraform 1.11 or OpenTofu 1.11 (write-only arguments), and a coffre
whose writes name the version they made (0.16 or later).

## Signing in

Exactly one of:

- `service` alone: GitHub Actions' ID token, traded at coffre for a
  five-minute credential, once per Terraform phase and again if an apply
  outlives it.
- `service` with `id_token`: another issuer's ID token, from an ephemeral
  variable. Spent once, so one per phase: `plan -out`, then apply the saved
  plan with a fresh token.
- `token`: a `coffre_svc_` or `coffre_pat_` bearer token, from an ephemeral
  variable (`TF_VAR_coffre_token`).

The provider reads no environment variable of its own; only GitHub's
`ACTIONS_ID_TOKEN_REQUEST_URL` and `_TOKEN`, as the CLI does.

## `coffre_secret`

| Argument | |
|---|---|
| `project`, `environment`, `key` | Where the key lives. A change replaces the resource; the old key is kept. |
| `sensitivity` | `plain`, `secret` or `sensitive`. Stricter marks the current value; looser needs `value_wo_version` changed in the same apply. |
| `value_wo` | The value, write-only. Sent on create and when `value_wo_version` changes, never otherwise. |
| `value_wo_version` | Any string. Change it to write `value_wo` again, as a new version. |
| `on_destroy` | `keep` (default): destroy stops managing the key, which stays. `archive`: destroy archives it, with a credential holding `secret.archive`. |
| `version`, `version_id` | Computed: coffre's current version, which the next write must replace. |

A version written outside Terraform is reported with a warning and never
overwritten unasked; one written between a saved plan and its apply stops
the apply (`stale`). `terraform import coffre_secret.x infra/prod/KEY`
adopts an existing key.

## Using a local build

Until the provider is published, point Terraform at a build:

```sh
cd terraform-provider && go build -o "$HOME/.terraform.d/coffre-dev/terraform-provider-coffre" .
```

```hcl
# ~/.terraformrc, or a file TF_CLI_CONFIG_FILE names
provider_installation {
  dev_overrides { "erwinkn/coffre" = "/home/you/.terraform.d/coffre-dev" }
  direct {}
}
```

## Tests

`pnpm test:terraform` from the repository's root, after `pnpm build`
(`scripts/terraform-provider.sh`): gofmt, `go vet`, the unit tests, then the
acceptance tests, on Terraform 1.11 and OpenTofu 1.11, against a local
coffre that `packages/conformance/scripts/terraform-fixture.ts` boots (the
Node example on SQLite, ports 3482 and 3483) and seeds. Go and both CLIs are
pinned by version and SHA-256 and downloaded once. `--unit` runs the first
three alone, with no coffre and no Terraform.

The acceptance tests also check, for every write, that the value is in
neither the state nor any record of a saved plan (`tfplan`, `tfstate`,
`tfstate-prev`), with private data decoded layer by layer, and first that
this check catches `internal/acceptance/leaky`, a test provider that hides a
value in its private data.
