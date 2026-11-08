# terraform-provider-coffre

A Terraform and OpenTofu provider that writes secrets into coffre and never
reads one back: one resource, `coffre_secret`, whose value is a write-only
argument, absent from state and plans. The design, its rules and why:
[docs/design/terraform-provider.md](https://github.com/erwinkn/coffre/blob/main/docs/design/terraform-provider.md).

It lives in [erwinkn/coffre](https://github.com/erwinkn/coffre)'s
`terraform-provider/`, beside the server it calls, and is mirrored to
[erwinkn/terraform-provider-coffre](https://github.com/erwinkn/terraform-provider-coffre)
for the registries: send changes to coffre.

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
| `on_destroy` | `keep` (default): destroy stops managing the key, which stays. `archive`: destroy archives it, with a credential holding `secret.archive`; in a fork, archiving an override returns the key to the parent's value. |
| `version`, `version_id` | Computed: coffre's current version, which the next write must replace. |

A version written outside Terraform is reported with a warning and never
overwritten unasked; one written between a saved plan and its apply stops
the apply (`stale`). `terraform import coffre_secret.x infra/prod/KEY`
adopts an existing key. `terraform apply -replace` and `taint` stop at the
plan, since the key exists: a new value is a new `value_wo_version`.

## Using a local build

To try a change, or before a release, point Terraform at a build:

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
(`scripts/terraform-provider.sh`): gofmt, `go vet` and the unit tests; then
the release, built as GoReleaser's unsigned snapshot, which Terraform and
OpenTofu each install from a filesystem mirror holding this platform's zip
(`init`) and run (a plan and the provider's schema); then the acceptance
tests, on Terraform 1.11 and OpenTofu 1.11, against a local coffre that
`packages/conformance/scripts/terraform-fixture.ts` boots (the Node example
on SQLite, ports 3482 and 3483) and seeds. Go, GoReleaser and both CLIs are
pinned by version and SHA-256 and downloaded once. `--unit` runs the first
three alone, with no release, no coffre and no Terraform.

The acceptance tests also check, for every write, that the value is in
neither the state nor any record of a saved plan (`tfplan`, `tfstate`,
`tfstate-prev`), with private data decoded layer by layer, and first that
this check catches `internal/acceptance/leaky`, a test provider that hides a
value in its private data.

## Releasing

The provider takes its own versions (`0.1.0` first), apart from coffre's:
`pnpm bump` leaves it alone. A release:

1. A PR in coffre heads `CHANGELOG.md`'s `## Unreleased` here as
   `## 0.1.0 (<date>)`, under a new, empty `## Unreleased`; its notes say
   which coffre release the provider needs. Merged, it is main.
2. `gh workflow run terraform-provider.yml --repo erwinkn/coffre --ref main -f version=0.1.0`.
   Coffre's `Terraform provider` workflow checks the version and its notes
   (`scripts/notes.sh 0.1.0`) and builds the release unsigned, then pushes
   this directory's own history (`git subtree split`, the same commits every
   time) to the mirror's `main`, with the tag `v0.1.0` on it, through a
   deploy key that only that workflow's `terraform-mirror` environment holds.
3. The tag starts the mirror's `Release` workflow
   (`.github/workflows/release.yml`), the one every Registry provider runs:
   one job, in the `release` environment, which only `v*` tags may use. It
   installs the pinned Go and GoReleaser (`scripts/tools.sh`), imports the
   signing key into a GnuPG home of its own, and runs `goreleaser release`
   (`.goreleaser.yml`), which builds the zips, signs their sums and publishes
   the GitHub release with those notes, a prerelease for a version such as
   `0.2.0-rc.1`. The Terraform Registry takes it from there; OpenTofu's too,
   once the provider and its key are submitted to it
   (github.com/opentofu/registry), a step not yet taken.

The build is reproducible: the same commit gives the same zips, byte for
byte. Rulesets on the mirror keep its `main` moving forward only and its
`v*` tags fixed, so a version is released once.

The signing key and the job's token, which may write the mirror's releases,
share that one job. Code that runs in it could take the key, which is worth
more than the token, so splitting them into two jobs would protect little.

The signing key is RSA 4096, signing only (the Registry takes no ECC key),
its private half and passphrase in the mirror's `release` environment
(`GPG_PRIVATE_KEY`, `PASSPHRASE`) and in Erwin's 1Password, its public half
on registry.terraform.io under the `erwinkn` namespace's signing keys. It
does not exist yet: the first release waits for it.
