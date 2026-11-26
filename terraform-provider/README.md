# terraform-provider-coffre

The coffre provider for Terraform and OpenTofu: it writes coffre secrets, and
keeps no value anywhere, not in state, a plan, a log or an error. Its design,
and why each choice, is
[docs/design/terraform-provider.md](../docs/design/terraform-provider.md);
what a user reads is [docs/](docs/index.md), as the registries show it.

```hcl
provider "coffre" {
  url  = "https://secrets.acme.example"
  oidc = { service = "terraform" }
}

resource "coffre_secret" "stripe" {
  project          = "billing"
  environment      = "prod"
  key              = "STRIPE_KEY"
  value_wo         = var.stripe_key # an ephemeral variable
  value_wo_version = 3
}
```

A Go module of its own, outside pnpm's workspace:

```
main.go                       the plugin's entry
internal/coffre/              the API client: sign-in, calls, refusals
internal/provider/            the provider, and one file per resource
acceptance/                   the acceptance tests, against a real deployment
docs/, examples/              what the registries show
scripts/binaries.sh           the Terraform and OpenTofu binaries the tests run, pinned
.goreleaser.yml               the release, as the registries read one
```

## Checks

Go 1.27, from this folder:

```sh
gofmt -l . && go vet ./... && go test -race ./internal/...
```

The acceptance tests build the provider, boot the Workers example on a
database of their own (`packages/conformance/scripts/terraform-fixture.ts`),
and run every scenario on each binary, Terraform and OpenTofu, at 1.11 and
at their newest pinned release. They need Postgres as `pnpm
conformance:workers` does, and `pnpm build` done, from the repository's root:

```sh
./scripts/ensure-postgres.sh && node --conditions=coffre:source scripts/ensure-database.mjs coffre
pnpm build
cd terraform-provider
COFFRE_ACC_BINARIES="$(scripts/binaries.sh ~/.cache/coffre-terraform)" TF_ACC=1 go test ./acceptance/ -count=1 -v
```

`COFFRE_POSTGRES_PORT` points them at another Postgres, as it does every
script. CI runs both on a change here or to what the provider calls
(`.github/workflows/terraform-provider.yml`).

## Releasing

Not done yet: publishing 0.1.0 is a decision of its own. When it is made:

1. The registries read a provider from a repository named
   `terraform-provider-<name>`, so the release goes to
   `erwinkn/terraform-provider-coffre`, a mirror of this folder. Make it,
   empty, and register it with the Terraform Registry and OpenTofu's.
2. Make a GPG signing key; give its public half to both registries, and its
   private half and passphrase to this repository as
   `TERRAFORM_PROVIDER_GPG_KEY` and `TERRAFORM_PROVIDER_GPG_PASSPHRASE`, with
   `TERRAFORM_PROVIDER_MIRROR_TOKEN`, a token that writes the mirror's
   contents.
3. Run the workflow `Release the Terraform provider`
   (`.github/workflows/terraform-provider-release.yml`) from `main`, with the
   version. It checks the signing key signs, then copies this folder to the
   mirror with its history, tags it `v<version>`, and GoReleaser builds,
   signs and publishes the release there.
