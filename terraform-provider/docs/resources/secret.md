---
page_title: "coffre_secret Resource - coffre"
description: |-
  One key of a coffre environment, and its value, which Terraform sends and keeps nowhere.
---

# coffre_secret (Resource)

One key of a coffre environment, and its value. The value is write-only:
Terraform sends it, and keeps it in neither state nor plan. So Terraform cannot
tell when it changes: `value_wo_version` says it did.

```terraform
resource "coffre_secret" "stripe" {
  project          = "billing"
  environment      = "prod"
  key              = "STRIPE_KEY"
  value_wo         = var.stripe_key   # an ephemeral variable
  value_wo_version = 3                # bump it to write the value again
  sensitivity      = "sensitive"
}
```

- **Create** writes the key only while it holds nothing: one in coffre already
  is imported, never overwritten. In a fork, a value a parent passes down is
  overridden with this environment's own.
- **Update** (a new `value_wo_version` or `sensitivity`) writes the value again,
  as the key's next version, and only over the version the plan saw: if anyone
  wrote the key after the plan, the apply is refused and writes nothing.
- **Drift:** a key written outside Terraform is planned to be written back, with
  a warning naming who wrote it.
- **Destroy** archives the key: coffre keeps its history, and it can be brought
  back there. A key that is archived is not made again from Terraform: bring it
  back in coffre and import it.

## Schema

### Required

- `project` (String) The project's slug. A change replaces the resource.
- `environment` (String) The environment's slug. A change replaces the resource.
- `key` (String) The key's name, such as `STRIPE_KEY`. A change replaces the resource: the old key is archived.
- `value_wo` (String, Sensitive, [Write-only](https://developer.hashicorp.com/terraform/language/resources/ephemeral#write-only-arguments)) The value: at most 64 KiB of text, with no NUL.
- `value_wo_version` (Number) Change it to write `value_wo` again. A number you choose, never one made from the value: a hash would carry it.

### Optional

- `sensitivity` (String) Who sees the value: `plain`, whoever lists the environment; `secret`, whoever reads it (the default); `sensitive`, nobody, as it is only used. A change writes the value again.

### Read-Only

- `id` (String) `project/environment/key`.
- `version` (Number) The version the key reads now, as the last refresh or write saw it.
- `version_id` (String) That version's id: what the next write says it replaces.
- `updated_by` (String) Who wrote that version.

## Import

```shell
terraform import coffre_secret.stripe billing/prod/STRIPE_KEY
```

Terraform has never written an imported key, so the first apply after the
import writes the configured value, once.
