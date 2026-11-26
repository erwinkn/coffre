---
page_title: "coffre provider"
description: |-
  Writes coffre secrets from Terraform and OpenTofu, and keeps no value: not in state, a plan or a log.
---

# coffre provider

Writes [coffre](https://github.com/erwinkn/coffre) secrets. A value goes in a
write-only attribute: Terraform sends it to coffre and keeps it nowhere, not in
state, a plan or a log. It needs Terraform 1.11 or OpenTofu 1.11 at least.

The provider signs in as a service account: by its token, or, in CI, with the
run's ID token, which it trades for a credential of five minutes
(`coffre trust` binds the service account to the workflow). The account needs
`secret.write` to write keys, `secret.archive` to destroy them, and to list the
environment: the built-in `maintainer` role holds all three.

## Example

```terraform
provider "coffre" {
  url  = "https://secrets.acme.example"
  oidc = { service = "terraform" }
}
```

Declare every variable that holds a value or a credential `ephemeral = true`:
a saved plan keeps any other variable's value, sensitive or not.

## Schema

### Required

- `url` (String) The instance's URL, such as `https://secrets.acme.example`: https, or http on loopback.

### Optional

- `token` (String, Sensitive) A service account's token (`coffre_svc_…`). Give this or `oidc`.
- `oidc` (Attributes) Sign in with the CI run's ID token. Give this or `token`.
  - `service` (String, Required) The service account, `terraform` or `token:terraform`, whose trust binding takes this run.
  - `id_token` (String, Sensitive) The run's ID token, for the instance's URL as its audience. It serves one exchange, so one command: `terraform plan -out`, or the apply of a saved plan. Left out in GitHub Actions (`permissions: id-token: write`), the provider asks the runner for a fresh one each time it needs one.

The provider reads no environment variable of its own. In GitHub Actions it
reads the runner's `ACTIONS_ID_TOKEN_REQUEST_URL` and
`ACTIONS_ID_TOKEN_REQUEST_TOKEN`, as coffre's CLI does.
