# Release notes

The provider's own versions, apart from coffre's. A release heads the
Unreleased section with its version, merged before the release workflow runs
(docs/design/terraform-provider.md, section 8): its notes are that section.

## Unreleased

- **`coffre_secret`, the first release.** One resource that writes a value
  into coffre and never reads one back: `value_wo`, a write-only argument,
  absent from state and plans, written again when `value_wo_version`
  changes. It signs in by GitHub Actions' OIDC, another issuer's ID token,
  or a bearer token. Needs Terraform 1.11 or OpenTofu 1.11, and coffre 0.16
  or later.
