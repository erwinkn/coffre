# Coffre

Single-company secrets manager; no SaaS tenancy, no commercial edition switch.

## Invariants
- `main` is not the implementation scratch branch. Use a feature branch and PR.
- Web routes/server functions have no database or root-key binding. Forward original credentials to the private vault.
- Metadata lists contain neither plaintext values nor encrypted envelopes.
- A value may leave the vault only after its audit event commits. Audit failure is not a warning; it aborts the operation.
- Version/current-pointer/audit/outbox/receipt commit together. Recheck permissions on each optimistic retry.
- AAD uses immutable IDs and version, never names. Payload and key wrapping each bind context independently.
- No automatic KMS/database downgrade. No dev identity in deployed stages. No secrets in logs or exceptions.
- Optional KMS service writes its own journal before releasing key material. It does not pretend a key unwrap equals a human read.
- UI: click value to edit, no pencil, no row expansion. In edit mode show only accept/cancel. Metadata stays in the drawer.
- Never put values or identity credentials in localStorage, persistent browser caches, analytics, or SSR loaders.
- Use synthetic data in tests. Never commit `.local/`, `.dev.vars`, keys, or deployment credentials.

## Checks
`npm run build && npm run typecheck && npm test && npm run test:browser`
The PostgreSQL/MySQL contract tests require the TEST_*_URL variables. A skipped adapter is not certified.
Read `docs/STATUS.md` before representing deployment support or production readiness.
