# Security model and release gates

This release is not independently audited. Passing tests is not production approval.
Report vulnerabilities privately to the repository owner, not with real credentials
in a public issue. Do not paste API keys into chat, issue comments, or CI logs.

## Implemented controls

- RS256 Access JWT verification (issuer, audience, expiry, signature), explicit
  enrollment and bootstrap subject; separate service common_name handling.
- Native machine tokens are random, expiring, scoped, stored only as digests.
  Suspension and grant expiry are checked from the primary database per operation.
- Explicit permission catalogue and scope inheritance. Auditors need not read values.
  Grant writers cannot self-grant or delegate permissions they do not hold.
- Two independent AAD layers, random per-version data keys/nonces, explicit key ring.
- Optimistic concurrency, transactional audit/outbox writes and idempotency receipts.
- Metadata-only listings. Values remain in transient component state, mask after
  inactivity and are discarded when the tab becomes hidden. No persistent UI cache.
- POST/custom-header/origin checks, bounded parsing, non-cacheable responses,
  production nonce-based script CSP, generic error responses, no value logging.
- Private vault fetch endpoint always returns 404. Public KMS HTTP is off by default.

## Threats not solved by this design

- A Cloudflare administrator or someone able to deploy vault code can obtain values
  with the vault's authority. Separate KMS administration improves detection/custody,
  not zero-knowledge storage. A trusted client can retain any value it receives.
- JavaScript garbage collection prevents reliable erasure of all plaintext copies.
  Clearing UI state is not forensic memory erasure or clipboard revocation.
- R2 retention rules are administrable. Audit chains need independently trusted heads.
- Application code does not enforce provider IAM, firewalling, database CA settings,
  object retention, company MFA policies, EU-only runtime/key residency or compliant
  operations. Operators must configure and verify these separately.

## Must complete before important company credentials

1. Independent security review of auth, crypto usage, concurrency, import/export,
   deployment and the optional KMS protocol.
2. Live Access policy coverage for every hostname/path. Disable workers.dev and
   preview routes. A dedicated native-token API hostname needs its own documented
   network/authentication policy, not a broad accidental Access bypass.
3. Real Hyperdrive verified TLS and disabled cache; restricted PostgreSQL role tests.
4. Real Scaleway KMS / remote KMS integration tests and key retirement/rewrap drills.
5. Backup/restore drill preserving instance UUID and historical root key material;
   after restoring, reconcile grants, revoke old sessions and review machine tokens.
6. Independent archive custody/checkpoints, retention and archive-lag/failure alerts.
7. Edge rate limits, request volume budgets, abuse monitoring and load testing of
   the globally serialized audit head. No exact distributed rate limiter is claimed.
8. Supply-chain review, pinned lockfile, reviewed releases and least-privilege CI.

Do not store the only Cloudflare recovery credential inside this vault. Root recovery
material must be stored separately; loss makes encrypted backups unrecoverable.
