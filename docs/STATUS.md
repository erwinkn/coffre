# Implementation status

The source in this branch replaces the prior Fastify/PostgreSQL-only prototype.
`main` is not changed. It is a development release, not a finished production service.

## Implemented

- TanStack Start web UI and HTTP API; private Vault Worker RPC.
- Approved Studio cell interaction and metadata/history drawer.
- Project/environment creation and protection, encrypted secret creation/read/write,
  metadata edits, version restore, archive semantics, JSON export.
- Explicit principal enrollment, scoped/expiring grants, machine issuance/revocation.
- PostgreSQL, D1 and MySQL transaction adapters; shared behavioral contract tests.
- Integrated root key ring, Scaleway REST provider, optional KMS Worker/private RPC,
  remote HTTPS KMS adapter; independent fail-closed KMS journal.
- Operational audit chain, transactional outbox, R2/S3 archive implementations, CLI.
- Local signed identity setup, persistent local D1, synthetic seeds, deployment
  templates/configuration checks, unit/integration/browser test harnesses.

## Not yet delivered as production-validated features

- No live Cloudflare, Hyperdrive, Access organization or Scaleway deployment has
  been validated. A build is not a deployment.
- Scaleway KMS and S3 adapters have not been tested against those live services.
- Complete .env/JSON import UI, environment comparison, provider sync integrations,
  self-service human CLI login, direct OIDC fallback and approval workflows.
- Automated cross-engine data migration, root-key rewrap administration, comprehensive
  backup/restore automation, archive-lag alert routing and performance certification.
- MySQL database-enforced append-only capability certification.
- Browser navigation guard covers in-app navigation and reload; browser history
  navigation requires additional router-level blocking before production.

See CI for the actual tested revision and adapter results. Tests without configured
SQL databases skip those adapters explicitly; skipped is not passed. Browser
screenshots/traces contain only synthetic fixtures.
