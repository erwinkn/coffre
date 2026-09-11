# Coffre

Company-owned secrets. A single-organization, open-source secrets manager for
Cloudflare Workers, with interchangeable PostgreSQL, D1 and MySQL storage.
No hosted control plane, licensing checks, or commercial audit-log edition.

**Development release, not production-certified.** Read [status](docs/STATUS.md)
and [security](docs/SECURITY.md) before storing important credentials. No cloud
resources are created by installing, building, or running tests.

## Run locally

Node 22.16+ and npm are required.

```sh
npm ci --ignore-scripts
npm run dev
```

Open http://127.0.0.1:5173. The setup script generates a local signing identity
and encryption keys, creates persistent local D1, and seeds only synthetic
sample credentials. It reuses those keys on subsequent runs. `.local/` and
`.wrangler/` are gitignored. Do not delete the local key file without also
intentionally resetting the corresponding local database.

The local signed identity is accepted only in the explicit local runtime.
Production uses Cloudflare Access JWT verification and explicit enrollment.

## Interaction

Click a secret's value to enter edit mode in the existing table cell. There is
no edit icon or expanded row. Accept/cancel replace reveal/copy while editing.
Enter saves; Escape discards; Shift+Enter inserts a newline. Key, description,
category and tag are edited in the details drawer. Values are never loaded by
metadata listings or stored in persistent browser storage.

## Architecture

- **Web Worker:** React, TanStack Start server functions and HTTP routes,
  shadcn-style Base UI components. No database or root-key binding.
- **Private Vault Worker:** independent identity verification, authorization,
  envelope encryption, versioning, atomic audit/outbox persistence.
- **Optional KMS Worker:** a private service binding or an Access-protected
  HTTPS key service, with a separate fail-closed key-operation journal.
- **Storage adapters:** PostgreSQL/direct or Hyperdrive; D1 binding; MySQL/direct
  or Hyperdrive. Drizzle is inside the SQL adapter, not the application API.
- **Keys:** integrated local root-key ring, Scaleway Key Manager, private Worker
  binding, or remote key-service protocol. There is no automatic fallback.
- **Archive:** R2 or S3-compatible conditional writes, downstream of the committed
  operational audit journal. Retention/independent custody are operator controls.

The vault uses a globally versioned transaction head for the initial internal-team
profile. It is deliberately simple, consistent, and auditable; it is not a claim
of unbounded write throughput. See [architecture](docs/ARCHITECTURE.md).

## Checks

```sh
npm run build                  # generates route types and all three Worker builds
npm run typecheck
npm test                       # real local D1; SQL adapters need URLs below
npm run test:browser            # Playwright; npm exec playwright install chromium
npm run cli:build
node dist/coffre.mjs help
```

Set `TEST_POSTGRES_URL` and `TEST_MYSQL_URL` to disposable loopback databases to
run their contract suites. **The suite creates a schema; never use a production
database.** GitHub Actions provides disposable PostgreSQL/MySQL service containers.
A skipped database test is not a passing database certification.

The HTTP API is `POST /api/v1/operations`. The request is `{requestId, command}`;
see `packages/contracts`. Machine callers use `Authorization: Bearer ...` and
`X-Coffre-Request: 1`. Use the same requestId to retry an ambiguous mutation.
Token issuance is one-time; failed delivery requires revoking and replacing it.

## Deploy

See [deployment](docs/DEPLOYMENT.md). Configurations under `deploy/` intentionally
contain nonfunctional placeholders. No secret credentials belong in them.
`npm run deploy:check` refuses unresolved placeholders and obvious unsafe settings.

## License

MIT. Base UI/shadcn component attribution is in [third-party notices](docs/THIRD_PARTY.md).
