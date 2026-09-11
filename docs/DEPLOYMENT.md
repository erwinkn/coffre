# Deployment runbook

No infrastructure is provisioned implicitly. Begin with an isolated staging account
or project and synthetic data. The checked-in placeholders are intentionally unusable.

## 1. Prepare resources and public configuration

Create your Cloudflare account resources: web hostname under Access, a private audit
R2 bucket, and either D1 or a reachable PostgreSQL/MySQL database. For Hyperdrive,
configure verified upstream TLS and **disable query caching**. Do not use a database
migration/admin credential as the vault runtime credential.

A non-secret installation JSON example:

```json
{
  "accountId": "YOUR_32_CHARACTER_ACCOUNT_ID",
  "origin": "https://coffre.company.example",
  "accessIssuer": "https://YOUR_TEAM.cloudflareaccess.com",
  "accessAudience": "YOUR_ACCESS_APPLICATION_AUDIENCE",
  "bootstrapSubject": "THE_EXACT_ACCESS_SUB_OF_THE_FIRST_ADMIN",
  "instanceId": "YOUR_STABLE_UUID",
  "storage": "postgres",
  "hyperdriveId": "YOUR_HYPERDRIVE_ID",
  "requireAppendOnly": true,
  "auditBucket": "coffre-audit",
  "keyProvider": "scaleway",
  "scalewayCurrentKey": "scaleway:fr-par:YOUR_KEY_UUID"
}
```

For D1, use storage=d1, d1Id=<database UUID>, requireAppendOnly=false. For direct SQL,
omit hyperdriveId and provide DATABASE_URL as a Worker secret. Do not use URL query
options such as sslmode; TLS verification is explicit in the driver configuration.
For a private CA, supply DATABASE_CA as a secret binding containing its PEM certificate.

```sh
node scripts/configure.mjs installation.json
npm run deploy:check
```

Keep the instance UUID stable forever. This command does not create IAM policies,
Access applications, buckets, databases, or key material, and does not verify them.

## 2. Initialize storage

PostgreSQL/MySQL: use an administrative/migration connection only for this step.
The script refuses to guess at migrations over an existing schema; use a new database.
Set DATABASE_URL and INSTANCE_ID in your shell's secret environment, not in Git.

```sh
node scripts/init-database.mjs postgres
```

Then create a separate `coffre_runtime` login role out of band and apply
`packages/storage/migrations/postgres-runtime-role.sql`. Configure Hyperdrive/direct
DATABASE_URL with that role, not the migration role. Use PostgreSQL managed backup/PITR.

D1: apply `packages/storage/migrations/d1.sql` using Wrangler and insert one meta row:
`INSERT INTO coffre_meta VALUES (1,'YOUR_STABLE_UUID',0,0,'GENESIS');`.
Use the exact UUID from the vault configuration. Test Time Travel/export recovery
separately; the application does not provision retention policies.

## 3. Provision secrets only on the appropriate Worker

Use `wrangler secret put NAME --config deploy/vault.jsonc` or a narrowly scoped
GitHub environment deployment workflow. Never put these in vars or source control.

- All vault modes: REQUEST_INTEGRITY_KEY, random 32 bytes encoded base64url.
- Direct SQL: DATABASE_URL; private CA deployments: DATABASE_CA.
- Integrated local root mode: ROOT_KEYS JSON:
  `{ "current": "root:v1", "keys": { "root:v1": "<32-random-bytes-base64url>" } }`.
  Keep an encrypted off-platform recovery copy and all historical root keys required
  by retained backups. Worker secret storage is not hardware-enforced nonexportability.
- Scaleway: SCW_SECRET_KEY (narrow key-use IAM). Public current/allowed key references
  are configured in vars. Never retire a root while old backups need it.
- S3 archive mode: S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY; set ARCHIVE_PROVIDER=s3 and
  S3_ENDPOINT/S3_BUCKET/S3_REGION. The provider must support conditional creation;
  do not rely on an unvalidated S3 implementation for production evidence custody.

No production credentials are necessary for unit tests, local D1 or CI service databases.

## 4. Optional dedicated key service

For keyProvider=service, specify keyAuditBucket (distinct private bucket) and kmsProvider
(local or scaleway) in installation JSON. Supply ROOT_KEYS or SCW_SECRET_KEY **only on
coffre-kms**, not coffre-vault. Use a separately administered deployment credential
for meaningful key custody separation. The binding's named entrypoint is KmsWorker.

For an independently hosted HTTPS key service, use keyProvider=remote and kmsOrigin.
Supply KMS_ACCESS_CLIENT_ID/KMS_ACCESS_CLIENT_SECRET on the vault. On the remote service,
enable HTTP_ENABLED, configure its Access issuer/audience and ALLOWED_ACCESS_SERVICES
as an explicit JSON list of allowed service common_name values. Protect its custom
hostname with Access; do not enable workers.dev. The same protocol is documented by
`kmsRequestSchema`, `/v1/wrap`, `/v1/unwrap` and the `KeyBroker` implementation.
There is no automatic fallback from this service to a local root key.

## 5. Build, deploy, verify

```sh
npm ci --ignore-scripts
npm run build
npm run typecheck
npm test
npm run deploy:check
# Only for the private KMS service mode:
npx wrangler deploy --config apps/web/dist/coffre_kms/wrangler.json
npx wrangler deploy --config apps/web/dist/coffre_vault/wrangler.json
npx wrangler deploy --config apps/web/dist/server/wrangler.json
```

Review generated configs before deploying. Provision service dependencies first.
A Cloudflare token used for this operation needs only the target-account Worker,
resource and route permissions appropriate to the chosen deployment. Access setup
and database/IAM provisioning should use separate credentials where practical.

Verify unauthorized requests fail on every public entrypoint; correct Access JWTs
with unenrolled subjects still fail; the configured bootstrap subject alone initializes
the first owner. Remove BOOTSTRAP_SUBJECT after successful initialization if desired.
Test vault fetch 404, valid UI flow, revocation, real archive delivery, database-role
restrictions, KMS failure, and restoration using only synthetic secrets first.

The CI browser test uses a signed local identity in a loopback-only dev server. It
does not validate your company's IdP, production cookie settings or Access policies.
