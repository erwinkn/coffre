import { readFile, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
const path = process.argv[2];
if (!path) throw new Error('Usage: node scripts/configure.mjs <installation.json>. No credentials belong in that file. See docs/DEPLOYMENT.md.');
const input = JSON.parse(await readFile(path, 'utf8'));
for (const field of ['accountId', 'origin', 'accessIssuer', 'accessAudience', 'bootstrapSubject']) if (!input[field] || typeof input[field] !== 'string') throw new Error(`Missing ${field}`);
if (!/^https:\/\/[a-z0-9.-]+$/.test(input.origin) || !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(input.accessIssuer)) throw new Error('Use HTTPS origins without paths');
if (!['d1', 'postgres', 'mysql'].includes(input.storage)) throw new Error('Unknown database adapter');
if (!['local', 'scaleway', 'service', 'remote'].includes(input.keyProvider)) throw new Error('Unknown key provider');
const instanceId = input.instanceId ?? randomUUID();
const web = JSON.parse(await readFile('deploy/web.jsonc', 'utf8')), vault = JSON.parse(await readFile('deploy/vault.jsonc', 'utf8')), kms = JSON.parse(await readFile('deploy/kms.jsonc', 'utf8'));
for (const config of [web, vault, kms]) { config.account_id = input.accountId; config.workers_dev = false; config.preview_urls = false; }
web.vars = { STAGE: 'production', PUBLIC_ORIGIN: input.origin };
web.routes = [{ pattern: new URL(input.origin).hostname, custom_domain: true }];
vault.vars = { STAGE: 'production', INSTANCE_ID: instanceId, STORAGE: input.storage, KEY_PROVIDER: input.keyProvider, ACCESS_ISSUER: input.accessIssuer, ACCESS_AUDIENCE: input.accessAudience, BOOTSTRAP_SUBJECT: input.bootstrapSubject, REQUIRE_APPEND_ONLY: input.requireAppendOnly ? 'true' : 'false', ARCHIVE_PROVIDER: 'r2' };
if (input.storage === 'd1') { if (!input.d1Id) throw new Error('Supply an existing D1 database UUID'); vault.d1_databases = [{ binding: 'DB', database_name: 'coffre', database_id: input.d1Id }]; delete vault.hyperdrive; }
else { delete vault.d1_databases; if (input.hyperdriveId) vault.hyperdrive = [{ binding: 'HYPERDRIVE', id: input.hyperdriveId }]; else delete vault.hyperdrive; }
if (!input.auditBucket) throw new Error('Supply a private audit R2 bucket name');
vault.r2_buckets = [{ binding: 'AUDIT_ARCHIVE', bucket_name: input.auditBucket }];
if (input.keyProvider !== 'service') delete vault.services;
else vault.services = [{ binding: 'KMS', service: kms.name, entrypoint: 'KmsWorker' }];
if (input.keyProvider === 'scaleway') { if (!input.scalewayCurrentKey) throw new Error('Supply the Scaleway wrapping-key reference'); vault.vars.SCW_CURRENT_KEY = input.scalewayCurrentKey; vault.vars.SCW_ALLOWED_KEYS = JSON.stringify(input.scalewayAllowedKeys ?? [input.scalewayCurrentKey]); }
if (input.keyProvider === 'remote') { if (!input.kmsOrigin) throw new Error('Supply the remote key-service HTTPS origin'); vault.vars.KMS_URL = input.kmsOrigin; }
kms.vars = { INSTANCE_ID: instanceId, KEY_PROVIDER: input.kmsProvider ?? 'local', HTTP_ENABLED: 'false' };
if (input.keyProvider === 'service') { if (!input.keyAuditBucket) throw new Error('Use a separate key-service audit bucket'); kms.r2_buckets = [{ binding: 'KEY_AUDIT', bucket_name: input.keyAuditBucket }]; if (input.kmsProvider === 'scaleway') { kms.vars.SCW_CURRENT_KEY = input.scalewayCurrentKey; kms.vars.SCW_ALLOWED_KEYS = JSON.stringify(input.scalewayAllowedKeys ?? [input.scalewayCurrentKey]); } }
for (const [name, config] of [['web', web], ['vault', vault], ['kms', kms]]) await writeFile(`deploy/${name}.jsonc`, JSON.stringify(config, null, 2) + '\n');
console.log(`Configured installation ${instanceId}. No credentials were generated or transmitted. Review the configuration, provision secret bindings, then build.`);
