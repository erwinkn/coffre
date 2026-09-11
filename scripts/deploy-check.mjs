import { readFile } from 'node:fs/promises';
const web = JSON.parse(await readFile('deploy/web.jsonc', 'utf8')), vault = JSON.parse(await readFile('deploy/vault.jsonc', 'utf8'));
const errors = [];
for (const [name, config] of [['web', web], ['vault', vault]]) {
  if (config.workers_dev !== false || config.preview_urls !== false) errors.push(`${name}: alternate public entrypoints must be disabled`);
  if (config.vars?.STAGE !== 'production') errors.push(`${name}: only production configuration may be deployed`);
  if (!config.account_id || !/^[a-f0-9]{32}$/.test(config.account_id)) errors.push(`${name}: set the Cloudflare account ID`);
  if (/REPLACE_ME|example\.invalid|replace-me|00000000-0000-4000-8000-000000000000/.test(JSON.stringify(config))) errors.push(`${name}: unresolved installation placeholders`);
  if (/LOCAL_JWKS|LOCAL_ACCESS_TOKEN|ROOT_KEYS|REQUEST_INTEGRITY_KEY|DATABASE_URL|SCW_SECRET_KEY/.test(JSON.stringify(config.vars ?? {}))) errors.push(`${name}: credentials must be secret bindings, not vars`);
}
if (vault.vars.STORAGE === 'd1' && vault.vars.REQUIRE_APPEND_ONLY === 'true') errors.push('D1 cannot enforce PostgreSQL audit-role privileges');
if (vault.vars.KEY_PROVIDER === 'service' && !vault.services?.some(x => x.binding === 'KMS')) errors.push('The separate KMS binding is missing');
if (errors.length) { for (const error of errors) console.error(error); process.exitCode = 1; }
else console.log('Static deployment checks passed. This does NOT verify Access policy coverage, Hyperdrive caching/TLS, database privileges, remote KMS, or archive retention. Complete the live checklist.');
