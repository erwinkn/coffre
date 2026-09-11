import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Miniflare } from 'miniflare';
import { generateKeyPair, exportJWK, importJWK, SignJWT, createLocalJWKSet } from 'jose';
import { b64, random, unb64, LocalKeyProvider } from '../packages/crypto/src/index';
import { AccessAuthenticator } from '../packages/core/src/auth';
import { Vault } from '../packages/core/src/vault';
import { d1Storage } from '../packages/storage/src/index';
import type { Command, Project, Environment } from '../packages/contracts/src/index';

const path = '.local/identity.json';
let identity: { instanceId: string; rootKey: string; requestKey: string; privateKey: JsonWebKey; publicKey: JsonWebKey };
if (existsSync(path)) identity = JSON.parse(await readFile(path, 'utf8'));
else {
  const pair = await generateKeyPair('RS256', { extractable: true });
  identity = { instanceId: crypto.randomUUID(), rootKey: b64(random(32)), requestKey: b64(random(32)), privateKey: await exportJWK(pair.privateKey), publicKey: await exportJWK(pair.publicKey) };
  await writeFile(path, JSON.stringify(identity), { mode: 0o600 });
}
const issuer = 'http://127.0.0.1:8789', audience = 'coffre-local', subject = 'local-owner';
const privateKey = await importJWK(identity.privateKey as never, 'RS256');
const jwt = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'local' }).setSubject(subject).setIssuer(issuer).setAudience(audience).setIssuedAt().setExpirationTime('8h').sign(privateKey);
const jwks = { keys: [{ ...identity.publicKey, kid: 'local', alg: 'RS256' }] };
const common = { STAGE: 'local', INSTANCE_ID: identity.instanceId, KEY_PROVIDER: 'local', ROOT_KEYS: JSON.stringify({ current: 'local:v1', keys: { 'local:v1': identity.rootKey } }) };
await writeFile('.local/config.json', JSON.stringify({ web: { STAGE: 'local', PUBLIC_ORIGIN: 'http://127.0.0.1:5173', LOCAL_ACCESS_TOKEN: jwt }, vault: { ...common, STORAGE: 'd1', ACCESS_ISSUER: issuer, ACCESS_AUDIENCE: audience, LOCAL_JWKS: JSON.stringify(jwks), BOOTSTRAP_SUBJECT: subject, REQUEST_INTEGRITY_KEY: identity.requestKey, REQUIRE_APPEND_ONLY: 'false' }, kms: { ...common, HTTP_ENABLED: 'false' } }), { mode: 0o600 });
const mf = new Miniflare({ cf: false, modules: true, script: 'export default {fetch(){return new Response("local setup")}}', compatibilityDate: '2026-07-01', d1Databases: { DB: '00000000-0000-4000-8000-000000000000' }, d1Persist: resolve('.wrangler/state/v3/d1') });
try {
  const db = await mf.getD1Database('DB');
  const exists = await db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='coffre_meta'").first();
  if (!exists) {
    for (const statement of (await readFile('packages/storage/migrations/d1.sql', 'utf8')).replace(/^--.*$/gm, '').split(';').map(s => s.trim()).filter(Boolean)) await db.prepare(statement).run();
    await db.prepare('INSERT INTO coffre_meta(singleton,instance_id,revision,audit_seq,audit_hash) VALUES(1,?,0,0,?)').bind(identity.instanceId, 'GENESIS').run();
  }
  const vault = new Vault({ storage: d1Storage(db as unknown as D1Database), auth: new AccessAuthenticator(issuer, audience, createLocalJWKSet(jwks as never), true), instanceId: identity.instanceId, keys: new LocalKeyProvider(new Map([['local:v1', unb64(identity.rootKey)]]), 'local:v1'), requestKey: unb64(identity.requestKey), bootstrapSubject: subject });
  const run = async <T>(command: Command) => await vault.execute({ accessJwt: jwt }, { requestId: crypto.randomUUID(), command }) as T;
  const workspace = await run<{ projects: Project[] }>({ type: 'workspace.get' });
  if (!workspace.projects.length) {
    const project = await run<Project>({ type: 'project.create', name: 'Core API', description: 'Configuration and credentials for the core application.' });
    const sample = [
      ['DATABASE_URL', 'postgresql://demo:synthetic@localhost:5432/core', 'Primary application database', 'Database', 'Credential'],
      ['REDIS_URL', 'redis://localhost:6379/0', 'Cache and session storage', 'Database', 'Credential'],
      ['STRIPE_SECRET_KEY', 'sk_test_SYNTHETIC_NOT_VALID', 'Payment processing · test account', 'Payments', 'Credential'],
      ['JWT_SECRET', 'synthetic-jwt-secret-not-for-production', 'Application session signing', 'Auth', 'Credential'],
      ['S3_BUCKET', 'coffre-demo-uploads', 'User upload storage', 'Storage', 'Config'],
      ['APP_URL', 'https://app.example.invalid', 'Canonical application URL', 'Application', 'Config'],
      ['SMTP_PASSWORD', 'synthetic-mail-credential', 'Transactional email provider', 'Messaging', 'Credential'],
      ['LOG_LEVEL', 'info', 'Application logging verbosity', 'Application', 'Config'],
      ['WEBHOOK_SECRET', 'synthetic-webhook-secret', 'Incoming webhook verification', 'Auth', 'Credential'],
    ];
    for (const name of ['Development', 'Staging', 'Production']) {
      const env = await run<Environment>({ type: 'environment.create', projectId: project.id, name, protected: name === 'Production' });
      for (const row of sample) await run({ type: 'secret.create', envId: env.id, key: row[0]!, value: row[1]!, note: row[2]!, tag: row[3]!, category: row[4] as 'Credential' | 'Config', confirmed: true });
    }
  }
  console.log('Local D1 initialized. Synthetic sample data only. Keys and signed local identity are in ignored .local/ files.');
} finally { await mf.dispose(); }
