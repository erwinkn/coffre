import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrate } from 'drizzle-orm/postgres-js/migrator';

import { createDatabase } from '../../src/database.ts';
import { canonicalTimestamp } from '../../src/dialect.ts';
import { migrateDatabase, migrationsFolder } from '../../src/migrate.ts';
import { postgresClient } from '../../src/postgres.ts';

/**
 * One session, opened at once, whose `query` runs text as written, several
 * statements too, and answers the last one's rows.
 */
async function session(url: string) {
  const client = postgresClient(url, { max: 1 });
  const query = async (text: string) => ({ rows: [...(await client.unsafe(text))] as Record<string, any>[] });
  await query('SELECT 1');
  return { query, client, end: () => client.end() };
}

/**
 * The upgrade from 0.14 (docs/design/0.16.md, "Upgrade from 0.14"): a 0.14
 * database with a row of every kind converts in place, only with coffre
 * offline, and each row becomes what the design's table says. Run by
 * scripts/test-upgrade.sh on a cluster of its own, since it sets the runtime
 * logins NOLOGIN, which are the cluster's: `DATABASE_URL` is its owner's, on
 * the database this makes and leaves, `coffre_upgraded`.
 */

const TAG = '0022_smaller_vault';
const owner = new URL(process.env.DATABASE_URL ?? '');
const urlOf = (database: string, user?: { name: string; password: string }) => {
  const url = new URL(owner);
  url.pathname = `/${database}`;
  if (user !== undefined) [url.username, url.password] = [user.name, user.password];
  return url.toString();
};
const UPGRADED = 'coffre_upgraded';

const h = (byte: number) => `'\\x${Buffer.alloc(32, byte).toString('hex')}'`;
const u = (n: number) => `'00000000-0000-4000-8000-${String(n).padStart(12, '0')}'`;
const id = (n: number) => u(n).slice(1, -1);
const T0 = Date.UTC(2026, 9, 1);
const day = 86_400_000;

/** A copy of the migrations up to the one before 0.16's: what 0.14.7 ships. */
function before(dir: string): string {
  const from = migrationsFolder('postgres');
  const folder = join(dir, 'migrations');
  cpSync(from, folder, { recursive: true, filter: (path) => !path.includes('_snapshot.json') });
  const journal = JSON.parse(readFileSync(join(folder, 'meta/_journal.json'), 'utf8')) as { entries: { tag: string }[] };
  const at = journal.entries.findIndex((entry) => entry.tag === TAG);
  assert.equal(at, journal.entries.length - 1, `${TAG} is the newest migration: a later one belongs to a later release's test`);
  writeFileSync(join(folder, 'meta/_journal.json'), JSON.stringify({ ...journal, entries: journal.entries.slice(0, at) }));
  rmSync(join(folder, `${TAG}.sql`));
  assert.ok(readdirSync(folder).length > 20);
  return folder;
}

/** An entry of 0.14's log: only what the upgrade reads is true to life. */
type More = { decision?: string; code?: string; subject?: string; place?: [project: number, environment: number]; secret?: number; related?: number; metadata?: object; at?: number };
const ENTRY_COLUMNS = 'seq, author, key_id, occurred_at, actor, action, decision, code, subject_principal, project_id, environment_id, secret_id, related_seq, metadata, prev_hash, mac, hash';
const text = (value: string | undefined) => (value === undefined ? 'NULL' : `'${value}'`);
const entry = (seq: number, author: 'app' | 'vault', actor: string, action: string, more: More = {}) =>
  `(${seq}, '${author}', 'k1', ${more.at ?? T0 + seq * 1000}, '${actor}', '${action}', '${more.decision ?? 'allow'}', ${text(more.code)}, ${text(more.subject)}, ` +
  `${more.place === undefined ? 'NULL, NULL' : `${u(more.place[0])}, ${u(more.place[1])}`}, ${more.secret === undefined ? 'NULL' : u(more.secret)}, ${more.related ?? 'NULL'}, '${JSON.stringify(more.metadata ?? {})}', ${h(1)}, ${h(2)}, ${h(3)})`;
/** The vault's seal of a reference: `holder` in billing/prod reads market/prod's `source`. */
const seal = (seq: number, reference: number, holder: number, source: number) =>
  entry(seq, 'vault', ADA, 'reference.create', { place: [2, 21], metadata: { reference: id(reference), secretId: id(holder), also: { projectId: id(1), environmentId: id(11), secretId: id(source) } } });
const version = (n: number, secret: number, number: number, more: { erased?: boolean; plaintext?: string; sensitive?: boolean } = {}) =>
  `(${u(n)}, ${u(secret)}, ${number}, 1, '\\x${more.erased ? '' : '01'}', '\\x${'00'.repeat(12)}', '\\x${'00'.repeat(16)}', '\\x${more.erased ? '' : '02'}', 'local', 'k', '1', '${ADA}', ${text(more.plaintext)}, ${more.sensitive ?? false})`;

const ADA = 'user:ada@acme.example';
const BO = 'user:bo@acme.example';
const API = 'token:api';
const CI = 'token:ci';
// Projects 1 and 2; environments 11 (market/prod), 12 (market/dev), 21 (billing/prod); secrets 101 and 102 in market/prod, 103 to 109 in billing/prod.
const SEED = `
  INSERT INTO vault_members (principal, status, owner, role, scope, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac) VALUES
    ('${ADA}', 'active', true, NULL, NULL, 0, ${T0}, 'system:setup', ${T0}, 'system:setup', 1, ${h(9)}),
    ('${BO}', 'removed', false, 'member', NULL, 1, ${T0 + 1}, '${ADA}', ${T0 + 5 * day + 123}, '${ADA}', 2, ${h(9)}),
    ('${API}', 'active', false, 'member', NULL, 0, ${T0}, '${ADA}', ${T0}, '${ADA}', 3, ${h(9)}),
    ('${CI}', 'active', false, 'member', NULL, 0, ${T0}, '${ADA}', ${T0}, '${ADA}', 4, ${h(9)});
  INSERT INTO projects (id, slug, name) VALUES (${u(1)}, 'market', 'Market'), (${u(2)}, 'billing', 'Billing');
  INSERT INTO environments (id, project_id, slug, name) VALUES (${u(11)}, ${u(1)}, 'prod', 'Production'), (${u(12)}, ${u(1)}, 'dev', 'Development'), (${u(21)}, ${u(2)}, 'prod', 'Production');
  INSERT INTO secrets (id, project_id, environment_id, key, current_version) VALUES
    (${u(101)}, ${u(1)}, ${u(11)}, 'DATABASE_URL', 1), (${u(102)}, ${u(1)}, ${u(11)}, 'STRIPE_KEY', 2),
    (${u(103)}, ${u(2)}, ${u(21)}, 'DATABASE_URL', 0), (${u(104)}, ${u(2)}, ${u(21)}, 'OLD_REFERENCE', 0), (${u(105)}, ${u(2)}, ${u(21)}, 'FORGED_REFERENCE', 0),
    (${u(106)}, ${u(2)}, ${u(21)}, 'VALUE_THEN_ENDED_REFERENCE', 2), (${u(107)}, ${u(2)}, ${u(21)}, 'VALUE_THEN_REFERENCE', 1),
    (${u(108)}, ${u(2)}, ${u(21)}, 'ENDED_OVER_UNENDED', 0), (${u(109)}, ${u(2)}, ${u(21)}, 'REFERENCE_THEN_VALUE', 1);
  INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by, plaintext, sensitive) VALUES
    ${[
      version(1011, 101, 1, { sensitive: true }),
      version(1021, 102, 1),
      version(1022, 102, 2, { plaintext: 'pk_live' }),
      // An erased version, of a place since deleted: 0.14 empties its ciphertext and its wrapped key.
      version(1061, 106, 1, { erased: true }),
      version(1062, 106, 2),
      version(1071, 107, 1),
      version(1091, 109, 1),
    ].join(',\n    ')};
  UPDATE secrets SET current_version_id = ${u(1011)} WHERE id = ${u(101)};
  UPDATE secrets SET current_version_id = ${u(1022)} WHERE id = ${u(102)};
  UPDATE secrets SET current_version_id = ${u(1091)} WHERE id = ${u(109)};
  INSERT INTO dismissed_keys (environment_id, key, dismissed_by) VALUES (${u(12)}, 'STRIPE_KEY', '${ADA}');
  INSERT INTO vault_grants (principal, project_id, environment_id, environment_slug, role, expires_at, granted_at, granted_by) VALUES
    ('${ADA}', ${u(1)}, NULL, NULL, 'maintainer', NULL, ${T0 + 7}, 'system:setup'),
    ('${API}', NULL, ${u(11)}, NULL, 'viewer', ${T0 + 400 * day + 1}, ${T0 + 8}, '${ADA}');
  INSERT INTO audit_log (${ENTRY_COLUMNS}) VALUES
    ${[
      // References: 10 seals billing/DATABASE_URL, live; 11 seals OLD_REFERENCE, which 12 ends; FORGED_REFERENCE's row points at 13, which seals nothing.
      seal(10, 201, 103, 101),
      seal(11, 202, 104, 102),
      entry(12, 'vault', ADA, 'reference.end', { related: 11, metadata: { reason: 'removed' } }),
      entry(13, 'app', ADA, 'secret.write'),
      // A secret with two versions that became a reference (14), which 15 ended: it has no value, not version 2 back.
      seal(14, 204, 106, 102),
      entry(15, 'vault', ADA, 'reference.end', { related: 14, metadata: { reason: 'broken' } }),
      // One with a version that became a reference, live (16). One whose newest reference (18) ended, over an older
      // one never ended (17): no reference. One given a value after its reference (19): a value.
      seal(16, 205, 107, 101),
      seal(17, 206, 108, 101),
      seal(18, 207, 108, 102),
      entry(19, 'vault', ADA, 'reference.end', { related: 18, metadata: { reason: 'broken' } }),
      seal(25, 208, 109, 101),
      // A binding unbound; freezes, of every target: the instance (lifted), a service, a binding (frozen, lifted, frozen), a session, two upstream credentials (one lifted).
      entry(20, 'app', ADA, 'token.unbind', { metadata: { bindingId: id(302) } }),
      entry(30, 'app', ADA, 'workload.freeze', { metadata: { target: 'instance' } }),
      entry(31, 'app', ADA, 'workload.unfreeze', { metadata: { target: 'instance' } }),
      entry(32, 'app', ADA, 'workload.freeze', { metadata: { target: API } }),
      entry(33, 'app', ADA, 'workload.freeze', { metadata: { target: `binding:${id(303)}` } }),
      entry(34, 'app', ADA, 'workload.unfreeze', { metadata: { target: `binding:${id(303)}` } }),
      entry(35, 'app', ADA, 'workload.freeze', { metadata: { target: `binding:${id(303)}` } }),
      entry(36, 'app', ADA, 'workload.freeze', { metadata: { target: `session:${id(503)}` } }),
      entry(37, 'app', ADA, 'workload.freeze', { metadata: { target: `credential:${id(11)}/stripe` } }),
      entry(38, 'app', ADA, 'workload.freeze', { metadata: { target: `credential:${id(11)}/old` } }),
      entry(39, 'app', ADA, 'workload.unfreeze', { metadata: { target: `credential:${id(11)}/old` } }),
      entry(40, 'app', ADA, 'workload.freeze', { decision: 'deny', metadata: { target: CI } }),
      entry(41, 'app', ADA, 'workload.freeze', { metadata: { target: `credential:${id(11)}/adyen` } }),
      // A code superseded, and the run a session was issued for.
      entry(50, 'app', CI, 'enrollment.supersede', { metadata: { enrollmentId: id(402) } }),
      entry(51, 'app', API, 'token.exchange', { metadata: { credentialId: id(503), bindingId: id(301), run: { repository: 'acme/api', run_id: '77' } } }),
      // Reads: Ada's two of STRIPE_KEY, one listing DATABASE_URL, one refused; and one by a principal no row names.
      entry(60, 'vault', ADA, 'secret.read', { secret: 102, at: T0 + 2 * day }),
      entry(61, 'vault', ADA, 'secret.read', { secret: 102, at: T0 + 3 * day + 456 }),
      entry(62, 'vault', ADA, 'secret.read', { at: T0 + 4 * day, metadata: { secrets: [{ secretId: id(101) }, { secretId: 'not-a-secret' }] } }),
      entry(63, 'vault', ADA, 'secret.read', { decision: 'deny', secret: 103 }),
      entry(64, 'vault', 'token:gone', 'secret.read', { secret: 102 }),
      entry(65, 'vault', API, 'secret.read', { secret: 102, at: T0 + 6 * day }),
    ].join(',\n    ')};
  INSERT INTO secret_references (id, project_id, environment_id, secret_id, source_project_id, source_environment_id, source_secret_id, created_seq, created_by) VALUES
    (${u(201)}, ${u(2)}, ${u(21)}, ${u(103)}, ${u(1)}, ${u(11)}, ${u(101)}, 10, '${ADA}'),
    (${u(202)}, ${u(2)}, ${u(21)}, ${u(104)}, ${u(1)}, ${u(11)}, ${u(102)}, 11, '${ADA}'),
    (${u(203)}, ${u(2)}, ${u(21)}, ${u(105)}, ${u(1)}, ${u(11)}, ${u(101)}, 13, '${ADA}'),
    (${u(204)}, ${u(2)}, ${u(21)}, ${u(106)}, ${u(1)}, ${u(11)}, ${u(102)}, 14, '${ADA}'),
    (${u(205)}, ${u(2)}, ${u(21)}, ${u(107)}, ${u(1)}, ${u(11)}, ${u(101)}, 16, '${ADA}'),
    (${u(206)}, ${u(2)}, ${u(21)}, ${u(108)}, ${u(1)}, ${u(11)}, ${u(101)}, 17, '${ADA}'),
    (${u(207)}, ${u(2)}, ${u(21)}, ${u(108)}, ${u(1)}, ${u(11)}, ${u(102)}, 18, '${ADA}'),
    (${u(208)}, ${u(2)}, ${u(21)}, ${u(109)}, ${u(1)}, ${u(11)}, ${u(101)}, 25, '${ADA}');
  INSERT INTO identities (id, provider, auth_mac, subject, issuer_hash, generation, principal, email, created_by, revoked_at) VALUES
    (${u(601)}, 'github', ${h(4)}, '1001', 'x', 0, '${ADA}', 'ada@acme.example', 'system:setup', NULL),
    (${u(602)}, 'github', ${h(4)}, '1002', 'x', 0, '${BO}', 'bo@acme.example', '${ADA}', now());
  INSERT INTO service_bindings (id, auth_mac, principal, generation, profile, issuer, jwks_uri, claims, created_by) VALUES
    (${u(301)}, ${h(4)}, '${API}', 0, 'kubernetes', 'https://k8s.example', 'sha256:00', '{}', '${ADA}'),
    (${u(302)}, ${h(4)}, '${CI}', 0, 'github', 'https://token.actions.githubusercontent.com', 'https://token.actions.githubusercontent.com/.well-known/jwks', '{}', '${ADA}'),
    (${u(303)}, ${h(4)}, '${CI}', 0, 'github', 'https://token.actions.githubusercontent.com', 'https://token.actions.githubusercontent.com/.well-known/jwks', '{}', '${ADA}');
  INSERT INTO enrollments (id, auth_mac, binding_id, code_hash, code_hint, scope, created_by, expires_at) VALUES
    (${u(401)}, ${h(4)}, ${u(301)}, ${h(41)}, 'coffre_enr_…aaaa', '[]', '${CI}', now() + interval '30 days'),
    (${u(402)}, ${h(4)}, ${u(301)}, ${h(42)}, 'coffre_enr_…bbbb', '[]', '${CI}', now() + interval '30 days');
  INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, identity_id, label, created_by, expires_at, revoked_at, revoked_by, jkt, enrollment_id) VALUES
    (${u(501)}, 'cli', ${h(4)}, ${h(51)}, 'coffre_cli_…abcd', 0, '${ADA}', ${u(601)}, 'laptop', '${ADA}', now() + interval '30 days', NULL, NULL, NULL, NULL),
    (${u(502)}, 'service', ${h(4)}, ${h(52)}, 'coffre_svc_…efgh', 0, '${CI}', NULL, NULL, '${ADA}', now() - interval '2 days', NULL, NULL, NULL, NULL),
    (${u(503)}, 'workload', ${h(4)}, ${h(53)}, 'coffre_wl_…ijkl', 0, '${API}', NULL, NULL, 'binding:${id(301)}', now() + interval '1 hour', NULL, NULL, 'thumb', ${u(401)}),
    (${u(504)}, 'personal', ${h(4)}, ${h(54)}, 'coffre_pat_…mnop', 0, '${ADA}', NULL, 'scripts', '${ADA}', now() + interval '30 days', now() - interval '1 hour', '${ADA}', NULL, NULL),
    (${u(505)}, 'browser', ${h(4)}, ${h(55)}, 'coffre_web_…qrst', 0, '${ADA}', ${u(601)}, NULL, '${ADA}', now() - interval '2 hours', NULL, NULL, NULL, NULL);
  INSERT INTO mcp_connections (id, auth_mac, principal, generation, client_id, client_name, client_host, registration, scopes, redirect_uri, code_hash, code_challenge, code_expires_at, refresh_hash, refresh_previous_hash, expires_at, revoked_at, revoked_by) VALUES
    (${u(701)}, ${h(4)}, '${ADA}', 0, 'https://claude.ai/client.json', 'Claude', 'claude.ai', 'cimd', 'read write', 'https://claude.ai/cb', NULL, NULL, NULL, ${h(71)}, ${h(72)}, now() + interval '30 days', NULL, NULL),
    (${u(702)}, ${h(4)}, '${ADA}', 0, 'c2', 'Revoked', NULL, 'dcr', 'read', 'https://two.example/cb', NULL, NULL, NULL, ${h(73)}, NULL, now() + interval '30 days', now(), '${ADA}'),
    (${u(703)}, ${h(4)}, '${ADA}', 0, 'c3', 'Unredeemed', NULL, 'dcr', 'read', 'https://three.example/cb', ${h(74)}, 'challenge', now() + interval '1 minute', NULL, NULL, now() + interval '30 days', NULL, NULL);
  INSERT INTO mcp_approvals (id, connection_id, tool, arguments, digest, expires_at) VALUES
    (${u(801)}, ${u(701)}, 'set_secret', '{}', ${h(81)}, now() + interval '5 minutes'),
    (${u(802)}, ${u(702)}, 'set_secret', '{}', ${h(82)}, now() + interval '5 minutes');
  INSERT INTO oauth_clients (id, auth_mac, name, redirect_uris) VALUES (${u(901)}, ${h(4)}, 'Three', '["https://three.example/cb"]');
  INSERT INTO consumed_tokens (hash, consumed_at) VALUES (${h(91)}, now() - interval '5 minutes'), (${h(92)}, now() - interval '3 hours');
  INSERT INTO device_authorizations (device_code_hash, auth_mac, user_code, expires_at) VALUES (${h(93)}, ${h(4)}, 'ABCD-EFGH', now() + interval '10 minutes');
  INSERT INTO capped_alerts (service, kind, raised_at) VALUES ('${API}', 'unknown_key', now());
`;

/** A time as the driver gives one, Postgres's own text, in milliseconds. */
const ms = (value: unknown) => new Date(canonicalTimestamp(value as string)).getTime();

test('a 0.14 database upgrades in place, only with coffre offline, and every row becomes what the design says', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-upgrade-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const admin = await session(urlOf('postgres'));
  t.after(() => admin.end());
  await admin.query(`DROP DATABASE IF EXISTS ${UPGRADED}`);
  await admin.query(`CREATE DATABASE ${UPGRADED}`);
  const login = (canLogin: boolean) => admin.query(`ALTER ROLE coffre_runtime ${canLogin ? 'LOGIN' : 'NOLOGIN'}; ALTER ROLE coffre_vault_runtime ${canLogin ? 'LOGIN' : 'NOLOGIN'}`);
  await login(true);

  const db = await session(urlOf(UPGRADED));
  t.after(() => db.end());
  const rows = async <R = Record<string, unknown>>(text: string) => (await db.query(text)).rows as R[];
  const one = async <R = Record<string, unknown>>(text: string) => (await rows<R>(text))[0]!;

  // Drizzle's migrator on coffre's own driver, as `migrateDatabase` runs it.
  await migrate(createDatabase(db.client) as unknown as Parameters<typeof migrate>[0], { migrationsFolder: before(dir) });
  await db.query(SEED);
  const count = async (table: string) => Number((await one<{ n: string }>(`SELECT count(*) AS n FROM ${table}`)).n);

  // Online, it changes nothing: the migration is one transaction.
  await assert.rejects(migrateDatabase(urlOf(UPGRADED)), (error: Error) => /still online.*Set coffre_runtime, coffre_vault_runtime NOLOGIN/.test(String((error as { cause?: unknown }).cause ?? error)));
  assert.equal(await count('vault_members'), 4);

  // A session a runtime login still holds refuses it too.
  const held = await session(urlOf(UPGRADED, { name: 'coffre_runtime', password: 'local-runtime-only' }));
  try {
    await login(false);
    await assert.rejects(migrateDatabase(urlOf(UPGRADED)), (error: Error) => /coffre_runtime still has a session open/.test(String((error as { cause?: unknown }).cause ?? error)));
    // Another login a host gave the app's rights is coffre online too.
    await admin.query(`DROP ROLE IF EXISTS reporting; CREATE ROLE reporting LOGIN; GRANT coffre_app TO reporting`);
    await assert.rejects(migrateDatabase(urlOf(UPGRADED)), (error: Error) => /still online.*Set reporting NOLOGIN/.test(String((error as { cause?: unknown }).cause ?? error)));
    await admin.query(`DROP ROLE reporting`);
    // A host's administrator is not: Postgres 16 makes whoever created a role its member, and some hosts have that inherit.
    await admin.query(`DROP ROLE IF EXISTS host_admin; CREATE ROLE host_admin LOGIN CREATEROLE; GRANT coffre_app, coffre_vault TO host_admin`);
  } finally {
    await held.end();
  }
  // Postgres drops the session from its list a moment after the client goes.
  for (let i = 0; i < 50 && (await rows(`SELECT 1 FROM pg_stat_activity WHERE usename = 'coffre_runtime'`)).length > 0; i += 1) await new Promise((done) => setTimeout(done, 100));

  // A member 0.14's vault refuses, their row changed around it, stops it, until they are removed.
  await db.query(`INSERT INTO audit_log (${ENTRY_COLUMNS}) VALUES ${entry(70, 'vault', 'system:vault', 'vault.tampered', { decision: 'deny', code: 'mac', subject: BO })}`);
  await assert.rejects(migrateDatabase(urlOf(UPGRADED)), (error: Error) => /that report stands/.test(String((error as { cause?: unknown }).cause ?? error)) && String((error as { cause?: unknown }).cause).includes(BO));
  await db.query(`INSERT INTO audit_log (${ENTRY_COLUMNS}) VALUES ${entry(71, 'vault', ADA, 'member.remove', { subject: BO })}`);
  assert.equal(await count('vault_members'), 4);
  const archived = await count('audit_log');

  await migrateDatabase(urlOf(UPGRADED));
  await login(true);
  await admin.query(`DROP ROLE host_admin`);

  await t.test('principals: a row of 0.4 gets its role, and times keep their milliseconds', async () => {
    assert.deepEqual(
      (await rows(`SELECT id, status, role, generation, status_changed_at, frozen_at IS NOT NULL AS frozen, mac FROM principals ORDER BY id`)).map((row) => ({ ...row, status_changed_at: ms(row.status_changed_at), mac: (row.mac as Buffer).length })),
      [
        { id: API, status: 'active', role: 'member', generation: 0, status_changed_at: T0, frozen: true, mac: 0 },
        { id: CI, status: 'active', role: 'member', generation: 0, status_changed_at: T0, frozen: false, mac: 0 },
        { id: ADA, status: 'active', role: 'admin', generation: 0, status_changed_at: T0, frozen: false, mac: 0 },
        { id: BO, status: 'removed', role: 'member', generation: 1, status_changed_at: T0 + 5 * day + 123, frozen: false, mac: 0 },
      ],
    );
  });

  await t.test('grants: each gets an id, and keeps its place and its end', async () => {
    const found = await rows(`SELECT id, principal, project_id, environment_id, role, expires_at, granted_at FROM grants ORDER BY principal`);
    assert.deepEqual(
      found.map((row) => ({ ...row, id: typeof row.id, expires_at: row.expires_at === null ? null : ms(row.expires_at), granted_at: ms(row.granted_at) })),
      [
        { id: 'string', principal: API, project_id: null, environment_id: id(11), role: 'viewer', expires_at: T0 + 400 * day + 1, granted_at: T0 + 8 },
        { id: 'string', principal: ADA, project_id: id(1), environment_id: null, role: 'maintainer', expires_at: null, granted_at: T0 + 7 },
      ],
    );
    assert.notEqual(found[0]!.id, found[1]!.id);
  });

  await t.test('secrets: a live reference is its holder\'s source, and a secret with no value of its own gets none back', async () => {
    assert.deepEqual(await rows(`SELECT key, source_id, versions, current_version FROM secrets WHERE project_id = ${u(2)} ORDER BY key`), [
      { key: 'DATABASE_URL', source_id: id(101), versions: 0, current_version: null },
      { key: 'ENDED_OVER_UNENDED', source_id: null, versions: 0, current_version: null },
      { key: 'FORGED_REFERENCE', source_id: null, versions: 0, current_version: null },
      { key: 'OLD_REFERENCE', source_id: null, versions: 0, current_version: null },
      { key: 'REFERENCE_THEN_VALUE', source_id: null, versions: 1, current_version: 1 },
      // Version 2 was replaced by the reference, and the reference ended: no value, and the next version is 3.
      { key: 'VALUE_THEN_ENDED_REFERENCE', source_id: null, versions: 2, current_version: null },
      { key: 'VALUE_THEN_REFERENCE', source_id: id(101), versions: 1, current_version: null },
    ]);
    assert.equal(await count('secret_versions'), 7);
    assert.deepEqual(await rows(`SELECT s.key, v.id FROM secrets s JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version ORDER BY s.key, s.id`), [
      { key: 'DATABASE_URL', id: id(1011) },
      { key: 'REFERENCE_THEN_VALUE', id: id(1091) },
      { key: 'STRIPE_KEY', id: id(1022) },
    ]);
    // An erased version stays erased: the adoption has nothing of it to encrypt again.
    assert.deepEqual(await rows(`SELECT octet_length(ciphertext) AS ciphertext, octet_length(wrapped_dek) AS wrapped FROM secret_versions WHERE id = ${u(1061)}`), [{ ciphertext: 0, wrapped: 0 }]);
  });

  await t.test('freezes: each is a field of the row it stops', async () => {
    assert.deepEqual(await rows(`SELECT id, frozen_at IS NOT NULL AS frozen, revoked_at IS NOT NULL AS revoked, revoked_by FROM bindings ORDER BY id`), [
      { id: id(301), frozen: false, revoked: false, revoked_by: null },
      { id: id(302), frozen: false, revoked: true, revoked_by: ADA },
      { id: id(303), frozen: true, revoked: false, revoked_by: null },
    ]);
    assert.equal(ms((await one(`SELECT frozen_at FROM bindings WHERE id = ${u(303)}`)).frozen_at), T0 + 35_000);
    assert.equal(ms((await one(`SELECT revoked_at FROM bindings WHERE id = ${u(302)}`)).revoked_at), T0 + 20_000);
    assert.deepEqual(await rows(`SELECT slug, protected, frozen_credentials FROM environments ORDER BY id`), [
      { slug: 'prod', protected: false, frozen_credentials: ['adyen', 'stripe'] },
      { slug: 'dev', protected: false, frozen_credentials: [] },
      { slug: 'prod', protected: false, frozen_credentials: [] },
    ]);
  });

  await t.test('credentials: the dead go, an MCP connection is one, and a session keeps its run and its freeze', async () => {
    assert.deepEqual(await rows(`SELECT id, kind, label, token_hint, frozen_at IS NOT NULL AS frozen, revoked_at IS NOT NULL AS revoked, run, client, previous_token_hash IS NOT NULL AS replaced FROM credentials ORDER BY id`), [
      { id: id(501), kind: 'cli', label: 'laptop', token_hint: 'coffre_cli_…abcd', frozen: false, revoked: false, run: null, client: null, replaced: false },
      { id: id(503), kind: 'workload', label: null, token_hint: 'coffre_wl_…ijkl', frozen: true, revoked: false, run: '{"run_id": "77", "repository": "acme/api"}', client: null, replaced: false },
      { id: id(504), kind: 'personal', label: 'scripts', token_hint: 'coffre_pat_…mnop', frozen: false, revoked: true, run: null, client: null, replaced: false },
      // Expired two hours ago: the upkeep's to delete, a day after.
      { id: id(505), kind: 'browser', label: null, token_hint: 'coffre_web_…qrst', frozen: false, revoked: false, run: null, client: null, replaced: false },
      { id: id(701), kind: 'mcp', label: 'Claude', token_hint: null, frozen: false, revoked: false, run: null, client: '{"id": "https://claude.ai/client.json", "host": "claude.ai", "scopes": "read write", "redirectUri": "https://claude.ai/cb", "registration": "cimd"}', replaced: true },
    ]);
    assert.deepEqual(await rows(`SELECT token_hash = ${h(71)} AS refresh, created_by FROM credentials WHERE kind = 'mcp'`), [{ refresh: true, created_by: ADA }]);
    assert.deepEqual(await rows(`SELECT id, connection_id FROM mcp_approvals`), [{ id: id(801), connection_id: id(701) }]);
    assert.deepEqual(await rows(`SELECT id, superseded_at IS NOT NULL AS superseded FROM enrollment_codes ORDER BY id`), [
      { id: id(401), superseded: false },
      { id: id(402), superseded: true },
    ]);
    assert.deepEqual(await rows(`SELECT hash = ${h(91)} AS recent FROM spent_id_tokens`), [{ recent: true }]);
    assert.equal(await count('device_logins'), 0);
    assert.equal(await count('identities'), 2);
    assert.equal(await count('oauth_clients'), 1);
    assert.equal(await count('dismissed_keys'), 1);
  });

  await t.test('exposures: who saw which key, and when last, from every read the vault allowed', async () => {
    assert.deepEqual(
      (await rows(`SELECT principal, secret_id, seen_at FROM exposures ORDER BY principal, secret_id`)).map((row) => ({ ...row, seen_at: ms(row.seen_at) })),
      [
        { principal: API, secret_id: id(102), seen_at: T0 + 6 * day },
        { principal: ADA, secret_id: id(101), seen_at: T0 + 4 * day },
        { principal: ADA, secret_id: id(102), seen_at: T0 + 3 * day + 456 },
      ],
    );
  });

  await t.test('the archive keeps every entry, and nothing of the log or the policy has a row until the vault adopts', async () => {
    assert.equal(await count('audit_archive'), archived);
    for (const table of ['roles', 'policy', 'log_pending', 'log', 'log_index', 'log_tiles', 'log_head']) assert.equal(await count(table), 0, table);
    assert.deepEqual(await rows(`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename IN ('vault_members', 'vault_grants', 'audit_log', 'audit_chain_head', 'secret_references', 'mcp_connections', 'vault_releases', 'capped_alerts', 'device_authorizations')`), []);
  });

  await t.test('the vault\'s login writes, and the app\'s only reads', async () => {
    const as = async (name: string, password: string, text: string) => {
      const client = await session(urlOf(UPGRADED, { name, password }));
      try {
        return await client.query(text);
      } finally {
        await client.end();
      }
    };
    const write = `UPDATE principals SET frozen_at = NULL WHERE id = '${CI}'`;
    await as('coffre_vault_runtime', 'local-vault-only', write);
    await as('coffre_vault_runtime', 'local-vault-only', `INSERT INTO log_pending (kept, body, mac) VALUES (true, '{}', '\\x${'00'.repeat(36)}'); DELETE FROM log_pending`);
    await assert.rejects(as('coffre_runtime', 'local-runtime-only', write), /permission denied/);
    await assert.rejects(as('coffre_runtime', 'local-runtime-only', `INSERT INTO log_pending (kept, body, mac) VALUES (true, '{}', '\\x${'00'.repeat(36)}')`), /permission denied/);
    await assert.rejects(as('coffre_vault_runtime', 'local-vault-only', `DELETE FROM audit_archive`), /permission denied/);
    assert.equal((await as('coffre_runtime', 'local-runtime-only', `SELECT count(*) AS n FROM audit_archive`)).rows[0].n, String(archived));
  });
});
