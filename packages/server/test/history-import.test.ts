import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { and, asc, count, eq } from 'drizzle-orm';

import { planImport, type CoffreClient } from '../../client/src/index.ts';
import { parseDotenv } from '../../core/src/dotenv.ts';
import { auditLog, secrets, secretVersions } from './db/tables.ts';
import { serveApi } from '../src/api/router.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

const ROOT = 'admin@acme.example';
const VIEWER = 'viewer@acme.example';
const READER = 'reader@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let viewer: CoffreClient;
let reader: CoffreClient;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  viewer = clientFor(deps, VIEWER);
  reader = clientFor(deps, READER);

  await root.members.add(`user:${VIEWER}`);
  await root.members.add(`user:${READER}`);
  await root.members.add('user:leaver@acme.example');
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Dev' });
  await root.access.set(`user:${READER}`, { 'market/dev': 'viewer' });
});

/** What `coffre import` does: parse, compare, then write the difference in one patch. */
async function importText(content: string, dryRun: boolean, as = root) {
  const { entries, problems } = parseDotenv(content);
  const { plan, changes } = await planImport(as, 'market/dev', entries);
  if (!dryRun) await as.secrets.set('market/dev', changes);
  return { plan, changes, problems };
}

async function auditRows(action: string, decision: 'allow' | 'deny') {
  const rows = await db.owner
    .select({ metadata: auditLog.metadata, bundleId: auditLog.bundleId })
    .from(auditLog)
    .where(and(eq(auditLog.action, action), eq(auditLog.decision, decision)))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ bundleId: row.bundleId, metadata: JSON.parse(row.metadata) }));
}

/** A raw PATCH, for query strings the client would never send. */
async function patchAs(query: string, body: unknown): Promise<Response> {
  const request = new Request(`https://coffre.test/api/secrets/market/dev${query}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return serveApi(request, await contextFor(deps, ROOT));
}

async function versionCount(): Promise<number> {
  const [row] = await db.owner.select({ n: count() }).from(secretVersions);
  return row.n;
}

test('parses the shapes a real .env file contains', () => {
  const { entries, problems } = parseDotenv(
    [
      '# a comment',
      '',
      'DATABASE_URL=db-demo://user:pw@host/db',
      'export EXPORTED=value',
      'QUOTED="hello world"',
      "SINGLE='literal $NOT_INTERPOLATED'",
      'WITH_ESCAPE="line\\nbreak"',
      'TRAILING=value # trailing comment',
      'EMPTY=',
      '  SPACED  =  padded  ',
    ].join('\n'),
  );
  assert.deepEqual(problems, []);
  assert.deepEqual(Object.fromEntries(entries.map((entry) => [entry.key, entry.value])), {
    DATABASE_URL: 'db-demo://user:pw@host/db',
    EXPORTED: 'value',
    QUOTED: 'hello world',
    SINGLE: 'literal $NOT_INTERPOLATED',
    WITH_ESCAPE: 'line\nbreak',
    TRAILING: 'value',
    EMPTY: '',
    SPACED: 'padded',
  });
});

test('reports malformed lines rather than silently mangling them', () => {
  const { entries, problems } = parseDotenv(
    ['GOOD=1', 'no equals sign here', '1BAD_KEY=x', 'UNTERMINATED="oh dear', 'GOOD=2'].join('\n'),
  );
  assert.deepEqual(entries.map((entry) => entry.key), ['GOOD']);
  assert.equal(problems.length, 4);
  assert.match(problems[0].reason, /no "="/);
  assert.match(problems[1].reason, /key must match/);
  assert.match(problems[2].reason, /unterminated/);
  assert.match(problems[3].reason, /duplicate/);
});

test('version history reports authors and current version without values', async () => {
  for (const value of ['v1', 'v2', 'v3']) {
    await root.secrets.set('market/dev', { API_KEY: value });
  }
  const history = await root.secrets.history('market/dev/API_KEY');
  assert.deepEqual(history.versions.map((version) => version.version), [3, 2, 1]);
  assert.equal(history.versions[0].current, true);
  assert.equal(history.versions[1].current, false);
  assert.equal(history.versions[0].createdBy, ROOT);
  assert.match(history.versions[0].createdAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(JSON.stringify(history).includes('v3'), false);
});

test('version history requires secret.read', async () => {
  await root.secrets.set('market/dev', { API_KEY: 'v1' });
  await assert.rejects(viewer.secrets.history('market/dev/API_KEY'), { status: 403 });
});

test('restoring adds a version holding the old value, and writes continue forward', async () => {
  for (const value of ['first', 'second', 'third']) {
    await root.secrets.set('market/dev', { API_KEY: value });
  }
  assert.deepEqual(await root.secrets.restore('market/dev/API_KEY', 1), { key: 'API_KEY', version: 4 });
  assert.equal((await root.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'first');
  assert.equal(await versionCount(), 4);
  assert.deepEqual((await root.secrets.set('market/dev', { API_KEY: 'fifth' })).keys.API_KEY, { version: 5 });
});

test('a restore is audited with both versions, and refused without write permission', async () => {
  await root.secrets.set('market/dev', { API_KEY: 'v1' });
  await root.secrets.set('market/dev', { API_KEY: 'v2' });
  await root.secrets.restore('market/dev/API_KEY', 1);
  assert.deepEqual((await auditRows('secret.rollback', 'allow'))[0].metadata, {
    key: 'API_KEY',
    fromVersion: 2,
    toVersion: 1,
    version: 3,
  });
  await assert.rejects(reader.secrets.restore('market/dev/API_KEY', 2), { status: 403 });
  assert.equal((await auditRows('secret.rollback', 'deny'))[0].metadata.reason, 'missing_secret_write');
});

test('restoring an unknown version is rejected and audited', async () => {
  await root.secrets.set('market/dev', { API_KEY: 'v1' });
  await assert.rejects(root.secrets.restore('market/dev/API_KEY', 99), { status: 404 });
  assert.equal((await auditRows('secret.rollback', 'deny'))[0].metadata.reason, 'unknown_version');
});

test('a dry run reports the plan and writes nothing', async () => {
  const result = await importText('A=one\nB=two', true);
  assert.deepEqual(result.plan.map(({ key, action }) => [key, action]), [
    ['A', 'added'],
    ['B', 'added'],
  ]);
  assert.equal((await db.owner.select().from(secrets)).length, 0);
});

test('a dry run of a write answers per key, returns no value, and writes nothing', async () => {
  await root.secrets.set('market/dev', { SAME: 'same-value', OLD: 'old-value', GONE: 'gone-value' });
  const versions = await versionCount();
  const writes = (await auditRows('secret.write', 'allow')).length;

  const result = await root.secrets.dryRun('market/dev', {
    SAME: 'same-value',
    OLD: 'new-value',
    NEW: 'fresh-value',
    GONE: null,
    NEVER: null,
  });

  assert.deepEqual(result, {
    dryRun: true,
    keys: { SAME: 'unchanged', OLD: 'changed', NEW: 'added', GONE: 'archived', NEVER: 'unchanged' },
  });
  assert.doesNotMatch(JSON.stringify(result), /-value/);
  assert.equal(await versionCount(), versions);
  assert.equal((await auditRows('secret.write', 'allow')).length, writes);
  assert.equal((await db.owner.select().from(secrets)).length, 3);
  assert.deepEqual({ ...(await root.secrets.reveal('market/dev')).values }, {
    SAME: 'same-value',
    OLD: 'old-value',
    GONE: 'gone-value',
  });
});

test('a dry run is spelled one way; anything else is refused before it writes', async () => {
  for (const query of ['?dryRun=yes', '?dryrun=1', '?dryRun=1&apply=1']) {
    assert.equal((await patchAs(query, { A: 'one' })).status, 400, query);
  }
  assert.equal((await db.owner.select().from(secrets)).length, 0);
  assert.equal((await patchAs('?dryRun=true', { A: 'one' })).status, 200);
  assert.equal((await db.owner.select().from(secrets)).length, 0);
});

test('a preview logs a read of every existing secret it compares', async () => {
  await root.secrets.set('market/dev', { A: 'one', B: 'two' });
  await importText('A=one\nB=changed\nC=new', true);
  const reads = await auditRows('secret.read', 'allow');
  assert.deepEqual(reads.map((row) => row.metadata.key).sort(), ['A', 'B']);
  assert.ok(reads.every((row) => row.metadata.dryRun === true));
  assert.equal(new Set(reads.map((row) => row.bundleId)).size, 1);
});

test('import creates every secret, one audit entry per key in one bundle', async () => {
  await importText('A=one\nB=two\nC=three', false);
  assert.deepEqual({ ...(await root.secrets.reveal('market/dev')).values }, { A: 'one', B: 'two', C: 'three' });
  const rows = await auditRows('secret.write', 'allow');
  assert.equal(rows.length, 3);
  assert.equal(new Set(rows.map((row) => row.bundleId)).size, 1);
});

test('re-importing unchanged values adds no versions', async () => {
  await importText('A=one\nB=two', false);
  const before = await versionCount();
  const again = await importText('A=one\nB=two', false);
  assert.deepEqual(again.plan.map(({ action }) => action), ['unchanged', 'unchanged']);
  assert.deepEqual(again.changes, {});
  assert.equal(await versionCount(), before);
});

test('import distinguishes added from changed', async () => {
  await root.secrets.set('market/dev', { A: 'old' });
  const result = await importText('A=new\nB=created', false);
  assert.deepEqual(result.plan.map(({ key, action, version }) => [key, action, version]), [
    ['A', 'changed', 1],
    ['B', 'added', null],
  ]);
  assert.equal((await root.secrets.reveal('market/dev/A')).values.A, 'new');
});

test('import reports parse problems alongside valid entries', async () => {
  const result = await importText('A=one\nnot valid\nB=two', false);
  assert.equal(result.plan.length, 2);
  assert.equal(result.problems.length, 1);
  assert.equal(result.problems[0].line, 2);
});

test('import refuses to write over an archived secret', async () => {
  await root.secrets.set('market/dev', { A: 'one' });
  await root.secrets.set('market/dev', { A: null });
  await assert.rejects(importText('A=two', false), { status: 409 });
});

test('import needs read to plan and write to apply, and refusals are audited', async () => {
  await assert.rejects(importText('A=one', false, viewer), { status: 403 });
  assert.equal((await auditRows('secret.list', 'deny'))[0].metadata.reason, 'missing_secret_read');
  assert.deepEqual((await auditRows('secret.read', 'deny'))[0].metadata, {
    reason: 'missing_secret_read',
    dryRun: true,
  });
  await assert.rejects(importText('A=one', false, reader), { status: 403 });
  assert.equal((await auditRows('secret.write', 'deny'))[0].metadata.reason, 'missing_secret_write');
  assert.equal((await db.owner.select().from(secrets)).length, 0);
});

test('the audit chain verifies across history, restore, and import', async () => {
  await root.secrets.set('market/dev', { API_KEY: 'v1' });
  await root.secrets.set('market/dev', { API_KEY: 'v2' });
  await root.secrets.restore('market/dev/API_KEY', 1);
  await importText('A=one\nB=two', false);
  assert.equal((await root.audit.verify()).ok, true);
});

test('creating a project does not grant its creator access to secrets', async () => {
  assert.deepEqual((await deps.vault.access(`user:${ROOT}`)).grants, []);
  assert.deepEqual((await root.members.list('market')).members.map((entry) => entry.member), [`user:${READER}`]);
});

test('a member shows what they still hold', async () => {
  await root.access.set('user:leaver@acme.example', { market: 'auditor' });
  const leaver = (await root.members.list()).members.find(
    (entry) => entry.member === 'user:leaver@acme.example',
  );
  assert.deepEqual(leaver?.grants.map(({ project, environment, role }) => ({ project, environment, role })), [
    { project: 'market', environment: null, role: 'auditor' },
  ]);
});

test('members exist independently of project access', async () => {
  await root.members.add('user:grantless@acme.example');
  assert.ok((await root.members.list()).members.some((entry) => entry.member === 'user:grantless@acme.example'));
  assert.equal(
    (await root.members.list('market')).members.some((entry) => entry.member === 'user:grantless@acme.example'),
    false,
  );
});
