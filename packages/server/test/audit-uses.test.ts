// Reads on every audit list (T166). With 0.15's log a read writes no 0.14
// `secret.read` entry: its use is the record (R53), and the audit lists show
// each where that entry stood, with who read what, which version, for what
// and through what, at the places and by the members the list asks for, every
// one vouched for by the vault. Under 0.14's log the same lists show its own
// entries: each test holds both.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type AuditEntryView, type CoffreClient } from '@coffre/client';
import { defineSignin, github } from '@coffre/core/identity';
import { logObject } from '@coffre/db/log';
import { and, desc, eq } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { credentials, logChanges, logUses, secretReferences, secrets, secretVersions } from './db/tables.ts';
import { clientFor, LOG, openTestDatabase, resetDatabase, testDeps, usesLogged, waitUntil, type FixtureDeps } from './api-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';
const BOB = 'user:bob@acme.example';
const SIGNIN = defineSignin({ publicUrl: ORIGIN, providers: [github({ clientId: 'a', clientSecret: 'b' })] });

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let root: CoffreClient;
/** Ada's personal token: a Developer of market's dev, reading through it as a run or an agent would. */
let ada: CoffreClient;
let adaToken: { id: string; label: string };

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.signin = signin;
  runtime = {
    db: deps.db, vault: deps.vault, chainKey: deps.chainKey, previousChainKeys: [], signin, workloads: null, mcp: null,
    auth: { mode: 'signin', signin: SIGNIN }, publicUrl: ORIGIN, verifier: signin, waitUntil,
    schema: { migrated: true }, appKey: { settled: true }, rotateAfterDays: 365, plugins: [],
  } as CoffreRuntime;
  root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) {
    await root.environments.create(`market/${environment}`, { name: environment });
    await root.secrets.set(`market/${environment}`, { API_KEY: `${environment}-key`, OTHER: `${environment}-other` });
  }
  await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } });
  const issued = await clientFor(deps, 'ada@acme.example').tokens.issue(ADA, { label: 'agent', expiresInMinutes: 60, scope: { 'market/dev': 'developer' } });
  ada = bearer(issued.token);
  adaToken = { id: issued.id, label: 'agent' };
});

/** The API as a request with this bearer token sees it, through the app's front door. */
function bearer(token: string): CoffreClient {
  return createClient({ url: ORIGIN, headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }) });
}

/** Every entry a list shows, page after page of `limit`, as a client of this release pages it, by `next`. */
async function every(client: CoffreClient, query: { actor?: string; path?: string; detail?: string; decision?: string } = {}, limit = 500): Promise<AuditEntryView[]> {
  const all: AuditEntryView[] = [];
  for (let before: string | undefined; ;) {
    const { entries, next } = await client.audit.list({ ...query, sealed: '1', limit, ...(before === undefined ? {} : { before }) } as Parameters<CoffreClient['audit']['list']>[0]);
    all.push(...entries);
    if (next === null) return all;
    before = next;
  }
}

/** The reads a list shows, as `who key version purpose log`. */
const reads = (entries: AuditEntryView[]) => entries.filter((entry) => entry.action === 'secret.read' && entry.decision === 'allow')
  .map((entry) => `${entry.actorId} ${entry.project}/${entry.environment}/${entry.key} v${entry.version} ${String(entry.metadata.purpose)} ${entry.log}`);

test('a read is on every list that would have shown its 0.14 entry: the whole log, its member, its key, environment and project, with its version and token', async () => {
  assert.equal((await ada.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'dev-key');
  await root.secrets.set('market/dev', { API_KEY: 'dev-key-2' });
  assert.equal((await ada.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'dev-key-2');
  if (LOG === '0.15') assert.equal((await usesLogged(db.owner)).length, 2, 'each read is a use');

  const expected = [`ada@acme.example market/dev/API_KEY v2 reveal ${LOG}`, `ada@acme.example market/dev/API_KEY v1 reveal ${LOG}`];
  for (const query of [{}, { actor: ADA }, { actor: 'ada@acme.example' }, { path: 'market/dev/API_KEY' }, { path: 'market/dev' }, { path: 'market' }]) {
    assert.deepEqual(reads(await every(root, query)), expected, JSON.stringify(query));
  }
  for (const query of [{ path: 'market/prod' }, { path: 'market/dev/OTHER' }, { actor: BOB }, { decision: 'deny' }]) {
    assert.deepEqual(reads(await every(root, query)), [], JSON.stringify(query));
  }
  const [newest] = (await every(root, { actor: ADA })).filter((entry) => entry.action === 'secret.read');
  assert.equal(newest!.author, 'vault');
  assert.equal(newest!.forged, undefined);
  assert.deepEqual(newest!.token, adaToken, "the token's label, beside the read it made");
  assert.equal(newest!.metadata.credentialId, adaToken.id);
  // A client older than 0.15 pages 0.14's log alone, by seq: under 0.15's log it lists no use.
  const old = (await root.audit.list({ limit: 500 })).entries;
  assert.deepEqual(reads(old), LOG === '0.15' ? [] : expected);
});

test('a reader of some places sees the reads there and nowhere else, and none in an environment their role leaves out', async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  const admin = bearer((await root.tokens.issue(`user:${ROOT}`, { label: 'reader', expiresInMinutes: 60, scope: { market: 'viewer' } })).token);
  await admin.secrets.reveal('market/prod/OTHER');
  // Bob audits dev alone; then market, but for prod, which is protected and whose log an Auditor's role leaves out.
  await root.members.add(BOB, { role: 'member' });
  const bob = clientFor(deps, 'bob@acme.example');
  await root.access.set(BOB, { 'market/dev': 'auditor' });
  assert.deepEqual(reads(await every(bob)), [`ada@acme.example market/dev/API_KEY v1 reveal ${LOG}`]);
  assert.deepEqual(reads(await every(bob, { path: 'market/prod' })), []);
  await root.access.set(BOB, { market: 'auditor' });
  assert.deepEqual(reads(await every(bob)), [`${ROOT} market/prod/OTHER v1 reveal ${LOG}`, `ada@acme.example market/dev/API_KEY v1 reveal ${LOG}`]);
  // An Auditor whose role leaves protected environments' logs out, and prod protected: market's log, but for prod.
  await root.roles.set('auditor', { name: 'Auditor', description: '', permissions: ['audit.read'], protected: [] });
  await root.environments.update('market/prod', { protected: true });
  assert.deepEqual(reads(await every(bob)), [`ada@acme.example market/dev/API_KEY v1 reveal ${LOG}`], 'a protected environment whose log the role leaves out');
  assert.deepEqual(reads(await every(bob, { actor: ADA })), reads(await every(bob)), 'by member, the same places');
  assert.deepEqual(reads(await every(bob, { actor: `user:${ROOT}` })), [], "by member, none of the places left out");
  assert.deepEqual(reads(await every(bob, { path: 'market' })), reads(await every(bob)), 'by path, the same places');
});

test('a read through a reference is in its source\'s log and its holder\'s, of the source\'s version; one in a fork, in the fork\'s and its parent\'s', async () => {
  await root.secrets.set('market/prod', { SOURCE: 'prod-source' });
  await root.secrets.set('market/prod', { SOURCE: 'prod-source-2' });
  await root.secrets.set('market/dev', { HELD: { ref: 'market/prod/SOURCE' } });
  assert.equal((await ada.secrets.reveal('market/dev/HELD')).values.HELD, 'prod-source-2');
  for (const path of ['market/prod', 'market/prod/SOURCE', 'market/dev', 'market/dev/HELD']) {
    const shown = (await every(root, { path })).filter((entry) => entry.action === 'secret.read' && entry.decision === 'allow' && entry.metadata.via !== undefined);
    assert.equal(shown.length, 1, path);
    const [read] = shown as [AuditEntryView];
    // Filed as 0.14 filed it: at the source, the reference's holder beside it.
    assert.deepEqual([read.project, read.environment, read.key, read.version, (read.metadata.via as { path?: unknown }).path], ['market', 'prod', 'SOURCE', 2, 'market/dev/HELD'], path);
  }
  assert.deepEqual(reads(await every(root, { path: 'market/prod/API_KEY' })), []);

  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.access.set(ADA, { 'market/dev-eu': 'developer' });
  const fork = bearer((await clientFor(deps, 'ada@acme.example').tokens.issue(ADA, { label: 'fork', expiresInMinutes: 60, scope: { 'market/dev': 'viewer', 'market/dev-eu': 'viewer' } })).token);
  assert.equal((await fork.secrets.reveal('market/dev-eu/OTHER')).values.OTHER, 'dev-other');
  for (const path of ['market/dev-eu', 'market/dev', 'market/dev/OTHER']) {
    const shown = (await every(root, { path })).filter((entry) => entry.action === 'secret.read' && entry.key === 'OTHER');
    assert.equal(shown.length, 1, path);
    assert.deepEqual([shown[0]!.environment, (shown[0]!.metadata.through as { slug?: unknown }).slug], ['dev', 'dev-eu'], path);
  }
  assert.deepEqual((await every(root, { path: 'market/prod' })).filter((entry) => entry.key === 'OTHER' && entry.action === 'secret.read'), []);
});

test('pages tile the reads with every other entry: each once, newest first, whatever the page size', async () => {
  for (let i = 0; i < 4; i++) {
    await ada.secrets.reveal('market/dev/API_KEY');
    await ada.secrets.reveal('market/dev/OTHER');
    await root.secrets.set('market/prod', { API_KEY: `prod-${i}` });
  }
  const whole = await every(root, { detail: '1' });
  assert.ok(whole.filter((entry) => entry.action === 'secret.read').length >= 2);
  const key = (entry: AuditEntryView) => `${entry.log}:${entry.seq}`;
  for (const limit of [1, 2, 3, 7]) {
    for (const query of [{ detail: '1' }, {}, { actor: ADA }, { path: 'market/dev' }]) {
      const paged = await every(root, query, limit);
      const all = await every(root, query);
      assert.deepEqual(paged.map(key), all.map(key), `${limit} ${JSON.stringify(query)}`);
      assert.equal(new Set(paged.map(key)).size, paged.length);
      assert.ok(paged.every((entry, i) => i === 0 || Date.parse(entry.occurredAt) <= Date.parse(paged[i - 1]!.occurredAt)), 'newest first');
    }
  }
});

test('a use the vault does not vouch for is shown as forged: a row edited, or written, around coffre', { skip: LOG !== '0.15' }, async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  await ada.secrets.reveal('market/dev/OTHER');
  const before = (await every(root)).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(before.map((entry) => entry.forged), [undefined, undefined]);
  // Whoever owns the database says the read was of another key, and writes one nobody made.
  const [first] = before.slice(-1) as [AuditEntryView];
  const other = before[0]!.metadata.secretId as string;
  await db.owner.update(logUses).set({ secret: other }).where(eq(logUses.number, BigInt(first.seq)));
  const after = (await every(root)).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(after.map((entry) => [entry.key, entry.forged]), [['OTHER', undefined], ['OTHER', true]]);
});

test('the offboarding report names what someone read under either log, current until a new version is written', async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  const report = await root.members.get(ADA);
  assert.deepEqual(report.exposed.map((entry) => `${entry.project}/${entry.environment}/${entry.key}`), ['market/dev/API_KEY']);
  await root.secrets.set('market/dev', { API_KEY: 'rotated' });
  const rotated = await root.members.get(ADA);
  assert.deepEqual([rotated.exposed.length, rotated.rotated], [0, 1]);
});

test("a reference's reads are its source's only while it read that source, by member too (review r1)", { skip: LOG !== '0.15' }, async () => {
  await root.environments.create('market/stage', { name: 'stage' });
  await root.secrets.set('market/prod', { SOURCE: 'prod-source' });
  await root.secrets.set('market/stage', { OTHER_SOURCE: 'stage-source' });
  await root.secrets.set('market/dev', { HELD: { ref: 'market/prod/SOURCE' } });
  // Bob audits prod alone; the holder then reads stage's key instead.
  await root.members.add(BOB, { role: 'member' });
  await root.access.set(BOB, { 'market/prod': 'auditor' });
  const bob = clientFor(deps, 'bob@acme.example');
  await root.secrets.set('market/dev', { HELD: { ref: 'market/stage/OTHER_SOURCE' } });
  // The reference to prod lived two hours ago, ending twenty minutes ago; a read through it then, and one now through
  // the reference to stage, each a use of the holder's.
  await db.owner.update(secretReferences).set({ createdAt: new Date(Date.now() - 2 * 3_600_000), endedAt: new Date(Date.now() - 20 * 60_000) })
    .where(eq(secretReferences.sourceSecretId, (await db.owner.select({ id: secrets.id }).from(secrets).where(eq(secrets.key, 'SOURCE')))[0]!.id));
  assert.equal((await ada.secrets.reveal('market/dev/HELD')).values.HELD, 'stage-source');
  // Ada's token, as old as the reads planted through it.
  await db.owner.update(credentials).set({ createdAt: new Date(Date.now() - 3 * 3_600_000) }).where(eq(credentials.id, adaToken.id));
  const [now] = await db.owner.select().from(logUses).orderBy(desc(logUses.number)).limit(1);
  await db.owner.insert(logUses).values({ ...now!, number: now!.number + 1000n, at: Date.now() - 30 * 60_000, requestId: now!.requestId + 1n });
  for (const query of [{}, { actor: ADA }]) {
    const shown = (await every(bob, query)).filter((entry) => entry.action === 'secret.read');
    assert.deepEqual(shown.map((entry) => entry.seq), [Number(now!.number) + 1000], JSON.stringify(query));
  }
});

test("a use whose version was read from a change the vault does not vouch for is shown forged (review r1)", { skip: LOG !== '0.15' }, async () => {
  await root.secrets.set('market/dev', { API_KEY: 'dev-key-2' });
  await ada.secrets.reveal('market/dev/API_KEY');
  const [read] = (await every(root, { actor: ADA })).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual([read!.version, read!.forged], [2, undefined]);
  // Whoever owns the database points the key's newest change at its first version.
  const versions = await db.owner.select({ id: secretVersions.id, version: secretVersions.version }).from(secretVersions)
    .where(eq(secretVersions.secretId, read!.metadata.secretId as string));
  const [first, second] = [versions.find((v) => v.version === 1)!, versions.find((v) => v.version === 2)!];
  const object = logObject('secret', read!.metadata.secretId as string);
  const [change] = await db.owner.select().from(logChanges).where(eq(logChanges.object, object)).orderBy(desc(logChanges.number)).limit(1);
  await db.owner.update(logChanges).set({ payload: change!.payload.replace(second!.id, first!.id) }).where(eq(logChanges.number, change!.number));
  const [after] = (await every(root, { actor: ADA })).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual([after!.version, after!.forged], [1, true]);
});

test('the offboarding report names every source a reference read while they read through it (review r1)', { skip: LOG !== '0.15' }, async () => {
  await root.secrets.set('market/dev', { A: 'a', B: 'b', C: 'c' });
  for (const source of ['A', 'B', 'C']) {
    await root.secrets.set('market/dev', { HELD: { ref: `market/dev/${source}` } });
    assert.equal((await ada.secrets.reveal('market/dev/HELD')).values.HELD, source.toLowerCase());
  }
  const report = await root.members.get(ADA);
  assert.deepEqual(report.exposed.map((entry) => entry.key).sort(), ['A', 'B', 'C']);
});
