// Reads on every audit list (T166). With 0.15's log a read writes no 0.14
// `secret.read` entry: its use is the record (R53), which the vault's
// projector lists once a pair seals it (`log_reads`), and the audit lists show
// each where that entry stood, with who read what, which version, for what
// and through what, at the places and by the members the list asks for, every
// one vouched for by the vault. Here a checkpointer seals and the projector
// lists at `settle()`. Under 0.14's log the same lists show its own entries:
// each test holds both.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';

import { createClient, type AuditEntryView, type CoffreClient } from '@coffre/client';
import { defineSignin, github } from '@coffre/core/identity';
import { tablesOf } from '@coffre/db';
import { derivedSigningKey } from '@coffre/vault';
import { runCheckpointer, type RunningCheckpointer } from '@coffre/vault/node';
import { and, desc, eq } from 'drizzle-orm';

import { READS_BEHIND_MS, readsListed } from '../src/api/audit.ts';
import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { logReadDays, logReads, logReadsCursor, logUses, secrets } from './db/tables.ts';
import { clientFor, LOG, openTestDatabase, resetDatabase, testDeps, testVault, usesLogged, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { openVaultDatabase } from './db/engine.ts';

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

const scratch = mkdtempSync(join(tmpdir(), 'coffre-reads-'));
/** Under 0.15's log, the checkpointer that seals every change, and whose projector lists the reads. */
let signer: RunningCheckpointer | null = null;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await signer?.stop();
  await db.close();
  rmSync(scratch, { recursive: true, force: true });
});

/** What a page lists of 0.15's reads once the log seals them and the projector has gone that far: a tick, then the projector. */
async function settle(): Promise<void> {
  if (signer === null) return;
  await signer.checkpointer.tick();
  await signer.projected();
}

beforeEach(async () => {
  await signer?.stop();
  signer = null;
  await resetDatabase(db.owner);
  if (LOG === '0.15') {
    const { logUses, logBulk, logCheckpoints, logTiles } = tablesOf(db.owner);
    for (const table of [logUses, logBulk, logCheckpoints, logTiles]) await db.owner.delete(table);
    const kek = randomBytes(32);
    signer = await runCheckpointer({ database: await openVaultDatabase(), seed: derivedSigningKey(kek), memory: join(scratch, `memory-${Date.now()}`), intervalMs: 3_600_000 });
    const vault = testVault([ROOT], {}, { kek }, {}, { log: '0.15', sealThrough: signer.sealThrough, heldOutside: signer.heldOutside });
    deps = testDeps(db.runtime, [ROOT], { vault });
  } else {
    deps = testDeps(db.runtime, [ROOT]);
  }
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
  await settle();
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

test("a read is on the whole log and its member's page, with its version and token; under 0.14's log on its key's, environment's and project's too, which in 0.15 say where reads are (D160)", async () => {
  assert.equal((await ada.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'dev-key');
  await root.secrets.set('market/dev', { API_KEY: 'dev-key-2' });
  assert.equal((await ada.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'dev-key-2');
  if (LOG === '0.15') assert.equal((await usesLogged(db.owner)).length, 2, 'each read is a use');

  const expected = [`ada@acme.example market/dev/API_KEY v2 reveal ${LOG}`, `ada@acme.example market/dev/API_KEY v1 reveal ${LOG}`];
  for (const query of [{}, { actor: ADA }, { actor: 'ada@acme.example' }]) {
    assert.deepEqual(reads(await every(root, query)), expected, JSON.stringify(query));
  }
  for (const path of ['market/dev/API_KEY', 'market/dev', 'market']) {
    assert.deepEqual(reads(await every(root, { path })), LOG === '0.15' ? [] : expected, path);
    const page = await root.audit.list({ path, sealed: '1', limit: 10 });
    assert.deepEqual([page.readsOmitted, page.reads], LOG === '0.15' ? ['path', undefined] : [undefined, undefined], path);
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

test("under 0.14's log, a reader of some places sees the reads there and nowhere else, and none in an environment their role leaves out", { skip: LOG !== '0.14' }, async () => {
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

test("under 0.15's log, a reader of some places sees no one's reads but their own, on their own page, and every page says so (D160)", { skip: LOG !== '0.15' }, async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  // Bob owns market: he audits it and reads its values, but not the whole log.
  await root.members.add(BOB, { role: 'member' });
  await root.access.set(BOB, { market: 'owner' });
  const bob = clientFor(deps, 'bob@acme.example');
  const bobs = bearer((await bob.tokens.issue(BOB, { label: 'bob', expiresInMinutes: 60, scope: { market: 'viewer' } })).token);
  await bobs.secrets.reveal('market/prod/OTHER');
  assert.deepEqual(reads(await every(bob, { actor: BOB })), [`bob@acme.example market/prod/OTHER v1 reveal ${LOG}`], 'his own reads');
  // However he names himself, and only his (review r6): `bob@acme.example` asks for `token:bob@acme.example` too.
  assert.deepEqual(reads(await every(bob, { actor: 'bob@acme.example' })), [`bob@acme.example market/prod/OTHER v1 reveal ${LOG}`], 'named bare');
  for (const query of [{}, { actor: ADA }, { path: 'market' }, { path: 'market/dev/API_KEY' }]) {
    assert.deepEqual(reads(await every(bob, query)), [], JSON.stringify(query));
    const page = await bob.audit.list({ ...query, sealed: '1', limit: 10 });
    assert.equal(page.readsOmitted, 'path' in query ? 'path' : 'scope', JSON.stringify(query));
  }
  // The whole log's reader sees both.
  assert.deepEqual(reads(await every(root)), [`bob@acme.example market/prod/OTHER v1 reveal ${LOG}`, `ada@acme.example market/dev/API_KEY v1 reveal ${LOG}`]);
});

test("a read through a reference is filed at its source, of the source's version, its holder beside it; one in a fork, at its key, the fork beside it", async () => {
  await root.secrets.set('market/prod', { SOURCE: 'prod-source' });
  await root.secrets.set('market/prod', { SOURCE: 'prod-source-2' });
  await root.secrets.set('market/dev', { HELD: { ref: 'market/prod/SOURCE' } });
  assert.equal((await ada.secrets.reveal('market/dev/HELD')).values.HELD, 'prod-source-2');
  // On the whole log and the member's page; under 0.14's log on each place's too.
  const pages = (paths: string[]) => [{}, { actor: ADA }, ...(LOG === '0.14' ? paths.map((path) => ({ path })) : [])];
  for (const query of pages(['market/prod', 'market/prod/SOURCE', 'market/dev', 'market/dev/HELD'])) {
    const shown = (await every(root, query)).filter((entry) => entry.action === 'secret.read' && entry.decision === 'allow' && entry.metadata.via !== undefined);
    assert.equal(shown.length, 1, JSON.stringify(query));
    const [read] = shown as [AuditEntryView];
    // Filed as 0.14 filed it: at the source, the reference's holder beside it.
    assert.deepEqual([read.project, read.environment, read.key, read.version, (read.metadata.via as { path?: unknown }).path], ['market', 'prod', 'SOURCE', 2, 'market/dev/HELD'], JSON.stringify(query));
  }

  await root.environments.create('market/dev-eu', { from: 'dev', inherit: true });
  await root.access.set(ADA, { 'market/dev-eu': 'developer' });
  const fork = bearer((await clientFor(deps, 'ada@acme.example').tokens.issue(ADA, { label: 'fork', expiresInMinutes: 60, scope: { 'market/dev': 'viewer', 'market/dev-eu': 'viewer' } })).token);
  assert.equal((await fork.secrets.reveal('market/dev-eu/OTHER')).values.OTHER, 'dev-other');
  for (const query of pages(['market/dev-eu', 'market/dev', 'market/dev/OTHER'])) {
    const shown = (await every(root, query)).filter((entry) => entry.action === 'secret.read' && entry.key === 'OTHER');
    assert.equal(shown.length, 1, JSON.stringify(query));
    assert.deepEqual([shown[0]!.environment, (shown[0]!.metadata.through as { slug?: unknown }).slug], ['dev', 'dev-eu'], JSON.stringify(query));
  }
});

test('a read through a reference within one environment is listed once (review r3)', async () => {
  await root.secrets.set('market/dev', { HELD: { ref: 'market/dev/API_KEY' } });
  assert.equal((await ada.secrets.reveal('market/dev/HELD')).values.HELD, 'dev-key');
  for (const query of [{}, { actor: ADA }]) {
    const shown = (await every(root, query)).filter((entry) => entry.action === 'secret.read' && entry.metadata.via !== undefined);
    assert.equal(shown.length, 1, JSON.stringify(query));
  }
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

test('a read the vault does not vouch for is shown forged: edited, renumbered, or written around coffre; a cursor moved on, said', { skip: LOG !== '0.15' }, async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  await ada.secrets.reveal('market/dev/OTHER');
  const before = (await every(root)).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(before.map((entry) => [entry.key, entry.forged]), [['OTHER', undefined], ['API_KEY', undefined]]);
  // Whoever owns the database says the first read was of another key, and moves the second to another number.
  const [second, first] = before as [AuditEntryView, AuditEntryView];
  await db.owner.update(logReads).set({ secret: second.metadata.secretId as string }).where(eq(logReads.number, BigInt(first.seq)));
  await db.owner.update(logReads).set({ number: BigInt(second.seq) + 1000n }).where(eq(logReads.number, BigInt(second.seq)));
  const after = (await every(root)).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(after.map((entry) => [entry.key, entry.forged]), [['OTHER', true], ['OTHER', true]]);
  // And moves the cursor on: the page says it cannot vouch for how far reads are listed.
  await db.owner.update(logReadsCursor).set({ through: 1_000_000n });
  const { reads } = await root.audit.list({ sealed: '1', limit: 10 });
  assert.deepEqual([reads?.forged, reads?.behind], [true, true]);
  // Or deletes it: no page, report or check takes that for a projection yet to start (review r6).
  await db.owner.delete(logReadsCursor);
  const gone = await root.audit.list({ sealed: '1', limit: 10 });
  assert.deepEqual([gone.reads?.forged, gone.reads?.behind], [true, true]);
  const report = await root.members.get(ADA);
  assert.deepEqual([report.reads?.forged, report.reads?.behind], [true, true]);
  const verdict = await root.audit.verifyReads();
  assert.ok(verdict.kept);
  assert.deepEqual([verdict.ok, verdict.problems], [false, ["the reads' cursor is gone: a database writer deleted it"]]);
});

test("the whole log's check holds the reads listed to the uses sealed: one deleted, edited, given to another member or listed twice, each named", { skip: LOG !== '0.15' }, async () => {
  await root.secrets.set('market/prod', { SOURCE: 'prod-source' });
  await root.secrets.set('market/dev', { HELD: { ref: 'market/prod/SOURCE' }, THIRD: 'third', FOURTH: 'fourth' });
  // Five reads, each sealed by a pair of its own, so that the check goes a stretch for each.
  for (const key of ['API_KEY', 'OTHER', 'HELD', 'THIRD', 'FOURTH']) {
    await ada.secrets.reveal(`market/dev/${key}`);
    await settle();
  }
  const sealed = await root.audit.verifyReads();
  assert.ok(sealed.kept && sealed.ok, JSON.stringify(sealed));
  const numbers = (await db.owner.select({ number: logReads.number }).from(logReads).orderBy(logReads.number)).map((row) => row.number);
  assert.equal(numbers.length, 5);
  const [deleted, edited, , moved, copied] = numbers as [bigint, bigint, bigint, bigint, bigint];
  // Whoever owns the database deletes a read; edits another; says a fourth was Bob's, off Ada's page and the offboarding
  // report; and lists the last twice, a moment apart. A read planted at a time no use of the log's sealed near, or under
  // a number none did, every page shows forged, by its MAC (above).
  await db.owner.delete(logReads).where(eq(logReads.number, deleted));
  await db.owner.update(logReads).set({ credential: randomUUID() }).where(eq(logReads.number, edited));
  await db.owner.update(logReads).set({ principal: BOB }).where(eq(logReads.number, moved));
  const [copy] = await db.owner.select().from(logReads).where(eq(logReads.number, copied));
  await db.owner.insert(logReads).values({ ...copy!, at: copy!.at + 1 });
  const verdict = await root.audit.verifyReads();
  assert.ok(verdict.kept && !verdict.ok);
  // The client stops at the first stretch that fails, the deleted read's; the vault's stretches go on past each.
  assert.deepEqual(verdict.problems, [`read ${deleted} is sealed but not listed`]);
  const named: string[] = [];
  for (let from = 'start'; ;) {
    const stretch = await deps.vault.verifyReads!({ from });
    assert.ok(stretch.kept);
    named.push(...stretch.problems);
    if (stretch.next === null) break;
    from = stretch.next;
  }
  for (const problem of [
    `read ${deleted} is sealed but not listed`,
    `read ${edited} is listed otherwise than the log sealed it`,
    `read ${moved} is listed otherwise than the log sealed it`,
    `read ${copied} is listed twice`,
  ]) assert.ok(named.includes(problem), `${problem}, among ${JSON.stringify(named)}`);
});

test("a member's day of reads deleted takes them off her report, and the whole log's check names each (review r6)", { skip: LOG !== '0.15' }, async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  await settle();
  const [listed] = await db.owner.select({ number: logReads.number }).from(logReads);
  assert.deepEqual((await root.members.get(ADA)).exposed.map((secret) => secret.key), ['API_KEY']);
  await db.owner.delete(logReadDays).where(eq(logReadDays.principal, ADA));
  // Her report reads her days alone (as her page does on Postgres, whose days are partitions).
  assert.deepEqual((await root.members.get(ADA)).exposed, []);
  const verdict = await root.audit.verifyReads();
  assert.ok(verdict.kept);
  assert.deepEqual([verdict.ok, verdict.problems], [false, [`read ${listed!.number} is off its member's pages: their day of it is not listed`]]);
});

test("a use renumbered after its seal stops the projection, which lists nothing it would derive from it, and the whole log's check says why (WindowChecked)", { skip: LOG !== '0.15' }, async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  await ada.secrets.reveal('market/dev/OTHER');
  await signer!.checkpointer.tick();
  // Whoever owns the database swaps the two sealed uses' numbers, which neither use's MAC covers.
  const [first, second] = (await db.owner.select({ number: logUses.number }).from(logUses).orderBy(logUses.number)).map((row) => row.number) as [bigint, bigint];
  for (const [from, to] of [[first, -1n], [second, first], [-1n, second]] as const) await db.owner.update(logUses).set({ number: to }).where(eq(logUses.number, from));
  await assert.rejects(signer!.projected(), /did not catch up/);
  assert.match((await signer!.alarms()).map((alarm) => alarm.message).join('\n'), /does not hold to the pair that sealed it/);
  const { entries } = await root.audit.list({ sealed: '1', limit: 50 });
  assert.equal(entries.filter((entry) => entry.action === 'secret.read').length, 0);
  const verdict = await root.audit.verifyReads();
  assert.ok(verdict.kept && !verdict.ok && /does not hold to the pair that sealed it/.test(verdict.problems.join()), JSON.stringify(verdict));
});

test("a read waits to be listed until the projector writes it, and the page says how far it lists", { skip: LOG !== '0.15' }, async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  // Sealed, not yet projected: not listed, and the page lists reads through nothing yet.
  await signer!.checkpointer.tick();
  const waiting = await root.audit.list({ sealed: '1', limit: 50 });
  assert.equal(waiting.entries.filter((entry) => entry.action === 'secret.read').length, 0);
  assert.equal(waiting.reads?.through, null);
  // Her report names nothing to rotate yet, and says it is behind, at once: an offboarding never reads it as all there is
  // (review r4); the removed members' counts the same.
  const report = await root.members.get(ADA);
  assert.deepEqual([report.exposed.length, report.reads?.behind], [0, true]);
  await signer!.projected();
  const listed = await root.audit.list({ sealed: '1', limit: 50 });
  assert.equal(listed.entries.filter((entry) => entry.action === 'secret.read').length, 1);
  assert.deepEqual([typeof listed.reads?.through, listed.reads?.behind, listed.reads?.forged], ['string', false, undefined]);
  const after = await root.members.get(ADA);
  assert.deepEqual([after.exposed.map((secret) => secret.key), after.reads?.behind], [['API_KEY'], false]);
});

test("a listing stopped behind its newest pair says so once that pair is a few seconds old, with no pair after it (review r4)", () => {
  const standing = (through: bigint, sealedAt: number, at: number) => ({ through, pair: through, at, mac: null, sealed: 10n, sealedAt, missing: false });
  const now = Date.now();
  // The newest pair signed a second after the listing's, and nothing signed since: behind once it is old, not before.
  assert.equal(readsListed(standing(8n, now - 1000, now - 2000), false)?.behind, false);
  assert.equal(readsListed(standing(8n, now - READS_BEHIND_MS - 1000, now - READS_BEHIND_MS - 2000), false)?.behind, true);
  // All listed: never behind; strict, as a report is: behind as soon as one waits.
  assert.equal(readsListed(standing(10n, now - 60_000, now - 60_000), false)?.behind, false);
  assert.equal(readsListed(standing(8n, now - 100, now - 200), false, { strict: true })?.behind, true);
  // No pair at all: 0.14's log alone, no listing to speak of.
  assert.equal(readsListed({ ...standing(0n, 0, 0), sealed: null, sealedAt: null }, false), null);
  // The cursor's row gone: forged, behind, whatever it would have said (review r6).
  assert.deepEqual(readsListed({ ...standing(10n, now, now), missing: true }, false), { through: new Date(now).toISOString(), behind: true, forged: true });
});

test('the offboarding report names what someone read under either log, current until a new version is written', async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  await settle();
  const report = await root.members.get(ADA);
  assert.deepEqual(report.exposed.map((entry) => `${entry.project}/${entry.environment}/${entry.key}`), ['market/dev/API_KEY']);
  await root.secrets.set('market/dev', { API_KEY: 'rotated' });
  const rotated = await root.members.get(ADA);
  assert.deepEqual([rotated.exposed.length, rotated.rotated], [0, 1]);
});

test("a reference's read is its source's then: repointed, its earlier read stays at the old source and its later is at the new; under 0.14's log, on each source's page too", async () => {
  await root.environments.create('market/stage', { name: 'stage' });
  await root.secrets.set('market/prod', { SOURCE: 'prod-source' });
  await root.secrets.set('market/stage', { OTHER_SOURCE: 'stage-source' });
  await root.secrets.set('market/dev', { HELD: { ref: 'market/prod/SOURCE' } });
  const reader = bearer((await root.tokens.issue(`user:${ROOT}`, { label: 'reader', expiresInMinutes: 60, scope: { market: 'viewer' } })).token);
  assert.equal((await reader.secrets.reveal('market/dev/HELD')).values.HELD, 'prod-source');
  await root.secrets.set('market/dev', { HELD: { ref: 'market/stage/OTHER_SOURCE' } });
  assert.equal((await reader.secrets.reveal('market/dev/HELD')).values.HELD, 'stage-source');
  const held = (entries: AuditEntryView[]) => entries.filter((entry) => entry.action === 'secret.read' && (entry.metadata.via as { path?: unknown } | undefined)?.path === 'market/dev/HELD')
    .map((entry) => `${entry.project}/${entry.environment}/${entry.key}`);
  for (const query of [{}, { actor: `user:${ROOT}` }]) assert.deepEqual(held(await every(root, query)), ['market/stage/OTHER_SOURCE', 'market/prod/SOURCE'], JSON.stringify(query));
  if (LOG === '0.14') {
    // Bob audits prod alone: its log names the earlier read alone.
    await root.members.add(BOB, { role: 'member' });
    await root.access.set(BOB, { 'market/prod': 'auditor' });
    const bob = clientFor(deps, 'bob@acme.example');
    for (const query of [{}, { actor: `user:${ROOT}` }, { path: 'market/prod' }, { path: 'market/prod/SOURCE' }]) {
      assert.deepEqual(held(await every(bob, query)), ['market/prod/SOURCE'], JSON.stringify(query));
    }
  }
});

test('the offboarding report names every source a reference read while they read through it', async () => {
  await root.secrets.set('market/dev', { A: 'a', B: 'b', C: 'c' });
  for (const source of ['A', 'B', 'C']) {
    await root.secrets.set('market/dev', { HELD: { ref: `market/dev/${source}` } });
    assert.equal((await ada.secrets.reveal('market/dev/HELD')).values.HELD, source.toLowerCase());
  }
  await settle();
  const report = await root.members.get(ADA);
  assert.deepEqual(report.exposed.map((entry) => entry.key).sort(), ['A', 'B', 'C']);
});
