// Reads on every audit list. A read writes no 0.14 `secret.read`
// entry: its use is the record, which the vault's projector lists once a
// pair seals it (`audit_events`), and the audit lists show each where that
// entry stood, with who read what, which version, for what and through what,
// at the places and by the members the list asks for, every one vouched for by
// the vault. Here a checkpointer seals and the projector lists at `settle()`.
import { defineDeployment } from '@coffre/core/deployment';
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';

import { createClient, type AuditEntryView, type CoffreClient } from '@coffre/client';
import { defineSignin, github } from '@coffre/core/identity';
import { derivedSigningKey } from '@coffre/vault';
import { runCheckpointer, type RunningCheckpointer } from '@coffre/vault/node';
import { and, desc, eq, sql } from 'drizzle-orm';

import { READS_BEHIND_MS, readsListed, readsReported } from '../src/api/audit.ts';
import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { logObject } from '@coffre/db/log';
import { auditCursor, auditEventPlaces, auditEvents, auditMemberKeys, bulkCap, logChanges, logCheckpoints, logTiles, logUses, secrets } from '@coffre/db/schema';
import { clientFor, listAudit, openTestDatabase, resetDatabase, testDeps, testVault, usesLogged, waitUntil, type FixtureDeps } from './api-fixture.ts';
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

/** What a page lists once the log seals it and the projector has gone that far (`listAudit`). */
async function settle(): Promise<void> {
  if (signer !== null) await listAudit(deps.vault, signer);
}

beforeEach(async () => {
  await signer?.stop();
  signer = null;
  await resetDatabase(db.owner);
  for (const table of [logUses, bulkCap, logCheckpoints, logTiles]) await db.owner.delete(table);
  const kek = randomBytes(32);
  signer = await runCheckpointer({ database: await openVaultDatabase(), signingKeys: [derivedSigningKey(kek)], memory: join(scratch, `memory-${Date.now()}`), intervalMs: 3_600_000 });
  const vault = testVault([ROOT], {}, { kek }, {}, { sealThrough: signer.sealThrough, heldOutside: signer.heldOutside });
  deps = testDeps(db.runtime, [ROOT], { vault, settleAudit: false });
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: SIGNIN });
  deps.signin = signin;
  runtime = {
    db: deps.db, vault: deps.vault, chainKey: deps.chainKey, previousChainKeys: [], signin, workloads: null, mcp: null,
    auth: { mode: 'signin', signin: SIGNIN }, publicUrl: ORIGIN, verifier: signin, waitUntil,
    schema: { migrated: true }, appKey: { settled: true }, rotateAfterDays: 365, deployment: defineDeployment(), plugins: [],
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
    const { entries, next } = await client.audit.list({ ...query, limit, ...(before === undefined ? {} : { before }) } as Parameters<CoffreClient['audit']['list']>[0]);
    all.push(...entries);
    if (next === null) return all;
    before = next;
  }
}

/** The reads a list shows, as `who key version purpose log`. */
const reads = (entries: AuditEntryView[]) => entries.filter((entry) => entry.action === 'secret.read' && entry.decision === 'allow')
  .map((entry) => `${entry.actorId} ${entry.project}/${entry.environment}/${entry.key} v${entry.version} ${String(entry.metadata.purpose)} ${entry.log}`);

test("a read is on the whole log, its member's page, and its key's, environment's and project's, with its version and token (T175)", async () => {
  assert.equal((await ada.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'dev-key');
  await root.secrets.set('market/dev', { API_KEY: 'dev-key-2' });
  assert.equal((await ada.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'dev-key-2');
  assert.equal((await usesLogged(db.owner)).length, 2, 'each read is a use');

  const expected = [`ada@acme.example market/dev/API_KEY v2 reveal 0.15`, `ada@acme.example market/dev/API_KEY v1 reveal 0.15`];
  for (const query of [{}, { actor: ADA }, { actor: 'ada@acme.example' }, { path: 'market/dev/API_KEY', actor: ADA }]) {
    assert.deepEqual(reads(await every(root, query)), expected, JSON.stringify(query));
  }
  for (const path of ['market/dev/API_KEY', 'market/dev', 'market']) {
    assert.deepEqual(reads(await every(root, { path })), expected, path);
    const page = await root.audit.list({ path, limit: 10 });
    assert.deepEqual([page.reads?.behind, page.reads?.forged], [false, undefined], path);
  }
  for (const query of [{ path: 'market/prod' }, { path: 'market/dev/OTHER' }, { actor: BOB }, { path: 'market/dev', actor: BOB }, { decision: 'deny' }]) {
    assert.deepEqual(reads(await every(root, query)), [], JSON.stringify(query));
  }
  const [newest] = (await every(root, { actor: ADA })).filter((entry) => entry.action === 'secret.read');
  assert.equal(newest!.author, 'vault');
  assert.equal(newest!.forged, undefined);
  assert.deepEqual(newest!.token, adaToken, "the token's label, beside the read it made");
  assert.equal(newest!.metadata.credentialId, adaToken.id);
  // A client older than 0.15, which sends no `sealed`: the same list (0.16 lists every log on every page).
  const old = (await root.audit.list({ limit: 500 })).entries;
  assert.deepEqual(reads(old), expected);
});

test("a reader of some places sees on a place's page the reads at places they read, none at an environment their role leaves out, through a reference or in a fork alike (T175)", async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  const admin = bearer((await root.tokens.issue(`user:${ROOT}`, { label: 'reader', expiresInMinutes: 60, scope: { market: 'viewer' } })).token);
  await admin.secrets.reveal('market/prod/OTHER');
  // And in prod-eu, a fork of prod made before prod is protected, which stays unprotected: a read of prod's key there.
  await root.environments.create('market/prod-eu', { from: 'prod', inherit: true });
  await admin.secrets.reveal('market/prod-eu/OTHER');
  // Bob audits dev alone: its pages, and market's but for what is at prod.
  await root.members.add(BOB, { role: 'member' });
  const bob = clientFor(deps, 'bob@acme.example');
  await root.access.set(BOB, { 'market/dev': 'auditor' });
  const adaDev = `ada@acme.example market/dev/API_KEY v1 reveal 0.15`;
  const rootProd = `${ROOT} market/prod/OTHER v1 reveal 0.15`;
  for (const [path, shown] of [
    ['market/dev', [adaDev]], ['market/dev/API_KEY', [adaDev]], ['market', [adaDev]], ['market/prod', []], ['market/prod/OTHER', []], ['market/prod-eu', []],
  ] as const) {
    assert.deepEqual(reads(await every(bob, { path })), shown, path);
  }
  await sameAsPlaces(bob, ['market/dev']);
  // A place he does not read lists none of its reads, not even as where a page stopped: no `next` walks prod's reads,
  // their times and numbers.
  const outside = async (paths: readonly string[]) => {
    for (const path of paths) {
      const page = await bob.audit.list({ path, limit: 1 });
      assert.deepEqual([page.entries, page.next], [[], null], path);
    }
  };
  await outside(['market/prod', 'market/prod/OTHER', 'market/prod-eu']);
  await root.access.set(BOB, { market: 'auditor' });
  assert.deepEqual(reads(await every(bob, { path: 'market' })), [rootProd, rootProd, adaDev]);
  assert.deepEqual(reads(await every(bob, { path: 'market/prod/OTHER' })), [rootProd, rootProd]);
  assert.deepEqual(reads(await every(bob, { path: 'market/prod-eu' })), [rootProd], 'the read in the fork');
  // An Auditor whose role leaves protected environments' logs out, and prod protected: market's pages, but for prod; the
  // fork's, but for its read of prod's key, which is at prod too.
  await root.roles.set('auditor', { name: 'Auditor', description: '', permissions: ['audit.read'], protected: [] });
  await root.environments.update('market/prod', { protected: true });
  for (const [query, shown] of [
    [{ path: 'market' }, [adaDev]], [{ path: 'market/prod' }, []], [{ path: 'market/prod/OTHER' }, []], [{ path: 'market/prod-eu' }, []],
    [{ path: 'market', actor: ADA }, [adaDev]], [{ path: 'market', actor: `user:${ROOT}` }, []],
  ] as const) assert.deepEqual(reads(await every(bob, query)), shown, JSON.stringify(query));
  // Prod is left out of his role there, and with it its pages. The fork's are his, unprotected: its read of prod's key
  // is passed over there, as a read hidden among those he sees.
  await outside(['market/prod', 'market/prod/OTHER']);
  assert.deepEqual(reads(await every(root, { path: 'market/prod-eu' })), [rootProd], "the whole log's reader sees it");
  // A read through a reference at dev to prod is at prod too: dev's pages leave it out for him. The whole log's reader
  // sees it there.
  await root.secrets.set('market/dev', { HELD: { ref: 'market/prod/OTHER' } });
  await ada.secrets.reveal('market/dev/HELD');
  const through = `ada@acme.example market/prod/OTHER v1 reveal 0.15`;
  for (const path of ['market/dev', 'market/dev/HELD', 'market']) {
    assert.deepEqual(reads(await every(bob, { path })).filter((read) => read === through), [], path);
    assert.deepEqual(reads(await every(root, { path })).filter((read) => read === through), [through], path);
  }
  // And on his page of no place, and by member: one rule, every page.
  for (const query of [{}, { actor: ADA }]) assert.deepEqual(reads(await every(bob, query)).filter((read) => read === through), [], JSON.stringify(query));
  await sameAsPlaces(bob, ['market']);
  // A page that reads it and shows nothing goes on past it, short: one entry a page, every page, lists what the whole does.
  for (const path of ['market/dev', 'market']) assert.deepEqual(reads(await every(bob, { path }, 1)), reads(await every(bob, { path })), path);
});

test("a reader of some places sees the entries at the places they read on every page, whoever's, and none elsewhere, their own included", async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  // Bob audits dev, as its Auditor, and reads prod's values, as a Developer there, whose role reads no log.
  await root.members.add(BOB, { role: 'member' });
  await root.access.set(BOB, { 'market/dev': 'auditor', 'market/prod': 'developer' });
  const bob = clientFor(deps, 'bob@acme.example');
  const bobs = bearer((await bob.tokens.issue(BOB, { label: 'bob', expiresInMinutes: 60, scope: { 'market/prod': 'developer' } })).token);
  await bobs.secrets.reveal('market/prod/OTHER');
  const adaDev = `ada@acme.example market/dev/API_KEY v1 reveal 0.15`;
  // His page of no place, and by member: the reads at dev, whoever's; his own read at prod nowhere, as prod's log is not his.
  for (const [query, shown] of [[{}, [adaDev]], [{ actor: ADA }, [adaDev]], [{ actor: BOB }, []], [{ actor: 'bob@acme.example' }, []]] as const) {
    assert.deepEqual(reads(await every(bob, query)), shown, JSON.stringify(query));
  }
  for (const [query, shown] of [[{ path: 'market/dev' }, [adaDev]], [{ path: 'market' }, [adaDev]], [{ path: 'market/prod' }, []], [{ path: 'market/prod', actor: BOB }, []]] as const) {
    assert.deepEqual(reads(await every(bob, query)), shown, JSON.stringify(query));
  }
  await sameAsPlaces(bob, ['market/dev']);
  // The whole log's reader sees both.
  assert.deepEqual(reads(await every(root)), [`bob@acme.example market/prod/OTHER v1 reveal 0.15`, adaDev]);
});

/**
 * No new access: a reader of some places sees on the page of no place exactly the entries the pages of the
 * places they read show, together; each by its log and number, detail included.
 */
async function sameAsPlaces(reader: CoffreClient, paths: readonly string[]): Promise<void> {
  const keys = (entries: AuditEntryView[]) => [...new Set(entries.map((entry) => `${entry.log}:${entry.seq}`))].sort();
  const placed: AuditEntryView[] = [];
  for (const path of paths) placed.push(...(await every(reader, { path, detail: '1' })));
  assert.deepEqual(keys(await every(reader, { detail: '1' })), keys(placed), `the page of no place against ${paths.join(', ')}`);
}

test("a read through a reference is filed at its source, of the source's version, its holder beside it; one in a fork, at its key, the fork beside it", async () => {
  await root.secrets.set('market/prod', { SOURCE: 'prod-source' });
  await root.secrets.set('market/prod', { SOURCE: 'prod-source-2' });
  await root.secrets.set('market/dev', { HELD: { ref: 'market/prod/SOURCE' } });
  assert.equal((await ada.secrets.reveal('market/dev/HELD')).values.HELD, 'prod-source-2');
  // On the whole log, the member's page and each place's.
  const pages = (paths: string[]) => [{}, { actor: ADA }, ...paths.map((path) => ({ path }))];
  for (const query of pages(['market/prod', 'market/prod/SOURCE', 'market/dev', 'market/dev/HELD'])) {
    const shown = (await every(root, query)).filter((entry) => entry.action === 'secret.read' && entry.decision === 'allow' && entry.metadata.via !== undefined);
    assert.equal(shown.length, 1, JSON.stringify(query));
    const [read] = shown as [AuditEntryView];
    // Filed at the source, the reference's holder beside it.
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
  // The vault vouches for the log's changes (here the tokens' issues) as for the reads: a cast or a MAC that drifts marks
  // every one forged.
  const changes = whole.filter((entry) => entry.log === '0.15' && entry.action !== 'secret.read');
  assert.ok(changes.some((entry) => entry.action === 'token.create'), JSON.stringify(changes));
  assert.ok(changes.every((entry) => entry.forged === undefined), JSON.stringify(changes.filter((entry) => entry.forged)));
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

/** The projection's row of a read, by its number. */
const readRow = (number: bigint) => and(eq(auditEvents.log, 16), eq(auditEvents.number, number));

test('a read the vault does not vouch for is shown forged: edited, renumbered, or written around coffre; a cursor moved on, said', async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  await ada.secrets.reveal('market/dev/OTHER');
  const before = (await every(root)).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(before.map((entry) => [entry.key, entry.forged]), [['OTHER', undefined], ['API_KEY', undefined]]);
  // Whoever owns the database says the first read was of another key, and moves the second to another number.
  const [second, first] = before as [AuditEntryView, AuditEntryView];
  await db.owner.update(auditEvents).set({ secret: second.metadata.secretId as string }).where(readRow(BigInt(first.seq)));
  await db.owner.update(auditEvents).set({ number: BigInt(second.seq) + 1000n }).where(readRow(BigInt(second.seq)));
  const after = (await every(root)).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(after.map((entry) => [entry.key, entry.forged]), [['OTHER', true], ['OTHER', true]]);
  // And moves the cursor on: the page says it cannot vouch for how far entries are listed.
  await db.owner.update(auditCursor).set({ through: 1_000_000n });
  const { reads } = await root.audit.list({ limit: 10 });
  assert.deepEqual([reads?.forged, reads?.behind], [true, true]);
  // Or deletes it: no page, report or check takes that for a projection yet to start.
  await db.owner.delete(auditCursor);
  const gone = await root.audit.list({ limit: 10 });
  assert.deepEqual([gone.reads?.forged, gone.reads?.behind], [true, true]);
  const report = await root.members.get(ADA);
  assert.deepEqual([report.reads?.forged, report.reads?.behind], [true, true]);
  const verdict = await root.audit.verifyReads();
  assert.ok(verdict.kept);
  assert.deepEqual([verdict.ok, verdict.problems], [false, ['the audit cursor is gone: a database writer deleted it']]);
});

test("the whole log's check holds the entries listed to the log sealed: one deleted, edited, given to another member, listed twice or off one of its places, each named", async () => {
  await root.secrets.set('market/prod', { SOURCE: 'prod-source' });
  await root.secrets.set('market/dev', { HELD: { ref: 'market/prod/SOURCE' }, THIRD: 'third', FOURTH: 'fourth', FIFTH: 'fifth' });
  // Six reads, each sealed by a pair of its own, so that the check goes a stretch for each, but the last two, which
  // share one: a copy is found only within its stretch's times and numbers.
  for (const key of ['API_KEY', 'OTHER', 'HELD', 'THIRD', 'FOURTH', 'FIFTH']) {
    await ada.secrets.reveal(`market/dev/${key}`);
    if (key !== 'FOURTH') await settle();
  }
  const sealed = await root.audit.verifyReads();
  assert.ok(sealed.kept && sealed.ok, JSON.stringify(sealed));
  const rows = await db.owner.select({ number: auditEvents.number, at: auditEvents.at, environment: auditEvents.environment }).from(auditEvents).where(eq(auditEvents.log, 16)).orderBy(auditEvents.number);
  assert.equal(rows.length, 6);
  const [deleted, edited, , moved, copied, unplaced] = rows.map((row) => row.number) as [bigint, bigint, bigint, bigint, bigint, bigint];
  // Whoever owns the database deletes a read; edits another; says a fourth was Bob's, off Ada's page and the offboarding
  // report; lists the fifth twice, the copy at the sixth's time, in their stretch; and takes the last off its
  // environment's pages. A read planted at a
  // time no use of the log's sealed near, or under a number none did, every page shows forged, by its MAC (above).
  await db.owner.delete(auditEvents).where(readRow(deleted));
  await db.owner.update(auditEvents).set({ credential: randomUUID() }).where(readRow(edited));
  await db.owner.update(auditEvents).set({ actor: BOB }).where(readRow(moved));
  const [copy] = await db.owner.select().from(auditEvents).where(readRow(copied));
  await db.owner.insert(auditEvents).values({ ...copy!, at: rows[5]!.at });
  await db.owner.delete(auditEventPlaces).where(and(eq(auditEventPlaces.log, 16), eq(auditEventPlaces.number, unplaced), eq(auditEventPlaces.place, rows[5]!.environment!)));
  assert.deepEqual(reads(await every(root, { path: 'market/dev' })).filter((read) => read.includes('/FIFTH ')), [], 'off its environment\'s page');
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
    `read ${unplaced} is off a place's pages: one of its places does not list it`,
  ]) assert.ok(named.includes(problem), `${problem}, among ${JSON.stringify(named)}`);
});

test("a read planted ahead of the projector, at other places, is replaced by the projector's, which its own places' pages list", async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  // Sealed, not yet listed: whoever owns the database writes a row of their own at the use's number, elsewhere.
  await signer!.checkpointer.tick();
  const [use] = await db.owner.select({ number: logUses.number, at: logUses.at }).from(logUses);
  const elsewhere = [randomUUID(), randomUUID()];
  await db.owner.insert(auditEvents).values({
    at: use!.at, number: use!.number, log: 16, author: 'vault', action: 'secret.read', shown: true, allowed: true, code: null, actor: BOB, subject: null,
    credential: randomUUID(), project: elsewhere[0]!, environment: elsewhere[1]!, secret: null, version: null, places: elsewhere, requestId: null,
    operationId: null, related: null, sourceIp: null, detail: '{}', mac: Buffer.alloc(16),
  });
  await db.owner.insert(auditEventPlaces).values(elsewhere.map((place) => ({ place, at: use!.at, number: use!.number, log: 16 })));
  await signer!.auditProjected();
  const [row] = await db.owner.select().from(auditEvents).where(readRow(use!.number));
  assert.deepEqual([row!.actor, row!.places.includes(elsewhere[1]!)], [ADA, false]);
  for (const path of ['market/dev/API_KEY', 'market/dev', 'market']) {
    assert.deepEqual(reads(await every(root, { path })), [`ada@acme.example market/dev/API_KEY v1 reveal 0.15`], path);
  }
  const verdict = await root.audit.verifyReads();
  assert.ok(verdict.kept && verdict.ok, JSON.stringify(verdict));
});

test("a use renumbered after its seal stops the projection, which lists nothing it would derive from it, and the whole log's check says why (WindowChecked)", async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  await ada.secrets.reveal('market/dev/OTHER');
  await signer!.checkpointer.tick();
  // Whoever owns the database swaps the two sealed uses' numbers, which neither use's MAC covers.
  const [first, second] = (await db.owner.select({ number: logUses.number }).from(logUses).orderBy(logUses.number)).map((row) => row.number) as [bigint, bigint];
  for (const [from, to] of [[first, -1n], [second, first], [-1n, second]] as const) await db.owner.update(logUses).set({ number: to }).where(eq(logUses.number, from));
  await signer!.auditProjected();
  assert.match((await signer!.alarms()).map((alarm) => alarm.message).join('\n'), /does not hold to the pair that sealed it/);
  const { entries } = await root.audit.list({ limit: 50 });
  assert.equal(entries.filter((entry) => entry.action === 'secret.read').length, 0);
  const verdict = await root.audit.verifyReads();
  assert.ok(verdict.kept && !verdict.ok && /does not hold to the pair that sealed it/.test(verdict.problems.join()), JSON.stringify(verdict));
});

test("a read waits to be listed until the projector writes it, and the page says how far it lists", async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  // Sealed, not yet projected: not listed, and the page lists through nothing yet.
  await signer!.checkpointer.tick();
  const waiting = await root.audit.list({ limit: 50 });
  assert.equal(waiting.entries.filter((entry) => entry.action === 'secret.read').length, 0);
  assert.equal(waiting.reads?.through, null);
  // Her report names nothing to rotate yet, and says it is behind, at once: an offboarding never reads it as all there is;
  // the removed members' counts the same.
  const report = await root.members.get(ADA);
  assert.deepEqual([report.exposed.length, report.reads?.behind], [0, true]);
  await signer!.auditProjected();
  const listed = await root.audit.list({ limit: 50 });
  assert.equal(listed.entries.filter((entry) => entry.action === 'secret.read').length, 1);
  assert.deepEqual([typeof listed.reads?.through, listed.reads?.behind, listed.reads?.forged], ['string', false, undefined]);
  const after = await root.members.get(ADA);
  assert.deepEqual([after.exposed.map((secret) => secret.key), after.reads?.behind], [['API_KEY'], false]);
  // A database writer who moves the cursor past what is listed: its MAC no longer holds, so the report says forged and
  // behind rather than whole: the report is whole only as far as the vault vouches the cursor.
  await db.owner.update(auditCursor).set({ through: sql`${auditCursor.through} + 1000` });
  const moved = await root.members.get(ADA);
  assert.deepEqual([moved.reads?.behind, moved.reads?.forged], [true, true]);
});

test('a report is behind while the walk down the log before 0.16 is open, its reads weighed too', async () => {
  const standing = { through: 10n, pair: 10n, at: Date.now(), oldFloor: 0n, oldFrom: 5n, oldTop: 9n, oldHash: Buffer.alloc(32), mac: Buffer.alloc(16), sealed: 10n, sealedAt: Date.now(), missing: false };
  const asking = (listingOlder: boolean, forged: string[] = []) => ({ vault: { vouch: async () => ({ forged, listingOlder }) } }) as unknown as Parameters<typeof readsReported>[0];
  assert.equal((await readsReported(asking(false), standing))?.behind, false);
  assert.equal((await readsReported(asking(true), standing))?.behind, true);
  assert.deepEqual(await readsReported(asking(false, ['cursor']), standing), { through: new Date(standing.at).toISOString(), behind: true, forged: true });
  // A cursor gone asks the vault nothing: forged.
  assert.equal((await readsReported(asking(false), { ...standing, missing: true }))?.forged, true);
});

test("a listing stopped behind its newest pair says so once that pair is a few seconds old, with no pair after it (review r4)", () => {
  const standing = (through: bigint, sealedAt: number, at: number) => ({
    through, pair: through, at, oldFloor: 0n, oldFrom: 0n, oldTop: 0n, oldHash: Buffer.alloc(32), mac: null, sealed: 10n, sealedAt, missing: false,
  });
  const now = Date.now();
  // The newest pair signed a second after the listing's, and nothing signed since: behind once it is old, not before.
  assert.equal(readsListed(standing(8n, now - 1000, now - 2000), false)?.behind, false);
  assert.equal(readsListed(standing(8n, now - READS_BEHIND_MS - 1000, now - READS_BEHIND_MS - 2000), false)?.behind, true);
  // All listed: never behind; strict, as a report is: behind as soon as one waits; or, for a member removed, as long as
  // the listing is below their removal.
  assert.equal(readsListed(standing(10n, now - 60_000, now - 60_000), false)?.behind, false);
  assert.equal(readsListed(standing(8n, now - 100, now - 200), false, { strict: true })?.behind, true);
  assert.equal(readsListed(standing(8n, now - 100, now - 200), false, { strict: true, upTo: 8n })?.behind, false);
  assert.equal(readsListed(standing(8n, now - 100, now - 200), false, { strict: true, upTo: 9n })?.behind, true);
  // No pair at all: no listing to speak of.
  assert.equal(readsListed({ ...standing(0n, 0, 0), sealed: null, sealedAt: null }, false), null);
  // The cursor's row gone: forged, behind, whatever it would have said.
  assert.deepEqual(readsListed({ ...standing(10n, now, now), missing: true }, false), { through: new Date(now).toISOString(), behind: true, forged: true });
});

test('the offboarding report names what someone read, current until a new version is written', async () => {
  await ada.secrets.reveal('market/dev/API_KEY');
  await settle();
  const report = await root.members.get(ADA);
  assert.deepEqual(report.exposed.map((entry) => `${entry.project}/${entry.environment}/${entry.key}`), ['market/dev/API_KEY']);
  await root.secrets.set('market/dev', { API_KEY: 'rotated' });
  const rotated = await root.members.get(ADA);
  assert.deepEqual([rotated.exposed.length, rotated.rotated], [0, 1]);
});

test("a reference's read is its source's then: repointed, its earlier read stays at the old source and its later is at the new, on each source's page too", async () => {
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
  for (const [path, shown] of [['market/prod/SOURCE', ['market/prod/SOURCE']], ['market/stage', ['market/stage/OTHER_SOURCE']], ['market/dev/HELD', ['market/stage/OTHER_SOURCE', 'market/prod/SOURCE']]] as const) {
    assert.deepEqual(held(await every(root, { path })), shown, path);
  }
  // Bob audits prod alone: its log names the earlier read alone, on every page.
  await root.members.add(BOB, { role: 'member' });
  await root.access.set(BOB, { 'market/prod': 'auditor' });
  const bob = clientFor(deps, 'bob@acme.example');
  for (const query of [{}, { actor: `user:${ROOT}` }, { path: 'market/prod' }, { path: 'market/prod/SOURCE' }]) {
    assert.deepEqual(held(await every(bob, query)), ['market/prod/SOURCE'], JSON.stringify(query));
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

test("a report weighs reads from retention's cut, as the newest retention change in the log names it, and says from when; an old log's read older than the cut stays on the page and is on no report", async () => {
  await ada.secrets.reveal('market/dev/OTHER');
  await settle();
  const [key] = await db.owner.select({ id: secrets.id, project: secrets.projectId, environment: secrets.environmentId, version: secrets.currentVersionId })
    .from(secrets).where(eq(secrets.key, 'API_KEY')).orderBy(secrets.environmentId);
  // A read 0.14's log kept from long ago, as the projector lists one (its MAC aside: only the pages and the report are
  // under test), the day retention since dropped: its row on the page, its summary row gone with the day.
  const old = Date.parse('2026-01-01T12:00:00Z');
  await db.owner.insert(auditEvents).values({
    at: old, number: 7n, log: 14, author: 'vault', action: 'secret.read', shown: true, allowed: true, code: null, actor: ADA, subject: null, credential: null,
    project: key!.project, environment: key!.environment, secret: key!.id, version: key!.version, places: [key!.project, key!.environment, key!.id], requestId: null,
    operationId: null, related: null, sourceIp: null, detail: '{"version":1}', mac: Buffer.alloc(16),
  });
  await db.owner.insert(auditEventPlaces).values([key!.project, key!.environment, key!.id].map((place) => ({ place, at: old, number: 7n, log: 14 })));
  assert.equal((await db.owner.select().from(auditMemberKeys).where(and(eq(auditMemberKeys.principal, ADA), eq(auditMemberKeys.secret, key!.id)))).length, 0);
  const page = (await every(root, { actor: ADA })).filter((entry) => entry.action === 'secret.read');
  assert.deepEqual(page.map((entry) => [entry.log, entry.key]), [['0.15', 'OTHER'], ['0.14', 'API_KEY']], 'both on the page');
  // Retention's change for that day, in the chain as the vault writes it, planted once the projector has run: its MAC aside (vault/log-entry.ts, `retentionPayload`).
  const payload = JSON.stringify({ op: 'retention', day: '2026-01-01', cut: { upto: '1', at: old, uses: 0, root: '00' } });
  await db.owner.insert(logChanges).values({
    number: 9_000_000_000n, at: Date.now(), requestId: randomUUID(), object: logObject('log', 'retention'), actor: 'system:retention', payload, mac: Buffer.alloc(16),
  });
  const report = await root.members.get(ADA);
  assert.deepEqual(report.exposed.map((secret) => secret.key), ['OTHER'], 'the old read on no report');
  assert.equal(report.readsFrom, '2026-01-02T00:00:00.000Z');
});
