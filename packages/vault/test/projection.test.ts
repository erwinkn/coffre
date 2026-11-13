// The audit projection (projection.ts): each log's entries as the pages will list them, from the chains' signed
// windows and from audit_log backward from its anchor; a projector overtaken; an entry edited under the anchor; a
// rebuild; retention's drop of a day.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { deriveLogKey } from '@coffre/core/audit';
import { appendEntries, type NewEntry } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { eventVouched, type AuditEvent } from '../src/audit-rows.ts';
import { alone } from '../src/keyring.ts';
import { openLogCheckpointer } from '../src/log-checkpointer.ts';
import { entryMac, logMacKey } from '../src/log-entry.ts';
import { canonical } from '../src/inputs.ts';
import { callRebuild, logStore } from '../src/log-store.ts';
import { vaultLogKey } from '../src/log.ts';
import { eventObject, eventRow, findingEventId } from '../src/note.ts';
import { changeEvent, projectAudit, rebuildRow } from '../src/projection.ts';
import { verifierKeys } from '../src/verifier.ts';
import { variableMemory } from './audit-tree.ts';
import { openTestDatabase, rows, run, withLogUnlocked, type TestDatabase } from './database.ts';
import { logWriter } from './log-entries.ts';
import { ask, emptyLog, isolate, ROOT, SIGNING_KEY, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(async () => {
  await emptyLog();
  for (const table of ['log_checkpoints', 'log_tiles']) await run(db.owner, sql.raw(`DELETE FROM ${table}`));
});

const keys = () => verifierKeys([SIGNING_KEY]);
const OLD_KEYS = [vaultLogKey(SIGNING_KEY)];
const project = async (options: { steps?: number; atOnce?: number } = {}, store = logStore(db.vault)) => projectAudit(store, await keys(), OLD_KEYS, options);

/** Every batch until none is left. */
async function projectAll(options: { atOnce?: number } = {}) {
  for (let run = 0; run < 200; run += 1) if (!(await project({ ...options, steps: 1 })).more) return;
  throw new Error('the projection did not catch up');
}

async function signer() {
  const cp = await openLogCheckpointer({ store: logStore(db.vault), signingKeys: [SIGNING_KEY], memory: variableMemory(), record: () => {} });
  return async () => {
    const tick = await cp.tick();
    assert.ok(tick.failures.length === 0, tick.failures.join('; '));
  };
}

type Row = Record<string, unknown>;
const events = (where = sql`true`) => rows<Row>(db.owner, sql`SELECT at, number, log, author, action, shown, allowed, code, actor, subject, credential, project, environment,
  secret, version, places, request_id, operation_id, related, source_ip, detail, mac FROM audit_events WHERE ${where} ORDER BY at, number, log`);
const count = async (query: ReturnType<typeof sql>) => Number((await rows<{ n: string | number }>(db.owner, query))[0]!.n);

/** A row as the projector wrote it, for its MAC. */
function eventOf(row: Row): AuditEvent {
  const id = (value: unknown) => (value === null ? null : String(value));
  return {
    at: Number(row.at), number: BigInt(row.number as string), log: Number(row.log) as AuditEvent['log'], author: row.author as AuditEvent['author'],
    action: String(row.action), shown: row.shown === true, allowed: row.allowed === true, code: id(row.code), actor: String(row.actor), subject: id(row.subject),
    credential: id(row.credential), project: id(row.project), environment: id(row.environment), secret: id(row.secret), version: id(row.version),
    places: row.places as string[], requestId: id(row.request_id), operationId: id(row.operation_id), related: row.related === null ? null : BigInt(row.related as string),
    sourceIp: id(row.source_ip), detail: String(row.detail), mac: Buffer.from(row.mac as Uint8Array),
  };
}

const APP = deriveLogKey('app', randomBytes(32));

/** Entries of audit_log, as a writer under 0.15's log appends them. */
const append = (entries: NewEntry[], key = APP) => db.owner.transaction((tx) => appendEntries(tx, key, entries, undefined, undefined, [], true));

/** The vault's 0.14 checkpoint of audit_log as it stands: the prefix to its last entry, under `key`. Its last seq. */
async function checkpoint14(key = OLD_KEYS[0]!): Promise<bigint> {
  const [last] = await rows<{ seq: string | number; hash: Uint8Array }>(db.owner, sql`SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`);
  const metadata = { seq: Number(last!.seq), hash: Buffer.from(last!.hash).toString('hex'), signedAt: new Date().toISOString(), keyId: key.keyId, signature: 'unchecked' };
  await append([{ actor: 'system:vault', action: 'audit.checkpoint', decision: 'allow', metadata: JSON.stringify(metadata) }], key);
  return BigInt(last!.seq);
}

const reads = (n: number) => Array.from({ length: n }, (_, i): NewEntry => ({ actor: ROOT, action: 'sign_in', decision: 'allow', metadata: JSON.stringify({ i }) }));
const listedOld = (upto: bigint) => count(sql`SELECT count(*) AS n FROM audit_log WHERE seq <= ${upto} AND action NOT IN ('audit.heartbeat', 'audit.checkpoint')`);

test('each use a read at its places, by its account, in the summary; a refusal of the vault a row of its own; a change audit_log records too, none; each row under the vault\'s MAC; a second run lists nothing new', async () => {
  const tick = await signer();
  const w = await world();
  const { use } = await isolate();
  const [k1, k2] = [await w.key(), await w.key()];
  for (const key of [k1, k2, k1]) assert.ok((await use(ask(w, key))).ok);
  // A key write the vault refused (refusal.ts), as `log_refusal` writes it.
  const request = randomUUID();
  const payload = JSON.stringify({
    code: 'no_grant', credential: w.credentialId, environmentId: w.dev, identity: null, keys: ['API_KEY'], op: 'write.refused', path: 'market/dev', projectId: w.project,
    read: 'digest', ref: { id: request, kind: 'request' }, request: { number: '1', operationId: null, requestId: 'req-1' },
  });
  const row = { at: Date.now(), requestId: request, object: '', actor: w.principal, payload, seal: null };
  const [{ object }] = await rows<{ object: string }>(db.owner, sql`SELECT CAST(log_object('request', ${request}) AS text) AS object`);
  await run(db.owner, sql`SELECT log_refusal(${row.at}::bigint, ${request}, ${w.principal}, ${payload}, ${entryMac(logMacKey(SIGNING_KEY), { tree: 'changes', row: { ...row, object } })})`);
  await tick();
  const done = await project();
  assert.equal(done.more, false);
  const listed = await events();
  const used = listed.filter((r) => Number(r.log) === 16);
  // A use each, as the log has them (a key read again within its period may be one use).
  assert.equal(used.length, await count(sql`SELECT count(*) AS n FROM log_uses`));
  assert.ok(used.length >= 2);
  for (const r of used) {
    assert.deepEqual([r.action, r.actor, r.allowed, r.shown, r.environment, r.project], ['secret.read', w.principal, true, true, w.dev, w.project]);
    assert.deepEqual([...(r.places as string[])].sort(), [String(r.secret), w.dev, w.project].sort());
  }
  const changes = listed.filter((r) => Number(r.log) === 15);
  assert.deepEqual(changes.map((r) => [r.action, r.allowed, r.code, r.actor, r.environment, r.project, r.request_id]), [['secret.write', false, 'no_grant', w.principal, w.dev, w.project, 'req-1']]);
  assert.deepEqual(JSON.parse(String(changes[0]!.detail)), { path: 'market/dev', keys: ['API_KEY'], reason: 'no_grant', credentialId: w.credentialId });
  // Under the vault's MAC, each; one edited, not.
  const ring = alone(await keys());
  for (const r of listed) assert.ok(eventVouched(ring, eventOf(r)), `${String(r.log)}:${String(r.number)}`);
  assert.equal(eventVouched(ring, { ...eventOf(used[0]!), actor: ROOT }), false);
  // Every place of each, and the summary: one row per key read, at its newest read.
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_event_places`), listed.reduce((n, r) => n + (r.places as string[]).length, 0));
  const summary = await rows<{ secret: string; wrote: boolean; number: string }>(db.owner, sql`SELECT CAST(secret AS text) AS secret, wrote, CAST(number AS text) AS number FROM audit_member_keys ORDER BY secret`);
  assert.deepEqual(summary.map((s) => s.secret).sort(), [k1, k2].sort());
  assert.equal(summary.find((s) => s.secret === k1)!.number, String(used.filter((r) => r.secret === k1).at(-1)!.number));
  // Nothing more to list.
  assert.equal((await project()).events, 0);
  assert.equal((await events()).length, listed.length);
});

test('audit_log is listed only behind the newest signed 0.14 checkpoint, batch by batch from the cursor, its heartbeats and checkpoints left out; the next checkpoint lists the rest', async () => {
  await append(reads(7));
  await append([{ actor: 'system:coffre', action: 'audit.heartbeat', decision: 'allow', metadata: '{}' }]);
  const first = await checkpoint14();
  await append(reads(3));
  // Three a batch, one a run: the cursor goes down and the gap closes, then nothing is left.
  let runs = 0;
  for (let more = true; more; runs += 1) more = (await project({ steps: 1, atOnce: 3 })).more;
  assert.ok(runs > 2, `${runs} runs`);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 14`), await listedOld(first));
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 14 AND action IN ('audit.heartbeat', 'audit.checkpoint')`), 0);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 14 AND number > ${first}`), 0);
  const second = await checkpoint14();
  await projectAll({ atOnce: 3 });
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 14`), await listedOld(second));
  const [cursor] = await rows<{ old_floor: string; old_from: string; old_top: string }>(db.owner, sql`SELECT old_floor, old_from, old_top FROM audit_cursor`);
  assert.deepEqual([cursor!.old_floor, cursor!.old_from, cursor!.old_top].map(BigInt), [second + 1n, second + 1n, second + 1n]);
  const ring = alone(await keys());
  for (const r of await events(sql`log = 14`)) assert.ok(eventVouched(ring, eventOf(r)));
});

test("an entry of audit_log is at the places today's page matches it at: its reference's other side (also), and each key a read of several lists, and that key's source", async () => {
  const [project, environment, secret, listed, source] = Array.from({ length: 5 }, () => randomUUID());
  await append([
    { actor: ROOT, action: 'reference.create', decision: 'allow', metadata: JSON.stringify({ also: { projectId: project, environmentId: environment, secretId: secret, extra: 'not-a-uuid' } }) },
    { actor: ROOT, action: 'secret.read', decision: 'allow', metadata: JSON.stringify({ secrets: [{ secretId: listed, version: 1 }, { secretId: null, also: { secretId: source } }, 'junk'] }) },
  ]);
  await checkpoint14();
  await projectAll();
  const placed = await rows<{ action: string; places: string[] }>(db.owner, sql`SELECT action, places FROM audit_events WHERE log = 14 AND action IN ('reference.create', 'secret.read') ORDER BY number`);
  assert.deepEqual(placed.map((row) => [row.action, row.places]), [
    ['reference.create', [project!, environment!, secret!].sort()],
    ['secret.read', [listed!, source!].sort()],
  ]);
});

test('an entry of audit_log edited below the anchor stops the walk there, nothing at or below it listed; a checkpoint without the vault\'s MAC starts no walk', async () => {
  await append(reads(6));
  const top = await checkpoint14();
  const [{ metadata }] = await rows<{ metadata: string }>(db.owner, sql`SELECT metadata FROM audit_log WHERE seq = ${top - 2n}`);
  await withLogUnlocked(db.owner, (owner) => run(owner, sql`UPDATE audit_log SET metadata = '{"i":99}' WHERE seq = ${top - 2n}`));
  await assert.rejects(projectAll({ atOnce: 2 }), /entry \d+ of audit_log does not hash to what the entry above it chains to/);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 14 AND number <= ${top - 2n}`), 0);
  // A newer checkpoint under a key the vault does not hold: the walk under way is not the problem, the anchor is.
  await withLogUnlocked(db.owner, (owner) => run(owner, sql`UPDATE audit_log SET metadata = ${metadata} WHERE seq = ${top - 2n}`));
  await run(db.owner, sql`TRUNCATE audit_events, audit_event_places, audit_member_keys`);
  await run(db.owner, sql`UPDATE audit_cursor SET through = 0, pair = 0, at = 0, old_floor = 0, old_from = 0, old_top = 0, old_hash = ${Buffer.alloc(32)}, mac = NULL`);
  await checkpoint14(deriveLogKey('vault', randomBytes(32)));
  await assert.rejects(project(), /does not hold to the vault's MAC/);
});

test("a break in audit_log's hashes inside a range an Owner accepted as lost stops the walk with a finding naming the acceptance, nothing at or below it listed", async () => {
  await append(reads(6));
  const [{ seq }] = await rows<{ seq: string | number }>(db.owner, sql`SELECT max(seq) AS seq FROM audit_log`);
  const lost = BigInt(seq) - 2n;
  const [{ metadata }] = await rows<{ metadata: string }>(db.owner, sql`SELECT metadata FROM audit_log WHERE seq = ${lost}`);
  // The range as a tail cut leaves it: what the log holds there now is not what the entry after it chains to.
  await withLogUnlocked(db.owner, (owner) => run(owner, sql`UPDATE audit_log SET metadata = '{"i":99}' WHERE seq = ${lost}`));
  await append([{ actor: ROOT, action: 'audit.loss_accepted', decision: 'allow', metadata: JSON.stringify({ from: Number(lost), to: Number(lost), resumes: Number(lost) + 1 }) }]);
  const [{ seq: accepted }] = await rows<{ seq: string | number }>(db.owner, sql`SELECT max(seq) AS seq FROM audit_log`);
  await checkpoint14();
  await assert.rejects(projectAll({ atOnce: 2 }), new RegExp(`entry ${lost} of audit_log is in entries ${lost} to ${lost}, whose loss an Owner accepted \\(entry ${accepted}, audit.loss_accepted\\): the walk does not go below an accepted loss`));
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 14 AND number <= ${lost}`), 0);
  // audit_log outlives the test: whole again for the next.
  await withLogUnlocked(db.owner, (owner) => run(owner, sql`UPDATE audit_log SET metadata = ${metadata} WHERE seq = ${lost}`));
});

test("a change is classified by its payload's own top-level keys, never by text nested in it", () => {
  const credential = randomUUID();
  const change = (actor: string, payload: object) => changeEvent({ tree: 'changes', number: 7n, at: 1, columns: [7n, randomUUID(), `credential:${credential}`, actor, JSON.stringify(payload)] });
  const ref = { id: credential, kind: 'credential' };
  const nested = { detail: { inputs: 'x', signIn: { binding: 'b' }, issue: { by: 'user:u' }, revoke: { reason: 'sign_out' } } };
  // A sign-in whose payload starts as a key write's and holds a two-trip write's text inside: still a sign-in. Matched
  // by text, it was taken for a two-trip write, which it is not, and listed as nothing.
  const signIn = { binding: randomUUID(), issuer: 'https://idp', proof: 'oidc', run: null };
  assert.equal(change('token:t', { digest: 'd', generation: 1, ref, held: nested, signIn })?.action, 'token.exchange');
  // A revoke by request, whose nested detail says sign_out: a revoke.
  assert.equal(change('user:u', { op: 'credential.revoke', ref, held: nested, revoke: { kind: 'personal', reason: 'revoke' } })?.action, 'token.revoke');
  // Nothing at the top level but the text inside: no row.
  assert.equal(change('user:u', { op: 'credential.revoke', ref, held: nested }), null);
  assert.equal(change('user:u', { digest: 'd', op: 'secret.write', ref: { id: randomUUID(), kind: 'secret' }, held: nested, request: {} }), null);
});

// A change carrying its entry: a key write's change, its payload as the vault writes it, canonical, `reported` sorting
// after `op`. `extra` adds the two-trip write's record beside it.
const ADA = 'user:ada@acme.example';
function carrier(entry: { action: string; detail: Record<string, unknown> }, at: { secret: string; version: string; project: string; environment: string }, extra: object = {}) {
  const reported = {
    action: entry.action, allowed: true, author: 'app', code: null, credential: randomUUID(), detail: entry.detail, operationId: randomUUID(),
    places: { environmentId: at.environment, projectId: at.project, secretId: at.secret, versionId: at.version }, requestId: `req-${entry.action}`, sourceIp: '203.0.113.7', subject: null,
  };
  return canonical({ digest: 'd', op: 'secret.write', ref: { id: at.secret, kind: 'secret' }, reported, version: at.version, ...extra });
}

test("a change carrying its entry is listed from it alone, before the vault's own records; a write that supplied a value is its member's summary's, a mark, a loosening and a restore are not", async () => {
  const tick = await signer();
  const log = logWriter(db.owner, logMacKey(SIGNING_KEY));
  const [project, environment] = [randomUUID(), randomUUID()];
  const key = () => ({ secret: randomUUID(), version: randomUUID(), project, environment });
  const [written, marked, loosened, restored, twoTrip] = [key(), key(), key(), key(), key()];
  const changes = [
    carrier({ action: 'secret.write', detail: { key: 'DB_URL', version: 2, credentialId: 'c' } }, written),
    carrier({ action: 'secret.write', detail: { key: 'DB_URL', kept: 2, version: 3, from: 'secret', to: 'sensitive' } }, marked),
    carrier({ action: 'secret.loosen', detail: { from: 'sensitive', kept: 3, key: 'DB_URL', to: 'secret', version: 4 } }, loosened),
    carrier({ action: 'secret.restore', detail: { key: 'DB_URL', version: 5, restoredFrom: 1 } }, restored),
    // A two-trip write's record (`written`: its digest first, its inputs, its request), which also carries: one row, the entry's.
    carrier({ action: 'secret.write', detail: { key: 'API_KEY', version: 1 } }, twoTrip, { inputs: 'i', request: { credential: randomUUID(), number: '1', operationId: null, requestId: 'req-record' } }),
  ];
  const numbers: bigint[] = [];
  for (const payload of changes) numbers.push(await log.change(payload, Date.now(), randomUUID(), ADA));
  await tick();
  await projectAll();
  const listed = await events(sql`log = 15 AND actor = ${ADA}`);
  assert.deepEqual(listed.map((r) => [String(r.number), r.action, r.secret, r.version]), [
    [String(numbers[0]), 'secret.write', written.secret, written.version],
    [String(numbers[1]), 'secret.write', marked.secret, marked.version],
    [String(numbers[2]), 'secret.loosen', loosened.secret, loosened.version],
    [String(numbers[3]), 'secret.restore', restored.secret, restored.version],
    [String(numbers[4]), 'secret.write', twoTrip.secret, twoTrip.version],
  ]);
  // Every field the entry's, the actor and time the change's; its places as carried, as an entry of audit_log's are.
  const [first] = listed;
  const entry = JSON.parse(changes[0]!).reported;
  assert.deepEqual(
    [first!.author, first!.allowed, first!.shown, first!.code, first!.subject, first!.credential, first!.project, first!.environment, first!.request_id, first!.operation_id, first!.source_ip],
    ['app', true, true, null, null, entry.credential, project, environment, 'req-secret.write', entry.operationId, '203.0.113.7'],
  );
  assert.deepEqual([...(first!.places as string[])].sort(), [project, environment, written.secret].sort());
  assert.deepEqual(JSON.parse(String(first!.detail)), entry.detail);
  assert.equal(listed[4]!.request_id, 'req-secret.write');
  const ring = alone(await keys());
  for (const r of listed) assert.ok(eventVouched(ring, eventOf(r)));
  // The summary: the write and the two-trip write supplied values; the mark, the loosening and the restore did not.
  const summary = await rows<{ secret: string; version: string; wrote: boolean }>(db.owner, sql`SELECT CAST(secret AS text) AS secret, CAST(version AS text) AS version, wrote FROM audit_member_keys WHERE principal = ${ADA} ORDER BY number`);
  assert.deepEqual(summary.map((s) => [s.secret, s.version, s.wrote]), [[written.secret, written.version, true], [twoTrip.secret, twoTrip.version, true]]);
});

test("only a top-level `reported` makes a change a carrier: one nested in a detail is the entry's detail, and one inside another key, nothing", () => {
  const at = { secret: randomUUID(), version: randomUUID(), project: randomUUID(), environment: randomUUID() };
  const change = (payload: string) => changeEvent({ tree: 'changes', number: 7n, at: 1, columns: [7n, randomUUID(), `secret:${at.secret}`, ADA, payload] });
  const inner = JSON.parse(carrier({ action: 'secret.delete', detail: { key: 'X' } }, at)).reported;
  const nested = change(carrier({ action: 'secret.write', detail: { key: 'DB_URL', reported: inner } }, at));
  assert.equal(nested?.action, 'secret.write');
  assert.deepEqual(JSON.parse(String(nested?.detail)), { key: 'DB_URL', reported: inner });
  // A key write's change with the entry below the top level, and no record of the vault's: listed as nothing.
  assert.equal(change(canonical({ digest: 'd', held: { reported: inner }, op: 'secret.write', ref: { id: at.secret, kind: 'secret' }, version: at.version })), null);
  // An entry of no event's shape: nothing, and no record read beside it.
  const signIn = { binding: randomUUID(), issuer: 'https://idp', proof: 'oidc', run: null };
  assert.equal(change(canonical({ digest: 'd', generation: 1, ref: { id: randomUUID(), kind: 'credential' }, reported: { detail: {} }, signIn })), null);
});

// Two carried entries, byte for byte as the app's encoder (`reportedPayload`) stores them in `log_changes.payload`: a
// key written through the app, then a value loosened. Their entries name no version (`places.versionId` null): the
// version is the change's own.
const A1_WRITE = '{"digest":null,"environmentId":"64cf37a3-fe9a-456e-8cdb-ab615118cd83","key":{"bytes":"Qfl0cJnhbo9xkb0XS9WtVGcOAiW0dOSAY8ZQWyJTN2YliRtWe+4tFkRWjPEQiQ+sRcNKOcwM0vTzT5zF","kekId":"test-kek-1","kekProvider":"local","kekVersion":"1"},"nature":"secret","op":"secret.write","projectId":"43e226c6-d9e5-4bcf-814c-445194bbf208","ref":{"id":"9a187106-385d-471e-8e88-752cfb7c4326","kind":"secret"},"reference":null,"reported":{"action":"secret.write","allowed":true,"author":"app","code":null,"credential":null,"detail":{"key":"DATABASE_URL","version":1},"operationId":"24006a57-fa9b-4994-8187-0271c59b8d28","places":{"environmentId":"64cf37a3-fe9a-456e-8cdb-ab615118cd83","projectId":"43e226c6-d9e5-4bcf-814c-445194bbf208","secretId":"9a187106-385d-471e-8e88-752cfb7c4326","versionId":null},"requestId":"f2db4597-4966-4625-8f78-f52a0485c78e","sourceIp":null,"subject":null},"source":null,"version":"03757f78-e76e-4b95-9799-571f89cad9f9"}';
const A1_LOOSEN = '{"digest":null,"environmentId":"64cf37a3-fe9a-456e-8cdb-ab615118cd83","key":{"bytes":"+f+zrUq7u7y+4kxin1DtMq+c7ygEXf84MBI7ReMSu5U3QLBvOkWKQ5HyActcARF+PmAW8fiHYZ+RC0xt","kekId":"test-kek-1","kekProvider":"local","kekVersion":"1"},"nature":"secret","op":"secret.write","projectId":"43e226c6-d9e5-4bcf-814c-445194bbf208","ref":{"id":"652d23b5-9407-42d2-9e49-c68abe19952c","kind":"secret"},"reference":null,"reported":{"action":"secret.loosen","allowed":true,"author":"app","code":null,"credential":null,"detail":{"from":"sensitive","kept":1,"key":"STRIPE_KEY","to":"secret","version":2},"operationId":"8db51159-b16c-4f07-ac4d-c4444154bade","places":{"environmentId":"64cf37a3-fe9a-456e-8cdb-ab615118cd83","projectId":"43e226c6-d9e5-4bcf-814c-445194bbf208","secretId":"652d23b5-9407-42d2-9e49-c68abe19952c","versionId":null},"requestId":"80d299f8-5858-4225-8d6e-b68347701add","sourceIp":null,"subject":null},"source":null,"version":"a4564561-bd17-403f-96ac-aa91444d313f"}';

test("a carried row: its places the entry's, its version and its member's summary the change's own; a value no uuid is null, and a non-member's write no summary's", async () => {
  const tick = await signer();
  const log = logWriter(db.owner, logMacKey(SIGNING_KEY));
  // The entry's places name other ids than the change's `ref` and `version`, which the vault sealed.
  const [named, sealed] = [{ secret: randomUUID(), version: randomUUID(), project: randomUUID(), environment: randomUUID() }, { secret: randomUUID(), version: randomUUID() }];
  const apart = JSON.parse(carrier({ action: 'secret.write', detail: { key: 'DB_URL', version: 2 } }, named));
  const base = { ...apart, ref: { id: sealed.secret, kind: 'secret' }, version: sealed.version };
  const differs = canonical(base);
  // Fields of no uuid's shape, which the row keeps as null rather than failing the batch's cast.
  const bad = canonical({ ...base, reported: { ...apart.reported, credential: 'not-a-uuid', operationId: 'nor-this', places: { ...apart.reported.places, projectId: 'x' } } });
  const numbers: bigint[] = [];
  for (const [payload, actor] of [[differs, ADA], [bad, ADA], [A1_WRITE, ADA], [A1_LOOSEN, ADA], [differs, 'system:vault']] as const) {
    numbers.push(await log.change(payload, Date.now(), randomUUID(), actor));
  }
  await tick();
  await projectAll();
  const listed = await events(sql`log = 15`);
  assert.deepEqual(listed.map((r) => [String(r.number), r.actor, r.action, r.secret, r.version]), [
    [String(numbers[0]), ADA, 'secret.write', named.secret, sealed.version],
    [String(numbers[1]), ADA, 'secret.write', named.secret, sealed.version],
    [String(numbers[2]), ADA, 'secret.write', '9a187106-385d-471e-8e88-752cfb7c4326', '03757f78-e76e-4b95-9799-571f89cad9f9'],
    [String(numbers[3]), ADA, 'secret.loosen', '652d23b5-9407-42d2-9e49-c68abe19952c', 'a4564561-bd17-403f-96ac-aa91444d313f'],
    [String(numbers[4]), 'system:vault', 'secret.write', named.secret, sealed.version],
  ]);
  assert.deepEqual([listed[1]!.credential, listed[1]!.operation_id, listed[1]!.project], [null, null, null]);
  const [write, loosen] = [listed[2]!, listed[3]!];
  assert.deepEqual(
    [write.author, write.project, write.environment, write.request_id, write.operation_id, JSON.parse(String(write.detail))],
    ['app', '43e226c6-d9e5-4bcf-814c-445194bbf208', '64cf37a3-fe9a-456e-8cdb-ab615118cd83', 'f2db4597-4966-4625-8f78-f52a0485c78e', '24006a57-fa9b-4994-8187-0271c59b8d28', { key: 'DATABASE_URL', version: 1 }],
  );
  assert.deepEqual(JSON.parse(String(loosen.detail)), { from: 'sensitive', kept: 1, key: 'STRIPE_KEY', to: 'secret', version: 2 });
  const ring = alone(await keys());
  for (const r of listed) assert.ok(eventVouched(ring, eventOf(r)));
  // The summary: the change's own key and version (once, a member's row of a version being one), and the app's write; the
  // loosening none, and the vault's own write none, as no member's.
  const summary = await rows<{ principal: string; secret: string; version: string }>(db.owner, sql`SELECT principal, CAST(secret AS text) AS secret, CAST(version AS text) AS version FROM audit_member_keys WHERE wrote ORDER BY number`);
  assert.deepEqual(summary.map((s) => [s.principal, s.secret, s.version]), [
    [ADA, sealed.secret, sealed.version],
    [ADA, '9a187106-385d-471e-8e88-752cfb7c4326', '03757f78-e76e-4b95-9799-571f89cad9f9'],
  ]);
});

test("a token the app issued is listed from its entry, whose detail holds its kind and label; an entry beside the vault's `issue` wins, and a `reported` of no entry's shape lists nothing", () => {
  const change = (payload: string, actor = ADA) => changeEvent({ tree: 'changes', number: 9n, at: 1, columns: [9n, randomUUID(), 'credential:c', actor, payload] });
  const reported = {
    action: 'token.create', allowed: true, author: 'app', code: null, credential: null, detail: { kind: 'cli', label: 'laptop' }, operationId: randomUUID(),
    places: { environmentId: null, projectId: null, secretId: null, versionId: null }, requestId: 'req-issue', sourceIp: null, subject: ADA,
  };
  // A credential's change as the app's issuer writes it (`#issueChange`): its columns and its entry, no `issue`.
  const issued = { caller: null, expiresAt: 1, generation: 1, op: 'credential.issue', principal: ADA, ref: { id: randomUUID(), kind: 'credential' }, reported, scope: null };
  for (const payload of [issued, { ...issued, issue: { kind: 'browser', label: 'from-the-record' } }]) {
    const row = change(canonical(payload));
    assert.deepEqual([row?.action, row?.author, row?.subject, row?.requestId, JSON.parse(String(row?.detail))], ['token.create', 'app', ADA, 'req-issue', { kind: 'cli', label: 'laptop' }]);
  }
  // `reported` there but no object: nothing, as an object of no entry's shape, and the sign-in's record beside it unread.
  const signIn = { binding: randomUUID(), issuer: 'https://idp', proof: 'oidc', run: null };
  const signedIn = { digest: 'd', generation: 1, ref: { id: randomUUID(), kind: 'credential' }, signIn };
  assert.equal(change(canonical(signedIn), 'token:t')?.action, 'token.exchange');
  for (const bad of ['x', null, [reported]]) assert.equal(change(canonical({ ...signedIn, reported: bad }), 'token:t'), null);
});

// Tokens issued through an MCP connection, as `log_changes.payload` holds them (`mcp-oauth.test.ts`): the
// caller has no credential of its own, so the entry's `credential` is null and its detail's `credentialId` names the
// connection (`traceFields`), as an entry of audit_log's does.
const A1_SERVICE_TOKEN = '{"caller":"bearer","expiresAt":1794620403861,"generation":0,"op":"credential.issue","principal":"token:ci","ref":{"id":"91d75aff-81c0-48db-9253-79f876395e79","kind":"credential"},"reported":{"action":"token.create","allowed":true,"author":"app","code":null,"credential":null,"detail":{"credentialId":"9b945b00-8351-44bb-a2c6-7d71f1e69f7d","expiresAt":"2026-11-14T01:40:03.861Z","kind":"service","label":"deploy","principalId":"ci","principalType":"service","scope":[{"environmentId":null,"permissions":{"normal":["secret.read","secret.use"],"protected":["secret.use"]},"projectId":"91fdfd03-e573-48e4-b130-ffacf62bf716","role":"viewer","sensitive":true}],"targetCredentialId":"91d75aff-81c0-48db-9253-79f876395e79","via":{"clientId":"https://claude.ai/oauth/claude-code-client-metadata","clientName":"Claude Code","connectionId":"9b945b00-8351-44bb-a2c6-7d71f1e69f7d"}},"operationId":null,"places":{"environmentId":null,"projectId":null,"secretId":null,"versionId":null},"requestId":"b7c48630-b2e0-44c6-90df-7cc5ba97328f","sourceIp":null,"subject":null},"scope":[{"environmentId":null,"permissions":{"normal":["secret.read","secret.use"],"protected":["secret.use"]},"projectId":"91fdfd03-e573-48e4-b130-ffacf62bf716","role":"viewer","sensitive":true}]}';
const A1_PERSONAL_TOKEN = '{"caller":"person","expiresAt":1794537603877,"generation":0,"op":"credential.issue","principal":"user:admin@acme.example","ref":{"id":"16e59b7b-1cc7-4dd2-94e5-63ec39ec8a4a","kind":"credential"},"reported":{"action":"token.create","allowed":true,"author":"app","code":null,"credential":null,"detail":{"credentialId":"9b945b00-8351-44bb-a2c6-7d71f1e69f7d","expiresAt":"2026-11-13T02:40:03.877Z","kind":"personal","label":"agent","principalId":"admin@acme.example","principalType":"user","scope":[{"environmentId":null,"permissions":{"normal":["secret.read","secret.use"],"protected":["secret.use"]},"projectId":"91fdfd03-e573-48e4-b130-ffacf62bf716","role":"viewer"}],"targetCredentialId":"16e59b7b-1cc7-4dd2-94e5-63ec39ec8a4a","via":{"clientId":"https://claude.ai/oauth/claude-code-client-metadata","clientName":"Claude Code","connectionId":"9b945b00-8351-44bb-a2c6-7d71f1e69f7d"}},"operationId":null,"places":{"environmentId":null,"projectId":null,"secretId":null,"versionId":null},"requestId":"b7c48630-b2e0-44c6-90df-7cc5ba97328f","sourceIp":null,"subject":null},"scope":[{"environmentId":null,"permissions":{"normal":["secret.read","secret.use"],"protected":["secret.use"]},"projectId":"91fdfd03-e573-48e4-b130-ffacf62bf716","role":"viewer"}]}';

test("a carried entry's credential is its own, else its detail's, as audit_log's; its version the entry's where the change seals none", () => {
  const change = (payload: string, actor: string) => changeEvent({ tree: 'changes', number: 9n, at: 1, columns: [9n, randomUUID(), 'credential:c', actor, payload] });
  const CONNECTION = '9b945b00-8351-44bb-a2c6-7d71f1e69f7d';
  for (const [payload, actor, kind, label, issued] of [
    [A1_SERVICE_TOKEN, 'token:ci', 'service', 'deploy', '91d75aff-81c0-48db-9253-79f876395e79'],
    [A1_PERSONAL_TOKEN, 'user:admin@acme.example', 'personal', 'agent', '16e59b7b-1cc7-4dd2-94e5-63ec39ec8a4a'],
  ] as const) {
    const row = change(payload, actor);
    const detail = JSON.parse(String(row?.detail));
    assert.deepEqual(
      [row?.action, row?.author, row?.credential, row?.project, row?.version, detail.kind, detail.label, detail.targetCredentialId, detail.via.connectionId],
      ['token.create', 'app', CONNECTION, null, null, kind, label, issued, CONNECTION],
    );
  }
  // The entry's own credential wins over its detail's.
  const own = randomUUID();
  const parsed = JSON.parse(A1_SERVICE_TOKEN);
  assert.equal(change(canonical({ ...parsed, reported: { ...parsed.reported, credential: own } }), 'token:ci')?.credential, own);
  // A carried entry of a change that seals no version (not a key write) keeps the version its entry names.
  const named = randomUUID();
  const placed = { ...parsed, reported: { ...parsed.reported, places: { ...parsed.reported.places, versionId: named } } };
  assert.equal(change(canonical(placed), 'token:ci')?.version, named);
});

/** An event as `log_events` writes it, the vault's or the app's (note.ts), signed under the vault's log key. Its number. */
async function noted(input: Parameters<typeof eventRow>[2], author: 'app' | 'vault', at = Date.now()): Promise<bigint> {
  const row = eventRow(logMacKey(SIGNING_KEY), at, input, author);
  const [written] = await rows<{ n: string }>(db.vault, sql`SELECT (log_events(ARRAY[${row.requestId}]::text[], ARRAY[${row.at}]::bigint[],
    ARRAY[${row.actor}]::text[], ARRAY[${row.payload}]::text[], ARRAY[${row.mac}]::bytea[]))[1]::text AS n`);
  return BigInt(written!.n);
}

test("an event is listed from its payload once a checkpoint seals it: who decided its author, the row's actor and time; it records no write, and a rebuild lists it again", async () => {
  const tick = await signer();
  const nowhere = { projectId: null, environmentId: null, secretId: null, versionId: null };
  const [project, environment, secret, version, credential] = [randomUUID(), randomUUID(), randomUUID(), randomUUID(), randomUUID()];
  const linked = {
    id: randomUUID(), requestId: 'req-link', action: 'account.link', allowed: true, code: null, actor: ADA, subject: null, places: nowhere,
    credential, operationId: null, sourceIp: '203.0.113.7', detail: { provider: 'github', confirmedBy: 'passkey', confirmedAt: '2026-11-13T02:00:00.000Z' },
  };
  const refused = {
    id: randomUUID(), requestId: 'req-read', action: 'secret.read', allowed: false, code: 'no_grant', actor: `token:${credential}`, subject: null,
    places: { projectId: project, environmentId: environment, secretId: secret, versionId: version }, credential, operationId: randomUUID(), sourceIp: null, detail: { key: 'DB_URL' },
  };
  const finding = {
    id: findingEventId(null, 'late'), requestId: null, action: 'audit.check', allowed: false, code: 'late', actor: 'system:vault', subject: null, places: nowhere,
    credential: null, operationId: null, sourceIp: null, detail: {},
  };
  const numbers = [await noted(linked, 'app'), await noted(refused, 'vault'), await noted(finding, 'vault')];
  // The same event again: its first number, one row.
  assert.equal(await noted(linked, 'app'), numbers[0]);
  // Unsealed, nothing; sealed, each once.
  await projectAll();
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 15`), 0);
  await tick();
  await projectAll();
  const listed = await events(sql`log = 15`);
  const columns = (r: Row) => [String(r.number), r.author, r.action, r.allowed, r.code, r.actor, r.credential, r.project, r.environment, r.secret, r.version, r.request_id, r.operation_id, r.source_ip];
  assert.deepEqual(listed.map(columns), [
    [String(numbers[0]), 'app', 'account.link', true, null, ADA, credential, null, null, null, null, 'req-link', null, '203.0.113.7'],
    [String(numbers[1]), 'vault', 'secret.read', false, 'no_grant', `token:${credential}`, credential, project, environment, secret, version, 'req-read', refused.operationId, null],
    [String(numbers[2]), 'vault', 'audit.check', false, 'late', 'system:vault', null, null, null, null, null, null, null, null],
  ]);
  assert.deepEqual(JSON.parse(String(listed[0]!.detail)), linked.detail);
  assert.deepEqual([...(listed[1]!.places as string[])].sort(), [project, environment, secret].sort());
  const ring = alone(await keys());
  for (const r of listed) assert.ok(eventVouched(ring, eventOf(r)));
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_member_keys`), 0);
  // Replayed from the start, the same rows, and the rebuild's own.
  const before = listed.map((r) => `${String(r.number)}:${String(r.mac)}`);
  await callRebuild(db.vault, rebuildRow(logMacKey(SIGNING_KEY), { actor: ROOT, requestId: 'rebuild-events' }, Date.now()));
  await tick();
  await projectAll();
  const again = await events(sql`log = 15 AND action <> 'audit.rebuild'`);
  assert.deepEqual(again.map((r) => `${String(r.number)}:${String(r.mac)}`), before);
});

test("an event's payload under another object than its id's is no event, and lists nothing", () => {
  const id = randomUUID();
  const payload = canonical({
    action: 'secret.read', allowed: false, author: 'vault', code: 'no_grant', credential: null, detail: {}, op: 'event', operationId: null,
    places: { environmentId: null, projectId: null, secretId: null, versionId: null }, ref: { id, kind: 'event' }, requestId: null, sourceIp: null, subject: null,
  });
  assert.equal(changeEvent({ tree: 'changes', number: 7n, at: 1, columns: [7n, id, `secret:${randomUUID()}`, ADA, payload] }), null);
  assert.equal(changeEvent({ tree: 'changes', number: 7n, at: 1, columns: [7n, randomUUID(), eventObject(id), ADA, payload] }), null);
  assert.equal(changeEvent({ tree: 'changes', number: 7n, at: 1, columns: [7n, id, eventObject(id), ADA, payload] })?.author, 'vault');
});

test("an event with no credential or code of its own takes its detail's, as a carried entry does", () => {
  const [id, credential] = [randomUUID(), randomUUID()];
  const payload = canonical({
    action: 'secret.read', allowed: false, author: 'vault', code: null, credential: null, detail: { credentialId: credential, reason: 'no_grant' }, op: 'event',
    operationId: null, places: { environmentId: null, projectId: null, secretId: null, versionId: null }, ref: { id, kind: 'event' }, requestId: null, sourceIp: null, subject: null,
  });
  const event = changeEvent({ tree: 'changes', number: 7n, at: 1, columns: [7n, id, eventObject(id), ADA, payload] });
  assert.deepEqual([event?.credential, event?.code], [credential, 'no_grant']);
});

test('a projector another overtook writes nothing (the cursor no longer where its batch started)', async () => {
  await append(reads(4));
  await checkpoint14();
  const real = logStore(db.vault);
  let wrote: boolean | null = null;
  const paused = Object.assign(Object.create(real) as typeof real, {
    writeAudit: async (...args: Parameters<typeof real.writeAudit>) => {
      await projectAll();
      wrote = await real.writeAudit(...args);
      return wrote;
    },
  });
  await project({ steps: 1 }, paused);
  assert.equal(wrote, false);
  const [{ n, distinct }] = await rows<{ n: string; distinct: string }>(db.owner, sql`SELECT count(*) AS n, count(DISTINCT (log, number)) AS distinct FROM audit_events`);
  assert.equal(n, distinct);
});

test('a rebuild: its record names who asked; the tables empty and the cursor at the start, in one transaction; the projector lists the same rows again, and the record', async () => {
  const tick = await signer();
  const w = await world();
  const { use } = await isolate();
  assert.ok((await use(ask(w, await w.key()))).ok);
  await append(reads(3));
  await checkpoint14();
  await tick();
  await projectAll();
  const before = (await events()).map((r) => `${String(r.log)}:${String(r.number)}:${String(r.mac)}`);
  const keysBefore = await count(sql`SELECT count(*) AS n FROM audit_member_keys`);
  const asked = rebuildRow(logMacKey(SIGNING_KEY), { actor: ROOT, requestId: 'rebuild-1' }, Date.now());
  const number = await callRebuild(db.vault, asked);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events`), 0);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_cursor WHERE mac IS NULL AND through = 0 AND old_top = 0`), 1);
  // Asked again under the same request: its number, nothing reset again.
  await tick();
  await projectAll();
  assert.equal(await callRebuild(db.vault, asked), number);
  assert.ok(await count(sql`SELECT count(*) AS n FROM audit_events`) > 0);
  const again = await events();
  const record = again.filter((r) => r.action === 'audit.rebuild');
  assert.deepEqual(record.map((r) => [r.actor, String(r.number), r.allowed, r.shown]), [[ROOT, String(number), true, true]]);
  assert.deepEqual(again.filter((r) => r.action !== 'audit.rebuild').map((r) => `${String(r.log)}:${String(r.number)}:${String(r.mac)}`), before);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_member_keys`), keysBefore);
  // Any other payload under a rebuild's name is refused.
  await assert.rejects(callRebuild(db.vault, { ...asked, requestId: 'rebuild-2' }), (error: Error) => /names its op first and its own request/.test(String(error.cause)));
});

test("retention's drop of a day: its uses' rows and places go, and the summary keeps no read older than its end, even from a batch listed after", async () => {
  const tick = await signer();
  const w = await world();
  const { use } = await isolate();
  assert.ok((await use(ask(w, await w.key()))).ok);
  await tick();
  await projectAll();
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_member_keys`), 1);
  const today = new Date().toISOString().slice(0, 10);
  await run(db.vault, sql`SELECT drop_audit_day(${today}::date)`);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 16`), 0);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_event_places p WHERE NOT EXISTS (SELECT 1 FROM audit_events e WHERE (e.at, e.number, e.log) = (p.at, p.number, p.log))`), 0);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_member_keys`), 0);
  // A rebuild lists the use again (its day is still here, in this test), but not its read in the summary.
  await callRebuild(db.vault, rebuildRow(logMacKey(SIGNING_KEY), { actor: ROOT, requestId: randomUUID() }, Date.now()));
  await tick();
  await projectAll();
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_events WHERE log = 16`), 1);
  assert.equal(await count(sql`SELECT count(*) AS n FROM audit_member_keys`), 0);
});

test("a row a database writer planted under an entry's key is replaced by the projector's, and the places it named go with it", async () => {
  const tick = await signer();
  const w = await world();
  const { use } = await isolate();
  assert.ok((await use(ask(w, await w.key()))).ok);
  await tick();
  await projectAll();
  const [read] = await events(sql`log = 16`);
  assert.ok(read !== undefined && (read.places as string[]).length > 0);
  // Emptied, then the read's key taken first by a writer's row placing it in another project.
  await callRebuild(db.vault, rebuildRow(logMacKey(SIGNING_KEY), { actor: ROOT, requestId: randomUUID() }, Date.now()));
  const victim = randomUUID();
  await run(db.owner, sql`INSERT INTO audit_events (at, number, log, author, action, shown, allowed, actor, places, detail, mac)
    VALUES (${read.at}, ${read.number}, 16, 'vault', 'secret.read', true, true, ${read.actor}, ARRAY[${victim}]::uuid[], '{}', ${randomBytes(16)})`);
  await run(db.owner, sql`INSERT INTO audit_event_places (place, at, number, log) VALUES (${victim}, ${read.at}, ${read.number}, 16)`);
  await tick();
  await projectAll();
  const [again] = await events(sql`log = 16`);
  assert.deepEqual(eventOf(again!), eventOf(read));
  const placed = await rows<{ place: string }>(db.owner, sql`SELECT place FROM audit_event_places WHERE at = ${read.at} AND number = ${read.number} AND log = 16 ORDER BY place`);
  assert.deepEqual(placed.map((p) => p.place), [...(read.places as string[])].sort());
});
