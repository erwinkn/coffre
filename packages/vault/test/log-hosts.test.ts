// Where 0.15's checkpointer runs (docs/design/audit-tree.md): on Node, a
// process ticking every 500 ms with its memory in a synced file; on
// Workers, a Durable Object with its memory in the object's storage, the
// witness's object beside it, and an R2 archive. The objects run here on a
// state of the shape the runtime gives them, over the suite's database.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, beforeEach, test } from 'node:test';

import { decodePair, encodePair, leafHash, openPair, pairSigners, pairVerifiers, proveConsistency, signPair, verifyInclusion, type PairNotes } from '@coffre/core/merkle';

import { Checkpointer, logOrigin, type Witness } from '../src/checkpointer.ts';
import { keepCheckpointer, runCheckpointer } from '../src/checkpointer-node.ts';
import { checkpointerAlarms, checkpointerObject, checkpointerStatus, durableSealing, durableSealThrough, startCheckpointer, type ObjectNamespace, type ObjectState } from '../src/checkpointer-workers.ts';
import { logMacKey } from '../src/log-entry.ts';
import { durableWitness, r2Archive, witnessObject } from '../src/witness-workers.ts';
import { authentic, keys, MemoryStore, sealThroughDouble, variableMemory } from './audit-tree.ts';
import { ENGINE, openTestDatabase, rows, run, VAULT_URL, type TestDatabase } from './database.ts';
import { sql } from 'drizzle-orm';
import { logWriter } from './log-entries.ts';
import { stallProxy } from './stall-proxy.ts';
import { isUnsealed } from '@coffre/core/vault';

let db: TestDatabase;
let seed: Buffer;
let log: ReturnType<typeof logWriter>;
let dir: string;

before(async () => {
  db = await openTestDatabase();
  seed = randomBytes(32);
  // One connection on SQLite, as a deployment has: two to one file would wait on each other's writes.
  log = logWriter(ENGINE === 'sqlite' ? db.vault : db.owner, logMacKey(seed));
  await log.days();
  dir = mkdtempSync(join(tmpdir(), 'coffre-checkpointer-'));
});
after(async () => {
  await db?.close();
  rmSync(dir, { recursive: true, force: true });
});
beforeEach(() => log.empty());

const until = async (done: () => boolean, ms = 5000) => {
  const end = Date.now() + ms;
  while (!done()) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
};

/** A Durable Object's state, as the runtime gives one: storage that reads its own writes, an alarm, and the gate. */
function objectState(): ObjectState & { alarm: number | null; data: Map<string, unknown>; syncs: number } {
  const data = new Map<string, unknown>();
  const state = {
    alarm: null as number | null,
    data,
    syncs: 0,
    storage: {
      get: async <T>(key: string) => data.get(key) as T | undefined,
      put: async <T>(key: string, value: T) => void data.set(key, value),
      sync: async () => void (state.syncs += 1),
      delete: async (keys: string[]) => keys.filter((k) => data.delete(k)).length,
      list: async <T>(o: { prefix: string; start?: string; end?: string; limit?: number }) =>
        new Map([...data].filter(([k]) => k.startsWith(o.prefix) && (o.start === undefined || k >= o.start) && (o.end === undefined || k < o.end))
          .sort(([a], [b]) => (a < b ? -1 : 1)).slice(0, o.limit) as [string, T][]),
      getAlarm: async () => state.alarm,
      setAlarm: async (at: number) => void (state.alarm = at),
    },
    // Nothing else delivered while the work runs, as the runtime holds a Durable Object's other events.
    blockConcurrencyWhile: <T>(work: () => Promise<T>): Promise<T> => {
      const done = gate.then(work);
      gate = done.catch(() => {});
      return done;
    },
  };
  let gate: Promise<unknown> = Promise.resolve();
  return state;
}

/** A namespace holding one object, as a binding reaches it. */
const namespaceOf = (object: { fetch(request: Request): Promise<Response> }): ObjectNamespace => ({ idFromName: (name) => name, get: () => object });

test('on Node: ticks every interval, a change sealed through it, its memory a synced file, an alarm kept once', async () => {
  const memory = join(dir, `memory-${randomBytes(4).toString('hex')}`);
  let forged = 0n;
  const running = await runCheckpointer({ database: db.vault, seed, memory, intervalMs: 20 });
  try {
    for (let i = 0; i < 5; i += 1) await log.use();
    const change = await log.change();
    await until(() => running.checkpointer.pair.pair.upto >= change);
    assert.equal(decodePair(readFileSync(memory, 'utf8'))!.uses, running.checkpointer.pair.notes.uses, 'the file holds the pair');
    const next = await log.change();
    const sealed = await running.sealThrough(next);
    assert.equal(sealed.proof.tree, 'changes');
    assert.ok(verifyInclusion(leafHash(sealed.proof.leaf), sealed.proof.index, sealed.proof.size, sealed.proof.proof, sealed.pair.changes.root));
    // A forged entry: refused on every tick, alarmed once.
    forged = await log.use(Date.now(), true);
    await new Promise((resolve) => setTimeout(resolve, 200));
    const alarms = await running.alarms();
    assert.equal(alarms.filter((a) => /MAC does not hold/.test(a.message)).length, 1, JSON.stringify(alarms));
  } finally {
    await running.stop();
  }
  // Started again over the same file and database, the forged entry gone: the memory and the rows agree, and it seals on.
  await run(ENGINE === 'sqlite' ? db.vault : db.owner, sql`DELETE FROM log_uses WHERE number = ${forged}`);
  const again = await runCheckpointer({ database: db.vault, seed, memory, intervalMs: 20 });
  try {
    const n = await log.change();
    assert.equal((await again.sealThrough(n)).proof.number, n);
  } finally {
    await again.stop();
  }
});

test("on Node, as the vault keeps it: a refused open is one alarm, a change's seal fails with why, and it opens once the log is put right", async () => {
  // Another signer's genesis in the database: this signer refuses it, as it refuses a restore made under another key.
  const other = await runCheckpointer({ database: db.vault, seed: randomBytes(32), memory: join(dir, `other-${randomBytes(4).toString('hex')}`), intervalMs: 3_600_000 });
  await other.stop();
  const memory = join(dir, `kept-${randomBytes(4).toString('hex')}`);
  const kept = await keepCheckpointer({ database: db.vault, seed, memory, intervalMs: 20, retryMs: 50 });
  try {
    const change = await log.change();
    await assert.rejects(kept.sealThrough(change), /the checkpointer cannot open: .*not a pair signed by this log/);
    await new Promise((resolve) => setTimeout(resolve, 200));
    const alarms = await kept.alarms();
    assert.equal(alarms.filter((a) => /cannot open/.test(a.message)).length, 1, JSON.stringify(alarms));
    assert.deepEqual(await kept.heldOutside(), [], 'it signed nothing');
    // The other signer's log gone: the next try opens over it, and seals.
    await log.empty();
    for (let waited = 0; ; waited += 25) {
      const n = await log.change();
      const sealed = await kept.sealThrough(n).catch(() => null);
      if (sealed !== null) {
        assert.equal(sealed.proof.number, n);
        break;
      }
      assert.ok(waited < 5000, 'it never opened');
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal((await kept.heldOutside()).length, 1, 'the pair it signed, in its file');
  } finally {
    await kept.stop();
  }
});

test('on Workers: the checkpointer\'s object ticks on its alarm, keeps its memory and alarms in its storage, and seals a change asked of it', { skip: ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive' }, async () => {
  const state = objectState();
  const Checkpointer_ = checkpointerObject(() => ({ hyperdrive: { connectionString: VAULT_URL }, seed, closeIdleMs: 50 }));
  const object = new Checkpointer_(state, {});
  const namespace = namespaceOf(object);
  await startCheckpointer(namespace);
  assert.ok(state.alarm !== null, 'its alarm set');
  for (let i = 0; i < 3; i += 1) await log.use();
  await object.alarm();
  assert.ok(decodePair(state.data.get('pair') as string), 'the memory is the object\'s storage');
  const change = await log.change();
  const sealed = await durableSealThrough(namespace)(change);
  assert.equal(sealed.proof.number, change);
  assert.equal(sealed.witnessed, null);
  const verifiers = await pairVerifiers(await signerKeys(seed));
  assert.ok(await openPair(sealed.notes, verifiers), 'notes the vault\'s keys signed');
  await log.use(Date.now(), true);
  await object.alarm();
  const alarms = await checkpointerAlarms(namespace);
  assert.ok(alarms.some((a) => /MAC does not hold/.test(a.message)), JSON.stringify(alarms));
});

async function signerKeys(s: Uint8Array) {
  const signers = await pairSigners(await logOrigin(s), s);
  return { changes: signers.changes.verifierKey, uses: signers.uses.verifierKey };
}

test('the witness\'s object cosigns pairs that extend its own, refuses a fork, and its client resends from the sizes it holds', async () => {
  const k = await keys(3);
  const store = new MemoryStore(k.macKey);
  const Witness_ = witnessObject(() => ({ name: 'witness.test', key: Buffer.alloc(32, 9).toString('base64'), log: { changes: k.signers.changes.verifierKey, uses: k.signers.uses.verifierKey } }));
  const object = new Witness_(objectState(), {});
  const witness = durableWitness(namespaceOf(object));
  const cp = await Checkpointer.open(store, k.signers, { memory: variableMemory(), authentic: authentic(k.macKey), witnesses: [witness] });
  for (let i = 0; i < 300; i += 1) store.append('uses', `u-${i}`);
  const s = await cp.sealThrough(store.append('changes', 'c'));
  assert.equal(s.witnessed, true, s.failures.join());
  assert.equal(s.cosigned.length, 1);
  assert.ok(s.cosigned[0]!.changes.includes(`— witness.test `), 'cosigned by the witness');
  // A second client, holding no sizes: the object answers 409 with its own, and the client resends from them.
  const other = durableWitness(namespaceOf(object));
  for (let i = 0; i < 10; i += 1) store.append('uses', `v-${i}`);
  await cp.tick();
  const answer = await other.publish(cp.pair.notes, async (from) => ({
    changes: await proveConsistency(store, 'changes', from.changes, cp.pair.pair.changes.size),
    uses: await proveConsistency(store, 'uses', from.uses, cp.pair.pair.uses.size),
  }), new AbortController().signal);
  assert.ok(answer.ok, JSON.stringify(answer));
  // A fork: a pair the object cannot be shown to extend, refused, and its pair held kept.
  const fork = await signPair(k.signers, cp.pair.pair.upto + 1n, cp.pair.pair.at, { changes: cp.pair.pair.changes, uses: { size: cp.pair.pair.uses.size + 1, root: Buffer.alloc(32, 1) } }, cp.pair.pair.floor);
  const refused = await other.publish(fork.notes, async () => ({ changes: [], uses: [Buffer.alloc(32)] }), new AbortController().signal);
  assert.ok(!refused.ok && /split view/.test(refused.reason), JSON.stringify(refused));
});

test('review r1: the witness\'s object cosigns one of two forks sent at once, never both', async () => {
  const k = await keys(6);
  const Witness_ = witnessObject(() => ({ name: 'witness.test', key: Buffer.alloc(32, 9).toString('base64'), log: { changes: k.signers.changes.verifierKey, uses: k.signers.uses.verifierKey } }));
  const object = new Witness_(objectState(), {});
  const heads = (root: number) => ({ changes: { size: 1, root: Buffer.alloc(32, 1) }, uses: { size: 1, root: Buffer.alloc(32, root) } });
  const [a, b] = await Promise.all([signPair(k.signers, 5n, 1, heads(2)), signPair(k.signers, 5n, 1, heads(3))]);
  const send = (notes: PairNotes) => object.fetch(new Request('https://witness/', { method: 'POST', body: JSON.stringify({ notes, from: { changes: 0, uses: 0 }, proofs: { changes: [], uses: [] } }) }));
  const answers = await Promise.all([send(a.notes), send(b.notes)]);
  assert.deepEqual(answers.map((r) => r.status).sort(), [200, 409], 'the second finds the first one\'s pair held');
});

test('the witness\'s client hands the abort to the object\'s request', async () => {
  let seen: AbortSignal | null = null;
  const hanging = { fetch: (request: Request) => ((seen = request.signal), new Promise<Response>(() => {})) };
  const abort = new AbortController();
  const publishing = durableWitness(namespaceOf(hanging)).publish({ changes: '', uses: '' }, async () => ({ changes: [], uses: [] }), abort.signal);
  abort.abort();
  assert.ok(seen !== null && (seen as AbortSignal).aborted, 'the request is aborted with the try');
  void publishing.catch(() => {});
});

test('the R2 archive keeps every pair once, takes the same pair again, and refuses another at its place', async () => {
  const objects = new Map<string, string>();
  // Under a bucket lock, a put over an object already there fails, rather than answering null.
  const bucket = {
    put: async (key: string, value: string, o?: { onlyIf?: { etagDoesNotMatch?: string } }) => {
      if (o?.onlyIf?.etagDoesNotMatch === '*' && objects.has(key)) throw new Error('This object is locked');
      objects.set(key, value);
      return {};
    },
    get: async (key: string) => (objects.has(key) ? { text: async () => objects.get(key)! } : null),
  };
  const k = await keys(4);
  const archive: Witness = r2Archive(bucket);
  const heads = { changes: { size: 1, root: Buffer.alloc(32, 1) }, uses: { size: 2, root: Buffer.alloc(32, 2) } };
  const a = await signPair(k.signers, 7n, 1, heads);
  const noProofs = async () => ({ changes: [], uses: [] });
  assert.deepEqual(await archive.publish(a.notes, noProofs, new AbortController().signal), { ok: true });
  assert.ok(objects.has('audit/00000000000000000007.json'));
  assert.deepEqual(await archive.publish(a.notes, noProofs, new AbortController().signal), { ok: true });
  const b: { notes: PairNotes } = await signPair(k.signers, 7n, 2, heads);
  const refused = await archive.publish(b.notes, noProofs, new AbortController().signal);
  assert.ok(!refused.ok && /another pair up to 7/.test(refused.reason));
  assert.equal(objects.get('audit/00000000000000000007.json'), encodePair(a.notes));
});

test('the change path\'s seam has a stand-in for its tests: the numbers asked, each answered as told', async () => {
  const k = await keys(5);
  const store = new MemoryStore(k.macKey);
  const cp = await Checkpointer.open(store, k.signers, { memory: variableMemory(), authentic: authentic(k.macKey) });
  const real = await cp.sealThrough(store.append('changes', 'c'));
  const double = sealThroughDouble((n) => (n === 2n ? new Error('change 2 is not in the signed changes tree') : { ...real, witnessed: false, failures: ['witness w: no answer within 2000 ms'] }));
  assert.equal((await double(1n)).witnessed, false);
  await assert.rejects(double(2n), /not in the signed changes tree/);
  assert.deepEqual(double.asked, [1n, 2n]);
});

test('Fable review: the object remembers durably, keeps a refused open and a failed tick as alarms, once each', { skip: ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive' }, async () => {
  const state = objectState();
  const Checkpointer_ = checkpointerObject(() => ({ hyperdrive: { connectionString: VAULT_URL }, seed, closeIdleMs: 50 }));
  const first = new Checkpointer_(state, {});
  await startCheckpointer(namespaceOf(first));
  await log.use();
  const synced = state.syncs;
  await first.alarm();
  assert.ok(state.syncs > synced, 'the pair synced before the database had it');
  // A tile changed under the signer: the next write fails, an alarm, kept once however many ticks fail.
  for (let i = 0; i < 300; i += 1) await log.use();
  await first.alarm();
  await run(db.owner, sql`UPDATE log_tiles SET hashes = ${randomBytes(64)} WHERE tree = 'uses' AND level = 0`);
  await log.use();
  for (let i = 0; i < 3; i += 1) await first.alarm();
  let alarms = await checkpointerAlarms(namespaceOf(first));
  assert.equal(alarms.filter((a) => /a checkpoint failed: .*shrink or change/s.test(a.message)).length, 1, JSON.stringify(alarms));
  // Evicted, then the database's rows gone: the next open is refused, kept as an alarm, and the object stays up.
  await log.empty();
  const second = new Checkpointer_(state, {});
  for (let i = 0; i < 2; i += 1) await second.alarm();
  alarms = await checkpointerAlarms(namespaceOf(second));
  assert.equal(alarms.filter((a) => /cannot open: .*holds no checkpoint/.test(a.message)).length, 1, JSON.stringify(alarms));
  assert.ok(state.alarm !== null, 'its alarm still set');
  await assert.rejects(durableSealThrough(namespaceOf(second))(1n), /cannot open/);
});

test('Fable review: a witness whose held pair no longer opens refuses, rather than starting over', async () => {
  const k = await keys(7);
  const other = await keys(8);
  const state = objectState();
  const make = (log: typeof k) => witnessObject(() => ({ name: 'witness.test', key: Buffer.alloc(32, 9).toString('base64'), log: { changes: log.signers.changes.verifierKey, uses: log.signers.uses.verifierKey } }));
  const heads = { changes: { size: 1, root: Buffer.alloc(32, 1) }, uses: { size: 1, root: Buffer.alloc(32, 2) } };
  const first = await signPair(k.signers, 5n, 1, heads);
  const send = (object: { fetch(r: Request): Promise<Response> }, notes: PairNotes, from = { changes: 0, uses: 0 }) =>
    object.fetch(new Request('https://witness/', { method: 'POST', body: JSON.stringify({ notes, from, proofs: { changes: [], uses: [] } }) }));
  assert.equal((await send(new (make(k))(state, {}), first.notes)).status, 200);
  // The deployment's settings now name other keys: the pair held does not open under them.
  const answer = await send(new (make(other))(state, {}), (await signPair(other.signers, 9n, 2, heads)).notes);
  assert.equal(answer.status, 500);
  assert.match(((await answer.json()) as { reason: string }).reason, /name a new witness/);
  // Through its client, as the checkpointer publishes: a failed try with that reason, again on the next, never a crash.
  const client = durableWitness(namespaceOf(new (make(other))(state, {})));
  for (let i = 0; i < 2; i += 1) {
    const refused = await client.publish((await signPair(other.signers, 9n, 2, heads)).notes, async () => ({ changes: [], uses: [] }), new AbortController().signal);
    assert.ok(!refused.ok && /name a new witness/.test(refused.reason), JSON.stringify(refused));
  }
  // A record damaged past parsing: refused from inside the gate, the object up.
  state.data.set('pair', 'not json');
  const damaged = await send(new (make(k))(state, {}), first.notes);
  assert.equal(damaged.status, 500);
  assert.match(((await damaged.json()) as { reason: string }).reason, /name a new witness/);
});

test('T119, item 3: a reset over a seal in flight: the seal fails rather than sign beside the next checkpointer, and the next seal opens one', { skip: ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive' }, async () => {
  const state = objectState();
  const Checkpointer_ = checkpointerObject(() => ({ hyperdrive: { connectionString: VAULT_URL }, seed, closeIdleMs: 50 }));
  const object = new Checkpointer_(state, {});
  const namespace = namespaceOf(object);
  await startCheckpointer(namespace);
  for (let i = 0; i < 300; i += 1) await log.use();
  await object.alarm();
  // The partial leaf tile changed by a writer: every write that grows it fails, the alarm's tick's and the seal's.
  const [edge] = await rows<{ leaf: string; hashes: Buffer }>(db.owner, sql`SELECT leaf::text AS leaf, hashes FROM log_tiles WHERE tree = 'uses' AND level = 0 ORDER BY leaf DESC LIMIT 1`);
  await run(db.owner, sql`UPDATE log_tiles SET hashes = ${randomBytes(edge!.hashes.length)} WHERE tree = 'uses' AND level = 0 AND leaf = ${BigInt(edge!.leaf)}`);
  await log.use();
  const change = await log.change();
  // The alarm's tick fails and resets the object while the seal waits on a tick of the same checkpointer: whichever runs
  // first, the seal fails (its write refused, or its checkpointer closed under it, its connection cut: not sealed in
  // time, T169), and none signs after the reset.
  const alarming = object.alarm();
  const sealing = durableSealThrough(namespace)(change);
  await assert.rejects(sealing, /the checkpointer failed: (Failed query: SELECT write_checkpoint|this checkpointer was closed|change \d+ was committed, but not sealed in time)/);
  await alarming;
  const [rowsBefore] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_checkpoints`);
  // The tile put back: the next seal opens a checkpointer, which finishes the pair the old one remembered, and seals.
  await run(db.owner, sql`UPDATE log_tiles SET hashes = ${edge!.hashes} WHERE tree = 'uses' AND level = 0 AND leaf = ${BigInt(edge!.leaf)}`);
  const sealed = await durableSealThrough(namespace)(change);
  assert.equal(sealed.proof.number, change);
  const [rowsAfter] = await rows<{ n: number }>(db.owner, sql`SELECT count(*) AS n FROM log_checkpoints`);
  assert.ok(Number(rowsAfter!.n) > Number(rowsBefore!.n));
  assert.equal(state.data.get('pair'), encodePair(sealed.notes), 'one signer: its memory is the pair that sealed the change');
  const alarms = await checkpointerAlarms(namespace);
  assert.equal(alarms.filter((a) => /a checkpoint failed/.test(a.message)).length, 1, JSON.stringify(alarms));
});

test('review r3: with the database unreachable, the object keeps one alarm for each failure while it stands, however many ticks', async () => {
  const state = objectState();
  const Checkpointer_ = checkpointerObject(() => ({ hyperdrive: { connectionString: 'postgresql://nobody:nothing@127.0.0.1:1/none' }, seed, closeIdleMs: 50 }));
  const object = new Checkpointer_(state, {});
  for (let i = 0; i < 4; i += 1) await object.alarm();
  const alarms = await checkpointerAlarms(namespaceOf(object));
  assert.equal(alarms.filter((a) => /cannot open/.test(a.message)).length, 1, JSON.stringify(alarms));
  assert.equal(alarms.filter((a) => /the next days of uses were not made/.test(a.message)).length, 1, JSON.stringify(alarms));
  assert.equal(alarms.length, 2, JSON.stringify(alarms));
});

test('T169, Workers: the object\'s connection stops answering under a tick: its alarm ends within its bound, the checkpointer replaced, a change answers unsealed, readiness red; answered again, its next alarm seals', { skip: ENGINE === 'postgres' ? false : 'Postgres only: Hyperdrive', timeout: 60_000 }, async () => {
  const proxy = await stallProxy(VAULT_URL);
  const state = objectState();
  const Checkpointer_ = checkpointerObject(() => ({ hyperdrive: { connectionString: proxy.url }, seed, closeIdleMs: 60_000, tickBoundMs: 300 }));
  const object = new Checkpointer_(state, {});
  const namespace = namespaceOf(object);
  try {
    await startCheckpointer(namespace);
    await log.use();
    await object.alarm();
    assert.deepEqual(await durableSealing(namespace)(), { ok: true });
    // Its one connection goes dead: nothing answers, nothing is closed, and a connect gets no answer either.
    proxy.hold();
    const change = await log.change();
    let t0 = Date.now();
    await object.alarm();
    assert.ok(Date.now() - t0 < 2000, `the alarm ended after ${Date.now() - t0} ms`);
    assert.ok(state.alarm !== null, 'the next alarm set');
    assert.equal((await checkpointerStatus(namespace)).open, false, 'the stalled checkpointer was replaced');
    const sealing = await durableSealing(namespace)();
    assert.ok(!sealing.ok && /stalled/.test(sealing.reason), JSON.stringify(sealing));
    // A change's seal: the object tries to open another, which gets no answer either: unsealed, the app's 503.
    t0 = Date.now();
    await assert.rejects(durableSealThrough(namespace)(change), (error: Error) => isUnsealed(error));
    assert.ok(Date.now() - t0 < 2000, `unsealed after ${Date.now() - t0} ms`);
    // Answered again: the next alarm opens another over a connection of its own and seals the change.
    proxy.release();
    await object.alarm();
    await object.alarm();
    assert.deepEqual(await durableSealing(namespace)(), { ok: true });
    const sealed = await durableSealThrough(namespace)(change);
    assert.equal(sealed.proof.number, change);
    assert.equal(state.data.get('pair'), encodePair(sealed.notes), 'one signer: its memory the pair that sealed the change');
    const alarms = await checkpointerAlarms(namespace);
    assert.ok(alarms.some((a) => /a checkpoint failed: .*stalled/.test(a.message)), JSON.stringify(alarms));
    assert.deepEqual(alarms.filter((a) => /floor/.test(a.message)), []);
  } finally {
    proxy.release();
    await proxy.close();
  }
});
