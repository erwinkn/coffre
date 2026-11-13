import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { inclusionProof, leafHash, nodesFrom, tileMap, verifyInclusion } from '@coffre/core/log';
import { rowsOf } from '@coffre/db/dialect';
import { principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { change, drop, part, put } from '../src/change.ts';
import { pending, type Pending } from '../src/entry.ts';
import { checked } from '../src/rows.ts';
import { headText, Signer, type Finding, type Store } from '../src/signer.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { principal, user } from './world.ts';

/**
 * The signer against a database writer, on Postgres: each protection of
 * formal/quint/log.qnt as the scenario its variant fails on, and what the
 * model leaves out (the trees, the batch, a signer that was away).
 */
const vault = await openTestVault();
after(() => vault.close());

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const named = (id: string) => JSON.stringify(['principals', id]);

/** The signer's storage, in memory: what a Durable Object's is in a deployment. */
function memory() {
  const kept = new Map<string, unknown>();
  return {
    kept,
    down: false,
    read: async () => structuredClone(kept),
    async write(changes: ReadonlyMap<string, unknown>) {
      if (this.down) throw new Error('storage is down');
      for (const [key, value] of structuredClone(changes)) if (value === undefined) kept.delete(key);
      else kept.set(key, value);
    },
  } satisfies Store & Record<string, unknown>;
}
let store: ReturnType<typeof memory>;
let signer: Signer;
const open = () => Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store });

beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.woken.length = 0;
  store = memory();
  signer = await open();
});

/** The vault tells the signer of what it committed, as it does after each commit. */
async function told(): Promise<void> {
  for (const hash of vault.woken.splice(0)) await signer.wake(hash);
}
/** Told of everything, then one run: what it found. */
async function run(full = true): Promise<Finding[]> {
  await told();
  return (await signer.run(full)).findings;
}
const kinds = (findings: Finding[]) => findings.map((each) => each.found).sort();

/** A change of one member's row: admitted or given a role, or with null removed. */
async function member(id: string, role: string | null): Promise<void> {
  const result = await change(vault, {
    read: { found: part(principals, sql`id = ${id}`) },
    decide: ({ found: [was] }) => ({
      writes: [role === null ? drop(principals, was!) : put(principals, principal(id, { role }), was ?? null)],
      entry: { kept: true, action: 'member.role', actor: null, credential: null, request: null, ip: null, objects: [`principal:${id}`], detail: {} },
      answer: null,
    }),
  });
  assert.ok('answer' in result);
}

/** A use's entry, under the tree that ages out, with no row. */
const reading = (key: string): Pending => pending(vault.keys[0]!, { kept: false, action: 'secret.read', actor: ada, credential: null, request: null, ip: null, objects: [`secret:${key}`], detail: {} }, vault.now(), []);
/** Entries committed as a use commits one, and the vault's word of each. */
async function wait(...entries: Pending[]): Promise<void> {
  const rows = JSON.stringify(entries.map(({ kept, body, mac }) => ({ kept, body, mac: mac.toString('hex') })));
  await vault.db.execute(sql`INSERT INTO log_pending (kept, body, mac) SELECT kept, body, decode(mac, 'hex') FROM jsonb_to_recordset(${rows}::jsonb) AS t(kept boolean, body text, mac text)`);
  for (const { hash } of entries) vault.wake(hash);
}

const logged = () => rowsOf<{ seq: number; kept: boolean; leaf: number; action: string }>(vault.owner, sql`SELECT seq::int, kept, leaf::int, body::jsonb ->> 'action' AS action FROM log ORDER BY seq`);
const waiting = async () => (await rowsOf<{ n: number }>(vault.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0]!.n;

/** The head is the vault's, and every entry in the log proves against it from the tiles as stored. */
async function proven(): Promise<void> {
  const [head] = await rowsOf<{ size: number; keptSize: number; keptRoot: string; agingSize: number; agingRoot: string; agingFrom: number; signedAt: number; mac: Buffer }>(
    vault.owner,
    sql`SELECT size::int, kept_size::int AS "keptSize", encode(kept_root, 'hex') AS "keptRoot", aging_size::int AS "agingSize", encode(aging_root, 'hex') AS "agingRoot", aging_from::int AS "agingFrom", (extract(epoch FROM signed_at) * 1000)::float8 AS "signedAt", mac FROM log_head`,
  );
  assert.ok(head !== undefined && checked(vault.keys, (key) => key.entries, headText(head), head.mac) !== undefined, 'the head is under the vault\'s MAC');
  for (const kept of [true, false]) {
    const [size, root] = kept ? [head.keptSize, head.keptRoot] : [head.agingSize, head.agingRoot];
    const nodes = nodesFrom(tileMap(await rowsOf<{ level: number; index: number; hashes: Buffer }>(vault.owner, sql`SELECT level::int, number::int AS index, hashes FROM log_tiles WHERE kept = ${kept}`)));
    const entries = await rowsOf<{ leaf: number; body: string }>(vault.owner, sql`SELECT leaf::int, body FROM log WHERE kept = ${kept} ORDER BY leaf`);
    assert.deepEqual(entries.map((entry) => entry.leaf), Array.from({ length: size }, (_, leaf) => leaf));
    for (const { leaf, body } of entries) assert.ok(verifyInclusion(leafHash(Buffer.from(body)), leaf, size, inclusionProof(nodes, leaf, size), Buffer.from(root, 'hex')), `leaf ${leaf}`);
  }
}

test('entries are numbered in the order written, each under its tree, and every one proves against the signed head', async () => {
  await member(ada, 'owner');
  await wait(reading('a'));
  await member(bo, 'member');
  await wait(reading('b'));
  await member(bo, 'owner');
  assert.deepEqual(await run(), []);
  assert.deepEqual(await logged(), [
    { seq: 0, kept: true, leaf: 0, action: 'member.role' },
    { seq: 1, kept: false, leaf: 0, action: 'secret.read' },
    { seq: 2, kept: true, leaf: 1, action: 'member.role' },
    { seq: 3, kept: false, leaf: 1, action: 'secret.read' },
    { seq: 4, kept: true, leaf: 2, action: 'member.role' },
  ]);
  assert.equal(await waiting(), 0);
  // One row of the index per object an entry mentions.
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT object, seq::int FROM log_index ORDER BY seq`), [`principal:${ada}`, 'secret:a', `principal:${bo}`, 'secret:b', `principal:${bo}`].map((object, seq) => ({ object, seq })));
  await proven();
  // The rows are what the entries say, and stay so: a run with nothing new finds nothing, and writes no head.
  assert.deepEqual(await run(), []);
  await member(bo, null);
  assert.deepEqual(await run(), []);
  await proven();
});

test('a signer that was away takes what waited for it; an entry put back is refused, whether it remembers signing it or not', async () => {
  await member(ada, 'owner');
  vault.tick(60 * 60_000);
  assert.deepEqual(await run(), []);
  assert.equal((await logged()).length, 1);

  await member(bo, 'member');
  const [signed] = await rowsOf<{ body: string; mac: string }>(vault.owner, sql`SELECT body, encode(mac, 'hex') AS mac FROM log_pending`);
  const putBack = () => vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (true, ${signed!.body}, decode(${signed!.mac}, 'hex'))`);
  assert.deepEqual(await run(), []);
  // Put back at once, twice over: it remembers signing it, and the second is the first again.
  await putBack();
  await putBack();
  assert.deepEqual(kinds(await run()), ['replayed', 'replayed']);
  // Put back once it has forgotten: dated before anything it would take.
  vault.tick(60_001);
  assert.deepEqual(await run(), []);
  await putBack();
  assert.deepEqual(kinds(await run()), ['stale']);
  assert.deepEqual([(await logged()).length, await waiting()], [2, 0]);
  // A twin beside an entry not yet signed: one is taken.
  await wait(reading('a'));
  await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) SELECT kept, body, mac FROM log_pending`);
  assert.deepEqual(kinds(await run()), ['replayed']);
  assert.deepEqual([(await logged()).length, await waiting()], [3, 0]);
  await proven();
});

test('an entry gone before it was signed is missed, because the vault told of it', async () => {
  await member(ada, 'owner');
  await member(bo, 'member');
  await vault.owner.execute(sql`DELETE FROM log_pending WHERE body::jsonb -> 'objects' ->> 0 = ${`principal:${bo}`}`);
  const hash = vault.woken[1]!.toString('hex');
  assert.deepEqual(await run(false), [{ found: 'missing', of: hash }]);
  // Said once. And Bo's row is there with no entry that says so, which the full run finds.
  assert.deepEqual(await run(false), []);
  assert.deepEqual(await run(), [{ found: 'row', of: named(bo) }]);
});

test('a change that replaced a MAC the mirror does not hold is false history', async () => {
  await member(bo, 'member');
  assert.deepEqual(await run(), []);
  // The writer removes Bo. Ada sees him gone and admits him again: an entry that says there was nobody.
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  await member(bo, 'member');
  assert.deepEqual(await run(), [{ found: 'rewritten', of: named(bo) }]);
});

test('the full run finds a row put back, one deleted, one written behind the vault, and a log cut short; a quick run looks at none', async () => {
  await member(bo, 'owner');
  const [{ mac }] = (await rowsOf<{ mac: string }>(vault.owner, sql`SELECT encode(mac, 'hex') AS mac FROM principals`)) as [{ mac: string }];
  await member(bo, 'member');
  await member(ada, 'member');
  assert.deepEqual(await run(), []);
  // Bo's row as it was when he was an Owner, MAC and all: a genuine row, and not the one the entries say.
  await vault.owner.execute(sql`UPDATE principals SET role = 'owner', mac = decode(${mac}, 'hex') WHERE id = ${bo}`);
  assert.deepEqual(await run(false), []);
  assert.deepEqual(await run(), [{ found: 'row', of: named(bo) }]);
  await vault.owner.insert(principals).values(principal(cy));
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${ada}`);
  await vault.owner.execute(sql`DELETE FROM log WHERE seq = 2`);
  assert.deepEqual(await run(false), []);
  assert.deepEqual(await run(), [{ found: 'row', of: named(bo) }, { found: 'row', of: named(cy) }, { found: 'row', of: named(ada) }, { found: 'cut', of: 'kept' }]);
});

test('an entry told of during a run, or after it was signed, raises nothing', async () => {
  await member(ada, 'owner');
  await told();
  const snapshot = await signer.read(true);
  // Committed and told of after the read: not in it, and not missed. Its row is not in the read either.
  await member(bo, 'member');
  await told();
  assert.deepEqual([...(await signer.sign(snapshot)), ...(await signer.move())], []);
  assert.deepEqual(await run(), []);
  // The signer's own run takes an entry before the vault's word of it arrives.
  await member(cy, 'member');
  assert.deepEqual((await signer.run(true)).findings, []);
  assert.deepEqual(await run(), []);
  assert.equal((await logged()).length, 3);
});

test('a run that died before its move, or before it could say it had moved, is finished by the next signer, once', async () => {
  await member(ada, 'owner');
  await wait(reading('a'));
  await told();
  assert.deepEqual(await signer.sign(await signer.read(true)), []);
  signer = await open();
  assert.deepEqual(await run(), []);
  assert.equal((await logged()).length, 2);

  await member(bo, 'member');
  await told();
  const [waited] = await rowsOf<{ body: string; mac: string }>(vault.owner, sql`SELECT body, encode(mac, 'hex') AS mac FROM log_pending`);
  await signer.sign(await signer.read(false));
  const before = structuredClone(store.kept);
  assert.deepEqual(await signer.move(), []);
  store.kept.clear();
  for (const [key, value] of before) store.kept.set(key, value);
  signer = await open();
  assert.deepEqual(await run(), []);
  assert.deepEqual((await logged()).map((entry) => entry.seq), [0, 1, 2]);
  await proven();
  // What it signed, the next signer remembers: an entry put back across the restart is not signed again.
  await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (true, ${waited!.body}, decode(${waited!.mac}, 'hex'))`);
  assert.deepEqual(kinds(await run()), ['replayed']);
  assert.equal((await logged()).length, 3);

  // A signer whose storage refused a write has a memory its storage lacks: it does nothing more.
  await member(cy, 'member');
  store.down = true;
  await assert.rejects(told(), /storage is down/);
  store.down = false;
  await assert.rejects(signer.run(true), /open another/);
  signer = await open();
  assert.deepEqual((await signer.run(true)).findings, []);
  assert.equal((await logged()).length, 4);
});

test('an entry that is nobody\'s is refused and removed; one changed between its signing and its move is lost, and said so', async () => {
  await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (true, '{"action":"member.role"}', decode(${'00'.repeat(36)}, 'hex'))`);
  assert.deepEqual(await run(), [{ found: 'forged', of: 'pending:1' }]);
  assert.deepEqual([await logged(), await waiting()], [[], 0]);

  await member(ada, 'owner');
  await told();
  assert.deepEqual(await signer.sign(await signer.read(false)), []);
  await vault.owner.execute(sql`UPDATE log_pending SET body = replace(body, 'member.role', 'member.gone')`);
  assert.deepEqual(await signer.move(), [{ found: 'lost', of: 'log' }]);
  // What is left of it is nobody's, and the tree holds a leaf the log does not.
  assert.deepEqual(kinds(await run()), ['cut', 'forged']);
});

test('a run takes a tile\'s worth; the rest wait for the next, and the full check for the last', async () => {
  await wait(...Array.from({ length: 600 }, (_, i) => ({ ...reading(`k${i}`), ...(i % 3 === 0 ? pending(vault.keys[0]!, { kept: true, action: 'test.kept', actor: null, credential: null, request: null, ip: null, objects: [], detail: { i } }, vault.now(), []) : {}) })));
  await vault.owner.insert(principals).values(principal(cy));
  await told();
  // While entries wait past the read, nothing is missing and no row is compared.
  assert.deepEqual([await signer.run(true), await signer.run(true)], [{ findings: [], more: true }, { findings: [], more: true }]);
  assert.deepEqual(await signer.run(true), { findings: [{ found: 'row', of: named(cy) }], more: false });
  const entries = await logged();
  assert.deepEqual(entries.map((entry) => entry.seq), Array.from({ length: 600 }, (_, seq) => seq));
  assert.deepEqual(entries.map((entry) => entry.kept), Array.from({ length: 600 }, (_, i) => i % 3 === 0));
  // 400 uses: past one tile, so a level above it.
  await proven();
});
