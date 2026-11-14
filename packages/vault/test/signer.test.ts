import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { inclusionProof, leafHash, nodesFrom, tileMap, verifyInclusion } from '@coffre/core/log';
import { openDatabase } from '@coffre/db/connect';
import { rowsOf } from '@coffre/db/dialect';
import { credentials, principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { caller } from '../src/caller.ts';
import { change, drop, part, put } from '../src/change.ts';
import { pending, type Pending } from '../src/entry.ts';
import { checked } from '../src/rows.ts';
import { HEAD_ROW, headText, Signer, type Finding } from '../src/signer.ts';
import { postgresProxy } from '../../../scripts/postgres-proxy.ts';
import { emptyDatabase, memoryStore, openTestVault, VAULT_URL } from './database.ts';
import { credential, principal, tokenOf, user } from './world.ts';

/**
 * The signer against a database writer, on Postgres: each protection of
 * formal/quint/log.qnt as the scenario its variant fails on, and what the
 * model leaves out (the trees, the batch, a signer that was away).
 */
const vault = await openTestVault();
after(() => vault.close());

const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
const named = (id: string) => JSON.stringify(['principals', id]);

let store: ReturnType<typeof memoryStore>;
let signer: Signer;
const open = () => Signer.open({ db: vault.db, keys: vault.keys, now: vault.now, store, keepUsesDays: 90 });

beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.woken.length = 0;
  store = memoryStore();
  signer = await open();
});

/** The vault tells the signer of what it committed, as it does after each commit. */
async function told(): Promise<void> {
  for (const hash of vault.woken.splice(0)) await signer.wake(hash);
}
/** Told of everything, then one run: what it found. */
async function run(full = true): Promise<Finding[]> {
  await told();
  await signer.run(full);
  return signer.take();
}
/** Quick runs until nothing waits and no full run is owed: all they found. */
async function runs(): Promise<Finding[]> {
  while (await signer.run(false));
  return signer.take();
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
    sql`SELECT size::int, kept_size::int AS "keptSize", encode(kept_root, 'hex') AS "keptRoot", aging_size::int AS "agingSize", encode(aging_root, 'hex') AS "agingRoot", aging_from::int AS "agingFrom", round(extract(epoch FROM signed_at) * 1000)::float8 AS "signedAt", mac FROM log_head`,
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

test('the head the signer wrote is the one a caller is answered, whole, and again after the next signing', async () => {
  await member(ada, 'member');
  // Her session, written as a change writes one, so that the signer's mirror has its row.
  const made = await change(vault, {
    read: { found: part(credentials, sql`false`) },
    decide: () => ({ writes: [put(credentials, credential('ada', ada, { lastUsedAt: new Date(vault.now()) }), null)], entry: { kept: true, action: 'signin', actor: ada, credential: null, request: null, ip: null, objects: [`principal:${ada}`], detail: {} }, answer: null }),
  });
  assert.ok('answer' in made);
  const asked = async () => {
    const answer = await caller(vault, { token: tokenOf('ada'), proof: null, ip: null, head: true });
    assert.ok(!('refused' in answer), JSON.stringify(answer));
    return answer.head;
  };
  const stored = async () => (await rowsOf<{ size: number; keptSize: number; keptRoot: string; agingSize: number; agingRoot: string; agingFrom: number; signedAt: string }>(
    vault.owner,
    sql`SELECT size::int, kept_size::int AS "keptSize", encode(kept_root, 'hex') AS "keptRoot", aging_size::int AS "agingSize", encode(aging_root, 'hex') AS "agingRoot", aging_from::int AS "agingFrom", to_char(signed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS "signedAt" FROM log_head`,
  ))[0];
  assert.equal(await asked(), null, 'nothing signed yet');
  // Signed at a millisecond no binary fraction holds exactly.
  vault.tick(1377);
  assert.deepEqual(await run(), []);
  const first = await asked();
  assert.ok(first !== null && first !== undefined);
  assert.deepEqual([first.size, first.keptSize, first.agingSize, first.signedAt], [2, 2, 0, new Date(vault.now()).toISOString()]);
  assert.deepEqual(first, await stored());
  await wait(reading('a'));
  vault.tick(1);
  assert.deepEqual(await run(), []);
  const second = await asked();
  assert.deepEqual(second, await stored());
  assert.deepEqual([second?.size, second?.agingSize, second?.keptRoot], [3, 1, first.keptRoot]);
});

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
  const signedAt = () => rowsOf(vault.owner, sql`SELECT signed_at FROM log_head`);
  const before = await signedAt();
  vault.tick(1000);
  assert.deepEqual(await run(), []);
  assert.deepEqual(await signedAt(), before);
  await member(bo, null);
  assert.deepEqual(await run(), []);
  await proven();
});

test('a signer that was away takes what waited for it; an entry put back is refused, whether it remembers signing it or not', async () => {
  await member(ada, 'owner');
  const opened = signer.checked;
  vault.tick(60 * 60_000);
  // One that has never checked says since when, however often it is opened.
  assert.deepEqual([opened, (await open()).checked], [vault.now() - 60 * 60_000, opened]);
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
  // And still once its clock is set back, before the entry's own date.
  vault.tick(-10 * 60_000);
  assert.deepEqual(await run(), []);
  await putBack();
  assert.deepEqual(kinds(await run()), ['stale']);
  vault.tick(10 * 60_000);
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
  // A run that dies once it has found something says it on the next: the finding is in its storage, as its decision is.
  await told();
  await signer.sign(await signer.read(false));
  signer = await open();
  assert.deepEqual(await run(false), [{ found: 'missing', of: hash }]);
  // Said once. And Bo's row is there with no entry that says so, which the full run finds.
  assert.deepEqual(await run(false), []);
  assert.deepEqual(await run(), [{ found: 'row', of: named(bo) }]);
});

test('what was found is let go once it is sent: not if sending fails, and not what a run found meanwhile', async () => {
  const forge = () => vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (false, '{}', decode(repeat('00', 36), 'hex'))`);
  await forge();
  await signer.run(false);
  const first = [{ found: 'forged', of: 'pending:1' }];
  await assert.rejects(signer.take(() => Promise.reject(new Error('not sent'))), /not sent/);
  // Still there, and in its storage.
  assert.deepEqual(store.kept.get('found'), first);
  const sent = await signer.take(async (found) => {
    assert.deepEqual(found, first);
    await forge();
    await signer.run(false);
    return true;
  });
  assert.deepEqual(sent, first);
  assert.deepEqual(await signer.take(), [{ found: 'forged', of: 'pending:2' }]);
  assert.deepEqual(await signer.take(), []);
});

test('a check names a thousand rows at most, the first by name, however many are wrong', async () => {
  await member(ada, 'owner');
  assert.deepEqual(await run(), []);
  // Rows written behind the vault, as many as a writer likes.
  const planted = Array.from({ length: 1001 }, (_, index) => user(`planted-${String(index).padStart(4, '0')}`));
  await vault.owner.insert(principals).values(planted.map((id) => ({ ...principal(id, { role: 'member' }), mac: Buffer.alloc(36) })));
  const first = planted.map(named).sort().slice(0, 1000).map((of) => ({ found: 'row', of }));
  assert.deepEqual(await run(), first);
  // Still wrong at the next check, and no news; the last one once one of them is put right.
  vault.tick(60_000);
  assert.deepEqual(await run(), []);
  assert.deepEqual(signer.standing, first);
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${planted[0]!}`);
  vault.tick(60_000);
  const last = { found: 'row', of: planted.map(named).sort()[1000]! };
  assert.deepEqual(await run(), [last]);
  assert.deepEqual(signer.standing, [...first.slice(1), last]);
  // Told that what it found reached nobody, it forgets what stands: the next check finds them all again.
  await signer.take(() => false);
  assert.deepEqual(signer.standing, []);
  vault.tick(60_000);
  assert.deepEqual(await run(), [...first.slice(1), last]);
});

test('a change that replaced a MAC the mirror does not hold is false history', async () => {
  await member(bo, 'member');
  assert.deepEqual(await run(), []);
  // The writer removes Bo. Ada sees him gone and admits him again: an entry that says there was nobody.
  await vault.owner.execute(sql`DELETE FROM principals WHERE id = ${bo}`);
  await member(bo, 'member');
  assert.deepEqual(await run(), [{ found: 'rewritten', of: named(bo) }]);
});

test('a change decided on a row put back for it is false history, though the row is withdrawn before any check', async () => {
  /** `by`, an Owner, makes `id` one. */
  const promote = async (by: string, id: string) => {
    const read = { caller: part(principals, sql`id = ${by}`), found: part(principals, sql`id = ${id}`) };
    const result = await change(vault, {
      read,
      decide: ({ caller: [owner], found: [was] }) =>
        owner?.role !== 'owner' ? { refused: 'not_owner' } : { writes: [put(principals, principal(id, { role: 'owner' }), was!)], entry: { kept: true, action: 'member.role', actor: by, credential: null, request: null, ip: null, objects: [`principal:${id}`], detail: {} }, answer: null },
    });
    return 'refused' in result ? result.refused : 'done';
  };
  await member(ada, 'owner');
  await member(bo, 'owner');
  await member(cy, 'member');
  const [owning] = await vault.owner.select().from(principals).where(sql`id = ${bo}`);
  await member(bo, 'member');
  const [demoted] = await vault.owner.select().from(principals).where(sql`id = ${bo}`);
  assert.deepEqual(await run(), []);
  assert.equal(await promote(bo, cy), 'not_owner');
  // An Owner's change names the row it was decided on, and the signer finds nothing in it.
  assert.equal(await promote(ada, cy), 'done');
  await member(cy, 'member');
  assert.deepEqual(await run(), []);

  // The writer puts Bo's Owner row back, Bo promotes Cy, and the writer withdraws the row: all between two runs.
  await vault.owner.update(principals).set(owning!).where(sql`id = ${bo}`);
  assert.equal(await promote(bo, cy), 'done');
  await vault.owner.update(principals).set(demoted!).where(sql`id = ${bo}`);
  // A quick run finds it, with no row to compare: the entry says which row Bo's change was decided on.
  assert.deepEqual(await run(false), [{ found: 'rewritten', of: named(bo) }]);
  // The mirror stays what the entries wrote: Bo a Member, as his row is again, and Cy an Owner.
  assert.deepEqual(await run(), []);
  assert.deepEqual([store.kept.get(`row ${named(bo)}`), store.kept.get(`row ${named(cy)}`) === store.kept.get(`row ${named(bo)}`)], [demoted!.mac.toString('hex'), false]);
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
  // Bo's row still stands, and is no news.
  const found = [{ found: 'row', of: named(cy) }, { found: 'row', of: named(ada) }, { found: 'cut', of: 'kept' }];
  // The log's last entry moved further on: it ends with the entry signed, and not where.
  await vault.owner.execute(sql`UPDATE log SET seq = 9, leaf = 7 WHERE seq = 2`);
  assert.deepEqual(await run(false), []);
  assert.deepEqual(await run(), found);
  // Put back and replaced: it ends where it did, and not with the entry signed.
  await vault.owner.execute(sql`UPDATE log SET seq = 2, leaf = 2, body = 'another' WHERE seq = 9`);
  // Wrong still, each of them, which is no news.
  assert.deepEqual(await run(), []);
  assert.deepEqual(signer.standing, [{ found: 'row', of: named(bo) }, ...found]);
});

test('the full run finds an older head put back, though it is genuine, one edited under its MAC, and one deleted; the next signing writes the head again, and a signer opened again holds it still', async () => {
  const head = async () => (await rowsOf<{ mac: string }>(vault.owner, sql`SELECT encode(mac, 'hex') AS mac FROM log_head`))[0]?.mac ?? null;
  /** The head it signed last, as the signer keeps it: its MAC is the last field. */
  const kept = () => (JSON.parse(store.kept.get('head') as string) as unknown[]).at(-1);
  const wrong = [{ found: 'row', of: HEAD_ROW }];
  // No head yet, and none signed: nothing to find.
  assert.deepEqual(await run(), []);
  await member(bo, 'owner');
  assert.deepEqual(await run(), []);
  const [{ older }] = (await rowsOf<{ older: unknown }>(vault.owner, sql`SELECT to_jsonb(log_head) AS older FROM log_head`)) as [{ older: unknown }];
  await member(bo, 'member');
  assert.deepEqual(await run(), []);
  const last = await head();
  assert.equal(kept(), last);
  // The head of one entry ago, whole: under the vault's MAC, as `caller` would find, and not the last.
  await vault.owner.execute(sql`UPDATE log_head SET (size, kept_size, kept_root, aging_size, aging_root, aging_from, signed_at, mac) = (SELECT size, kept_size, kept_root, aging_size, aging_root, aging_from, signed_at, mac FROM jsonb_populate_record(NULL::log_head, ${JSON.stringify(older)}::jsonb))`);
  assert.notEqual(await head(), last);
  assert.deepEqual(await run(false), []);
  assert.deepEqual(await run(), wrong);
  // Wrong still, which is no news, to a signer opened again from its storage too.
  assert.deepEqual(await run(), []);
  signer = await open();
  assert.deepEqual(await run(), []);
  assert.deepEqual(signer.standing, wrong);
  // The next signing writes the head it signs: right again, to the check after it, since a run reads before it moves.
  await member(cy, 'member');
  assert.deepEqual(await run(), []);
  assert.deepEqual(signer.standing, wrong);
  assert.deepEqual(await run(), []);
  assert.deepEqual(signer.standing, []);
  assert.equal(await head(), kept());
  await proven();
  // Opened again from its storage with the head right: it holds the head it signed, and finds nothing.
  signer = await open();
  assert.deepEqual(await run(), []);
  assert.deepEqual(signer.standing, []);
  // Each column edited in turn, the MAC left: no caller is answered such a head, and it is not the one signed.
  for (const edit of [sql`aging_from = aging_from + 1, aging_size = aging_size + 1, size = size + 1`, sql`kept_root = sha256(kept_root)`, sql`aging_root = sha256(aging_root)`, sql`signed_at = signed_at + interval '1 millisecond'`, sql`kept_size = kept_size + 1, size = size + 1`]) {
    const [{ before }] = (await rowsOf<{ before: unknown }>(vault.owner, sql`SELECT to_jsonb(log_head) AS before FROM log_head`)) as [{ before: unknown }];
    await vault.owner.execute(sql`UPDATE log_head SET ${edit}`);
    assert.equal(await head(), kept());
    assert.deepEqual(await run(), wrong);
    await vault.owner.execute(sql`UPDATE log_head SET (size, kept_size, kept_root, aging_size, aging_root, aging_from, signed_at) = (SELECT size, kept_size, kept_root, aging_size, aging_root, aging_from, signed_at FROM jsonb_populate_record(NULL::log_head, ${JSON.stringify(before)}::jsonb))`);
    assert.deepEqual(await run(), []);
    assert.deepEqual(signer.standing, []);
  }
  // Gone: news again.
  await vault.owner.execute(sql`DELETE FROM log_head`);
  assert.deepEqual(await run(), wrong);
});

test('an entry told of during a run, or after it was signed, raises nothing', async () => {
  await member(ada, 'owner');
  await told();
  const snapshot = await signer.read(true);
  // Committed and told of after the read: not in it, and not missed. Its row is not in the read either.
  await member(bo, 'member');
  await told();
  await signer.sign(snapshot);
  await signer.move();
  assert.deepEqual(await signer.take(), []);
  assert.deepEqual(await run(), []);
  // The signer's own run takes an entry before the vault's word of it arrives.
  await member(cy, 'member');
  assert.equal(await signer.run(true), false);
  assert.deepEqual(await signer.take(), []);
  assert.deepEqual(await run(), []);
  assert.equal((await logged()).length, 3);
});

test('a run that died before its move, or before it could say it had moved, is finished by the next signer, once', async () => {
  await member(ada, 'owner');
  await wait(reading('a'));
  await told();
  await signer.sign(await signer.read(true));
  // Nothing is read on top of a decision not yet moved: its entries would be read again, as if put back.
  await assert.rejects(signer.read(false), /not moved yet/);
  signer = await open();
  assert.deepEqual(await run(), []);
  assert.equal((await logged()).length, 2);

  await member(bo, 'member');
  await told();
  const [waited] = await rowsOf<{ body: string; mac: string }>(vault.owner, sql`SELECT body, encode(mac, 'hex') AS mac FROM log_pending`);
  await signer.sign(await signer.read(false));
  const before = structuredClone(store.kept);
  await signer.move();
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
  await assert.rejects(signer.wake(Buffer.alloc(32)), /open another/);
  signer = await open();
  assert.deepEqual(await run(), []);
  assert.equal((await logged()).length, 4);

  // The same when its storage refuses what a run decided: the next signer decides again, and nothing was moved on a decision nobody kept.
  await member(cy, 'owner');
  await told();
  store.down = true;
  await assert.rejects(signer.run(false), /storage is down/);
  store.down = false;
  await assert.rejects(signer.run(false), /open another/);
  await assert.rejects(signer.move(), /open another/);
  assert.equal((await logged()).length, 4);
  signer = await open();
  assert.deepEqual(await run(), []);
  assert.deepEqual((await logged()).map((entry) => entry.seq), [0, 1, 2, 3, 4]);
  await proven();
});

test('an entry that is nobody\'s is refused and removed, alone; one changed between its signing and its move is lost, and said so', async () => {
  await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (true, '{"action":"member.role"}', decode(${'00'.repeat(36)}, 'hex'))`);
  await told();
  await signer.sign(await signer.read(true));
  // Committed between the read and the move: it waits on, for the next run.
  await member(bo, 'member');
  await signer.move();
  assert.deepEqual(await signer.take(), [{ found: 'forged', of: 'pending:1' }]);
  assert.deepEqual([await logged(), await waiting()], [[], 1]);
  assert.deepEqual(await run(), []);
  assert.deepEqual([(await logged()).length, await waiting()], [1, 0]);
  await emptyDatabase(vault.owner);
  store = memoryStore();
  signer = await open();

  await member(ada, 'owner');
  const [hash] = vault.woken.map((each) => each.toString('hex'));
  await told();
  await signer.sign(await signer.read(false));
  await vault.owner.execute(sql`UPDATE log_pending SET body = replace(body, 'member.role', 'member.gone')`);
  await signer.move();
  assert.deepEqual(await signer.take(), [{ found: 'lost', of: hash }]);
  // What is left of it is nobody's, and the tree holds a leaf the log does not, which the re-check of old entries names again.
  assert.deepEqual(kinds(await run()), ['cut', 'forged', 'lost']);
});

test('a row planted where an entry is about to go does not stop the signer: the entry is lost, and said so', async () => {
  // At the next leaf of the tree, under a number far away; then at the next number itself, with the entry taken from where it waited.
  await vault.owner.execute(sql`INSERT INTO log (seq, kept, leaf, body) VALUES (1000000, true, 0, '{}')`);
  await member(ada, 'owner');
  const [first] = vault.woken.map((each) => each.toString('hex'));
  assert.deepEqual(await run(false), [{ found: 'lost', of: first }]);
  // And the index names no entry the log does not hold.
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT * FROM log_index`), []);
  await member(bo, 'member');
  const [second] = vault.woken.map((each) => each.toString('hex'));
  await told();
  await signer.sign(await signer.read(false));
  await vault.owner.execute(sql`DELETE FROM log_pending`);
  await vault.owner.execute(sql`INSERT INTO log (seq, kept, leaf, body) VALUES (1, true, 1, '{}')`);
  await signer.move();
  assert.deepEqual(await signer.take(), [{ found: 'lost', of: second }]);
  // It goes on: the next entry is numbered and moved. The log then ends as signed, so the check has nothing to add:
  // what was planted before its end was said when it was lost, and the re-check of old entries finds it again (D222).
  await member(cy, 'member');
  assert.deepEqual(await run(false), []);
  assert.deepEqual((await logged()).map((entry) => entry.seq), [1, 2, 1000000]);
  assert.deepEqual(await run(), [{ found: 'lost', of: first }, { found: 'lost', of: second }]);
});

test('a run is two round trips, its read and its move, and a minute\'s five, with the re-check\'s read and the deletions\' read and statement, each bounded; only one runs at a time, and what it found outlasts its failure', async () => {
  const sent: string[][] = [];
  const proxy = await postgresProxy(VAULT_URL, { onSync: (statements) => sent.push(statements.map((text) => text.trimStart())) });
  const through = await openDatabase(proxy.url);
  try {
    signer = await Signer.open({ db: through.db, keys: vault.keys, now: vault.now, store, keepUsesDays: 90 });
    await signer.run(false);
    await member(ada, 'owner');
    sent.length = 0;
    // The rows and the entries that wait are of one moment: one statement reads both. Each goes with the bound on its waits.
    assert.deepEqual(await run(), []);
    const bounded = (statement: string) => ['begin isolat', 'SELECT set_c', statement, 'commit'];
    assert.deepEqual(sent.map((group) => group.map((text) => text.slice(0, 12))), [bounded('SELECT parts'), bounded('WITH taken A'), bounded('SELECT part,'), bounded('WITH spent A'), bounded('SELECT l.kep')]);
    // With the database's clock, so that no pooler answers the read from a cache.
    assert.match(sent[0]![2]!, /^SELECT parts\.\*, clock_timestamp\(\)/);
    const first = signer.run(true);
    await assert.rejects(signer.run(true), /one at a time/);
    assert.equal(await first, false);

    // The writer holds the head's row. The move waits two seconds and fails: the run fails, the signer does not hang,
    // and what it found before it is there to take. Once the lock goes, the next run moves what was signed.
    await vault.owner.execute(sql`INSERT INTO log_pending (kept, body, mac) VALUES (true, '{}', decode(${'00'.repeat(36)}, 'hex'))`);
    await member(bo, 'member');
    await told();
    let release!: () => void;
    const held = vault.owner.transaction(async (tx) => {
      await tx.execute(sql`SELECT 1 FROM log_head FOR UPDATE`);
      await new Promise<void>((resolve) => (release = resolve));
    });
    try {
      await new Promise((resolve) => setTimeout(resolve, 100));
      await assert.rejects(signer.run(false));
      assert.deepEqual(kinds(await signer.take()), ['forged']);
    } finally {
      release();
      await held;
    }
    assert.deepEqual(await run(false), []);
    assert.deepEqual([(await logged()).length, await waiting()], [2, 0]);

    // The writer holds a table the full run reads. The run fails, having signed and moved what waited; and the signer
    // says when it last checked, for whoever watches it to say it is stopped.
    assert.deepEqual(await run(), []);
    const checked = signer.checked;
    assert.equal(checked, vault.now());
    vault.tick(60_000);
    await member(cy, 'member');
    await told();
    const locked = vault.owner.transaction(async (tx) => {
      await tx.execute(sql`LOCK TABLE principals IN ACCESS EXCLUSIVE MODE`);
      await new Promise<void>((resolve) => (release = resolve));
    });
    try {
      await new Promise((resolve) => setTimeout(resolve, 100));
      await assert.rejects(signer.run(true));
      assert.deepEqual([(await rowsOf(vault.owner, sql`SELECT 1 FROM log`)).length, await signer.take(), signer.checked], [3, [], checked]);
    } finally {
      release();
      await locked;
    }
    // The next minute's run checks, not every run until then; and the next signer knows when.
    assert.deepEqual(await run(false), []);
    assert.equal(signer.checked, checked);
    assert.deepEqual(await run(), []);
    assert.equal(signer.checked, vault.now());
    vault.tick(5000);
    assert.equal((await Signer.open({ db: through.db, keys: vault.keys, now: vault.now, store, keepUsesDays: 90 })).checked, vault.now() - 5000);
  } finally {
    await through.close();
    await proxy.close();
  }
});

test('a run takes a tile\'s worth; the rest wait for the next, and the full check for the last, however long the signer was away', async () => {
  const some = (count: number, from: number) =>
    Array.from({ length: count }, (_, i) => ({ ...reading(`k${from + i}`), ...((from + i) % 3 === 0 ? pending(vault.keys[0]!, { kept: true, action: 'test.kept', actor: null, credential: null, request: null, ip: null, objects: [], detail: { i: from + i } }, vault.now(), []) : {}) }));
  assert.deepEqual(await run(), []);
  // 300 entries a minute after its last run, 300 an hour later, and only then does it run again.
  vault.tick(60_000);
  await wait(...some(300, 0));
  vault.tick(60 * 60_000);
  await wait(...some(300, 300));
  await vault.owner.insert(principals).values(principal(cy));
  await told();
  const fulls: boolean[] = [];
  const read = signer.read.bind(signer);
  signer.read = (full) => (fulls.push(full), read(full));
  // While entries wait past the read, nothing is missing, no row is compared, and its window does not move: the oldest are still taken.
  assert.equal(await signer.run(true), true);
  assert.deepEqual(await signer.take(), []);
  // The full run stays owed, whatever is asked next, and reads the rows again only once nothing waits.
  assert.deepEqual(await runs(), [{ found: 'row', of: named(cy) }]);
  assert.deepEqual(fulls, [true, false, false, true]);
  const entries = await logged();
  assert.deepEqual(entries.map((entry) => entry.seq), Array.from({ length: 600 }, (_, seq) => seq));
  assert.deepEqual(entries.map((entry) => entry.kept), Array.from({ length: 600 }, (_, i) => i % 3 === 0));
  // 400 uses: past one tile, so a level above it.
  await proven();
});
