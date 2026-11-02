// A request's several keys as it names them (T165, B2's PR 2; migration 0055, `use_named_batch`;
// formal/ProbingMany.tla), on both engines: the vault's one call decides the caller's standing at the place first, from
// rows no key decides, and reads nothing of any key without it; for one who stands, it resolves each key's name, the
// request's names or every key the place holds, decides them all (a sealed key not mapped on the batch by ids' first
// round), and only then makes the rest by ids, as a batch does (Batching.tla). Each case is named for what the model holds of it.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { decrypt } from '@coffre/core/envelope';
import type { NamedManyInput, NamedManyOutcome, NamedUseInput } from '@coffre/core/vault';
import { createDatabase, type Database } from '@coffre/db';
import { postgresClient } from '@coffre/db/connect';
import { sql } from 'drizzle-orm';

import { openVault, prepareVault } from '../src/vault.ts';
import { ENGINE, HOT_URL, openTestDatabase, postgresOnly, rows, run, type TestDatabase } from './database.ts';
import { namedWorld } from './named-world.ts';
import { CONFIG, emptyLog, isolate, LOG_015, onePeriod, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

const named = (options: Parameters<typeof world>[0] = {}) => namedWorld(db, options);
const count = async (table: string) => (await rows(db.owner, sql.raw(`SELECT 1 FROM ${table}`))).length;

/** A named batch of `keys` (null: every key the place holds) as the world's caller asks it. */
function many(w: { ask: (key: string, extra?: Partial<NamedUseInput>) => NamedUseInput }, keys: readonly string[] | null, extra: Partial<NamedManyInput> = {}): NamedManyInput {
  const { key: _, requestId: __, forks: ___, ...one } = w.ask('UNUSED');
  return { ...one, keys, ...extra };
}

const byName = (outcome: NamedManyOutcome) => {
  assert.ok(outcome.served && outcome.route === 'name', JSON.stringify(outcome));
  return outcome as Extract<NamedManyOutcome, { route: 'name' }>;
};

/** Each key's value, by name: its text, or null for a key not held or left out. */
function values(outcome: NamedManyOutcome): Record<string, string | null> {
  const answer = byName(outcome);
  assert.ok(answer.outcome.ok, JSON.stringify(answer.outcome));
  const out: Record<string, string | null> = {};
  for (const [i, key] of answer.keys.entries()) {
    const value = answer.outcome.values[i]!;
    out[key.key] = value === null ? null : 'plain' in value ? value.plain : decrypt(
      { envelopeVersion: value.value.envelope.version, ciphertext: Buffer.from(value.value.envelope.ciphertext, 'base64'), iv: Buffer.from(value.value.envelope.iv, 'base64'), authTag: Buffer.from(value.value.envelope.authTag, 'base64') },
      value.value.context, Buffer.from(value.value.key, 'base64'),
    ).toString();
  }
  return out;
}

/** What a refusal says: the place's (`index` null) or a key's, by name. */
function refused(outcome: NamedManyOutcome): { key: string | null; code: string } {
  const answer = byName(outcome);
  assert.ok(!answer.outcome.ok && 'code' in answer.outcome, JSON.stringify(answer.outcome));
  return { key: answer.outcome.index === null ? null : answer.keys[answer.outcome.index]!.key, code: answer.outcome.code };
}

/** An isolate whose hot pool counts the statements it sends (Postgres). */
async function counted() {
  let statements = 0;
  const client = postgresClient(HOT_URL, { max: 2 });
  const pool = new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        statements += 1;
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  const hot: Database = createDatabase(pool);
  const prepared = await prepareVault(CONFIG, LOG_015);
  const vault = openVault(db.vault, prepared, hot);
  return { vault, statements: () => statements, cache: prepared.uses, close: () => client.end() };
}

test('a list of keys is one call: each value in the order asked, each use its entry; a key never made is none, left out', async () => {
  const w = await named();
  const a = await w.key('a');
  const b = await w.key('b');
  const { vault, cache } = await isolate();
  const [nameA, nameB] = [await w.nameOf(a), await w.nameOf(b)];
  const answer = await vault.useNamedMany!(many(w, [nameB, 'NEVER_MADE', nameA]));
  assert.deepEqual(values(answer), { [nameB]: 'b', NEVER_MADE: null, [nameA]: 'a' });
  assert.deepEqual(byName(answer).keys.map((key) => key.secretId), [b, null, a]);
  assert.equal(byName(answer).stands, true);
  assert.equal(await count('log_uses'), 2, 'a key the place does not hold writes nothing');
  // The map keeps every key's ids, the one never made as none.
  assert.deepEqual(cache.keyed(w.dev, nameA), { id: a, through: false });
  assert.equal(cache.keyed(w.dev, 'NEVER_MADE'), null);
  if (ENGINE === 'postgres') {
    const app = JSON.parse(byName(answer).keys[0]!.app!) as { secrets: { secret: { id: string } }[] };
    assert.deepEqual(app.secrets.map((row) => row.secret.id), [b], "each key's rows, as `app_read` answers them");
  }
});

test("a key mapped is used by its ids only while they are its name's now, its value sealed: else by its name, a plain value logged by none", async () => {
  const w = await named();
  const a = await w.key('a');
  const name = await w.nameOf(a);
  const { vault, cache } = await isolate();
  // Cold, then warm: by its name, then by the ids the map keeps, each a use logged.
  assert.deepEqual(values(await vault.useNamedMany!(many(w, [name]))), { [name]: 'a' });
  assert.deepEqual(cache.keyed(w.dev, name), { id: a, through: false });
  assert.deepEqual(values(await vault.useNamedMany!(many(w, [name]))), { [name]: 'a' });
  const logged = await count('log_uses');
  assert.ok(logged >= 1, 'each a use');
  // Deleted, and its name made again as a plain value: the map's ids are not the name's now, and a plain value is no
  // use's. Read by its name, its text handed back, nothing logged, the map moved to the new key.
  await w.remove(a);
  const { id: plain } = await w.plain('plain-now', name);
  const answer = await vault.useNamedMany!(many(w, [name]));
  assert.deepEqual(values(answer), { [name]: 'plain-now' });
  assert.equal(byName(answer).keys[0]!.secretId, plain);
  assert.equal(await count('log_uses'), logged, 'a plain value: no entry');
  assert.deepEqual(cache.keyed(w.dev, name), { id: plain, through: false });
  // Mapped to the plain key now, still by its name: no entry.
  assert.deepEqual(values(await vault.useNamedMany!(many(w, [name]))), { [name]: 'plain-now' });
  assert.equal(await count('log_uses'), logged, 'a plain value mapped: by its name all the same');
});

test("a key mapped, deleted and made again sealed under its name: the map's ids are not the name's now, the new key's value goes back, its use logged under its own id (IdsChecked)", async () => {
  const w = await named();
  const old = await w.key('old');
  const name = await w.nameOf(old);
  const { vault, cache } = await isolate();
  assert.deepEqual(values(await vault.useNamedMany!(many(w, [name]))), { [name]: 'old' });
  assert.deepEqual(cache.keyed(w.dev, name), { id: old, through: false });
  await w.remove(old);
  const made = await w.key('new');
  await run(db.owner, sql`UPDATE secrets SET key = ${name} WHERE id = ${made}`);
  const answer = await vault.useNamedMany!(many(w, [name]));
  assert.deepEqual(values(answer), { [name]: 'new' });
  assert.equal(byName(answer).keys[0]!.secretId, made);
  assert.deepEqual(cache.keyed(w.dev, name), { id: made, through: false }, 'the map moved to the new key');
  const secrets = (await rows<{ secret: string }>(db.owner, sql`SELECT secret FROM log_uses`)).map((row) => row.secret);
  assert.ok(secrets.includes(made) && secrets.filter((id) => id === old).length === 1, 'the new key used under its id; the old one only the once it was');
});

test("a live reference in a batch: its source's value, decided by its name on the first statement, used with the rest", async () => {
  const w = await named();
  const own = await w.key('own');
  const ref = await w.reference('LIVE_REF');
  const { vault } = await isolate();
  const name = await w.nameOf(own);
  assert.deepEqual(values(await vault.useNamedMany!(many(w, [name, 'LIVE_REF']))), { [name]: 'own', LIVE_REF: 'source of LIVE_REF' });
  assert.deepEqual(values(await vault.useNamedMany!(many(w, null))), { [name]: 'own', LIVE_REF: 'source of LIVE_REF', [await w.nameOf(ref.source)]: 'source of LIVE_REF' });
});

test('every key the place holds, listed by the vault, sorted by name', async () => {
  const w = await named();
  const made = [await w.key('x'), await w.key('y'), await w.key('z')];
  const { vault } = await isolate();
  const answer = await vault.useNamedMany!(many(w, null));
  const names = await Promise.all(made.map((id) => w.nameOf(id)));
  assert.deepEqual(byName(answer).keys.map((key) => key.key), [...names].sort());
  assert.deepEqual(Object.values(values(answer)).sort(), ['x', 'y', 'z']);
});

test('GateBeforeKeys: with no standing, one statement refuses on the place, nothing of any key read, listed or written', async () => {
  const w = await named();
  for (const value of ['a', 'b', 'c']) await w.key(value);
  await w.revoke();
  const { vault } = await isolate();
  for (const keys of [null, ['NEVER_MADE', 'ALSO_NEVER'], [await w.nameOf(w.keys[0]!.id)]] as const) {
    const answer = byName(await vault.useNamedMany!(many(w, keys)));
    assert.equal(answer.stands, false);
    assert.deepEqual(answer.keys, [], 'no key named back');
    assert.equal(refused(answer).key, null, "the place's refusal");
    assert.equal(answer.standing.grants.length, 0);
  }
  assert.equal(await count('log_uses'), 0);
  assert.equal(await count('log_bulk'), 0);
});

test('AllDecidedFirst: a key refused (a reference ended) refuses the batch at it, entering no key in the set, nothing written', async () => {
  const w = await named();
  const held = await w.key('held');
  const ended = await w.reference('ENDED');
  await w.end(ended);
  const { vault } = await isolate();
  const answer = await vault.useNamedMany!(many(w, [await w.nameOf(held), 'ENDED']));
  assert.deepEqual(refused(answer), { key: 'ENDED', code: 'ended' });
  assert.equal(await count('log_uses'), 0, 'the reference refused on the first statement, which wrote nothing, the sealed key only resolved there');
  assert.equal(await count('log_bulk'), 0, 'refused reads never insert');
});

test('the first key refused answers, whatever the map holds: a sealed key not mapped, before one refused on the first statement', async () => {
  // Review r2 of T165 PR 2: cold, the sealed key was left to the batch by ids, and the reference after it, refused on the
  // statement's rows, answered for the batch; warm, the sealed key, by its ids on the statement, did.
  const w = await named({ caller: 'person' });
  const id = await w.key('hidden', true);
  const hidden = await w.nameOf(id);
  await w.end(await w.reference('ENDED'));
  const ask = () => many(w, [hidden, 'ENDED'], { purpose: 'run' });
  const first = { key: hidden, code: 'sensitive' };
  const { vault, cache } = await isolate();
  assert.deepEqual(refused(await vault.useNamedMany!(ask())), first, 'cold');
  // The statement resolved its name, so the map now holds its ids, which the same request passes next.
  assert.deepEqual(cache.keyed(w.dev, hidden), { id, through: false });
  assert.deepEqual(refused(await vault.useNamedMany!(ask())), first, 'warm');
  assert.equal(await count('log_uses'), 0, 'neither key used');
  assert.equal(await count('log_bulk'), 0, 'refused reads never insert');
});

test('LeaveFirst: a read that leaves sensitive values out uses none of them, naming them; the rest are used', async () => {
  const w = await named({ caller: 'person' });
  const open = await w.key('open');
  const hidden = await w.key('hidden', true);
  const { vault } = await isolate();
  // Warm the map with the sensitive key's ids, as a use of it would: a read that leaves it out passes them no further.
  await vault.useNamed!(w.ask(await w.nameOf(hidden), { purpose: 'use' }));
  const before = await count('log_uses');
  const answer = await vault.useNamedMany!(many(w, null, { purpose: 'run', leavesSensitive: true }));
  const keys = byName(answer).keys;
  assert.deepEqual(keys.find((key) => key.secretId === hidden)?.left, true);
  assert.deepEqual(keys.find((key) => key.secretId === open)?.left, false);
  assert.deepEqual(Object.values(values(answer)).filter((value) => value !== null), ['open']);
  assert.equal(await count('log_uses') - before, 1, 'only the key it hands back is used');
  // Without it, a person's read of a sensitive value is refused, as the vault's rule refuses any.
  assert.equal(refused(await vault.useNamedMany!(many(w, null, { purpose: 'run' }))).code, 'sensitive');
});

test("a fork's keys: its own and dev's it inherits, each decided where it is held; one it removed is none", async () => {
  const w = await named();
  const fork = await w.fork('fork');
  await w.grantAt(fork, 'viewer');
  const own = await w.key('own', false, fork);
  const inherited = await w.key('inherited');
  const removed = await w.key('removed');
  await w.dismiss(fork, await w.nameOf(removed));
  const { vault } = await isolate();
  const at = { place: { project: w.slug, environment: 'fork' } };
  const answer = await vault.useNamedMany!(many(w, null, at));
  assert.deepEqual(values(answer), { [await w.nameOf(inherited)]: 'inherited', [await w.nameOf(own)]: 'own' });
  const held = byName(answer).keys.find((key) => key.secretId === inherited)!.held;
  assert.deepEqual(held, { environmentId: w.dev, slug: 'dev' }, 'where an inherited key is held');
  assert.equal(values(await vault.useNamedMany!(many(w, [await w.nameOf(removed), await w.nameOf(own)], at)))[await w.nameOf(removed)], null);
  // Her grant at dev revoked: the fork's own still hers, dev's refused where it is held.
  await w.revokeAt(w.dev);
  assert.deepEqual(refused(await vault.useNamedMany!(many(w, null, at))), { key: await w.nameOf(inherited), code: refused(await vault.useNamedMany!(many(w, null, at))).code });
  assert.deepEqual(values(await vault.useNamedMany!(many(w, [await w.nameOf(own)], at))), { [await w.nameOf(own)]: 'own' });
});

test('CutByPlace: a fork whose parent is archived reads nothing, refused on the place before any key', async () => {
  const w = await named();
  const middle = await w.fork('middle');
  const fork = await w.fork('fork', middle);
  await w.grantAt(fork, 'viewer');
  await w.key('own', false, fork);
  await w.archive(middle, false);
  const { vault } = await isolate();
  const answer = byName(await vault.useNamedMany!(many(w, null, { place: { project: w.slug, environment: 'fork' } })));
  assert.equal(answer.stands, false);
  assert.deepEqual(refused(answer), { key: null, code: 'archived' });
  assert.equal(await count('log_uses'), 0);
});

test("`dev@me`: her personal config's own keys and dev's, one call", async () => {
  const w = await named({ caller: 'person' });
  const mine = await w.personal();
  const own = await w.key('mine', false, mine, w.principal);
  const devs = await w.key('devs');
  const { vault } = await isolate();
  const answer = await vault.useNamedMany!(many(w, null, { place: { project: w.slug, environment: 'dev@me' } }));
  assert.deepEqual(values(answer), { [await w.nameOf(own)]: 'mine', [await w.nameOf(devs)]: 'devs' });
});

test('CountsOwnBatch: past the cap, the batch is refused at the first key over it, and enters none', async () => {
  const w = await named({ count: 2 });
  const ids = [await w.key('a'), await w.key('b'), await w.key('c')];
  const { vault } = await isolate();
  const names = await Promise.all(ids.map((id) => w.nameOf(id)));
  assert.deepEqual(refused(await vault.useNamedMany!(many(w, names))), { key: names[2], code: 'bulk_limit' });
  assert.equal(await count('log_bulk'), 2, 'the two before it entered, as lone uses would; a refusal enters nothing');
  assert.deepEqual(Object.keys(values(await vault.useNamedMany!(many(w, names.slice(0, 2))))), names.slice(0, 2));
});

test('one call: a cold list two statements (three, its keys entering the set); mapped and in the set, one', postgresOnly('the hot pool counted'), async () => {
  const w = await named();
  const names: string[] = [];
  for (let i = 0; i < 5; i += 1) names.push(await w.nameOf(await w.key(`v${i}`)));
  const isolate = await counted();
  const at = onePeriod();
  const now = () => ({ at, deadline: at + 3000 });
  try {
    // The isolate's first call waits for the cutover: made here, at a place that is none, before anything is counted.
    assert.equal((await isolate.vault.useNamedMany!(many(w, ['X'], { place: { project: 'none', environment: 'none' } }))).served, false);
    let before = isolate.statements();
    assert.equal(Object.keys(values(await isolate.vault.useNamedMany!(many(w, names, now())))).length, 5);
    assert.equal(isolate.statements() - before, 3, 'by name, then by ids, then entering the set under the lock');
    before = isolate.statements();
    assert.equal(Object.keys(values(await isolate.vault.useNamedMany!(many(w, names, now())))).length, 5);
    assert.equal(isolate.statements() - before, 1, 'every key mapped and fresh: used in the first statement');
    before = isolate.statements();
    assert.equal(Object.keys(values(await isolate.vault.useNamedMany!(many(w, null, now())))).length, 5);
    assert.equal(isolate.statements() - before, 2, 'every key the place holds: listed, then used by ids');
    await w.revoke();
    before = isolate.statements();
    assert.equal(byName(await isolate.vault.useNamedMany!(many(w, names, now()))).stands, false);
    assert.equal(isolate.statements() - before, 1, 'no standing: one statement');
  } finally {
    await isolate.close();
  }
});

test('a place of more keys than a statement reads is read in statements of that many, each its gate', async () => {
  const w = await named();
  const made: string[] = [];
  for (let i = 0; i < 5; i += 1) made.push(await w.key(`v${i}`));
  const prepared = await prepareVault(CONFIG, { ...LOG_015, uses: { batch: 2 } });
  const vault = openVault(db.vault, prepared, ENGINE === 'postgres' ? await db.hot() : db.vault);
  assert.equal(Object.keys(values(await vault.useNamedMany!(many(w, null)))).length, 5);
  assert.equal(Object.keys(values(await vault.useNamedMany!(many(w, await Promise.all(made.map((id) => w.nameOf(id))))))).length, 5);
});

/**
 * `use_named_batch`'s answer when the chain is cut after its gate read it whole, by a write around the log between the
 * two (each command its own snapshot): the gate's row as it was, no names listed, no key read. Here the `cut`-th call's
 * answer is rewritten to it, its gate's row untouched, since no test can stop a function between two of its commands.
 */
async function cutAfterGate(cut: number, options: { batch?: number } = {}) {
  let calls: number | null = null;
  const client = postgresClient(HOT_URL, { max: 2 });
  const asCut = (text: string) => {
    // The gate's object, its end found by its braces outside strings, then the rest as `v_cut` answers it.
    const start = text.indexOf('{', 1);
    let depth = 0;
    let quoted = false;
    for (let i = start; i < text.length; i += 1) {
      const c = text[i]!;
      if (quoted) { if (c === '\\') i += 1; else if (c === '"') quoted = false; continue; }
      if (c === '"') quoted = true;
      else if (c === '{') depth += 1;
      else if (c === '}' && --depth === 0) return `${text.slice(0, i + 1)}, "keys" : null, "rows" : [], "by_ids" : [], "aheads" : []}`;
    }
    throw new Error('no gate in a named batch');
  };
  const pool = new Proxy(client, {
    get(target, key) {
      const value: unknown = Reflect.get(target, key, target);
      if (key !== 'unsafe') return value;
      return (...args: unknown[]) => {
        const sent = (value as (...a: unknown[]) => PromiseLike<{ uses?: string }[]>).apply(target, args);
        if (typeof args[0] !== 'string' || !args[0].includes('use_named_batch') || calls === null || ++calls !== cut) return sent;
        return Promise.resolve(sent).then((answer) => {
          answer[0]!.uses = asCut(answer[0]!.uses!);
          return answer;
        });
      };
    },
  });
  const prepared = await prepareVault(CONFIG, { ...LOG_015, ...(options.batch === undefined ? {} : { uses: { batch: options.batch } }) });
  const vault = openVault(db.vault, prepared, createDatabase(pool));
  return { vault, arm: () => { calls = 0; }, close: () => client.end() };
}

test('CutByPlace, the chain cut after the gate read it (around the log): refused `stale`, never an empty place read', postgresOnly('a function\'s commands, each its snapshot'), async () => {
  const w = await named();
  const names: string[] = [];
  for (let i = 0; i < 3; i += 1) names.push(await w.nameOf(await w.key(`v${i}`)));
  for (const [keys, cut, batch] of [[names, 1, undefined], [null, 1, undefined], [null, 2, 2], [names, 2, 2]] as const) {
    const isolate = await cutAfterGate(cut, { batch });
    try {
      // The isolate's first call waits for the cutover: made at a place that is none, before the rewrite is armed.
      assert.equal((await isolate.vault.useNamedMany!(many(w, ['X'], { place: { project: 'none', environment: 'none' } }))).served, false);
      isolate.arm();
      const answer = byName(await isolate.vault.useNamedMany!(many(w, keys)));
      const asked = `${keys === null ? 'every key' : 'by names'}, cut on statement ${cut}`;
      assert.equal(answer.stands, false, asked);
      assert.deepEqual(refused(answer), { key: null, code: 'stale' }, asked);
      assert.equal(await count('log_uses'), 0, asked);
      assert.equal(await count('log_bulk'), 0, asked);
    } finally {
      await isolate.close();
    }
  }
});
