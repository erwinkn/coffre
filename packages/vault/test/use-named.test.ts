// 0.15's use as the request names it (T145, PR B; D153; use.ts, `useNamed`; formal/Probing.tla): the vault's call reads
// what a token's hash, a place's slugs and a key's name name, by them, whatever its isolate's map of names holds, whose
// ids only let that call make the use (`moved` otherwise, nothing written). A key the place does not hold, and a plain
// value, are decided on the caller's standing there, and leave no entry; every refusal is one call, whatever the map
// held: nobody refused learns whether a key is held, at any load. A use allowed on rows the map had no ids for is made
// by the ids the call read, in a second.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import type { NamedUseInput, NamedUseOutcome } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { sql } from 'drizzle-orm';

import { refreshMs } from '../src/bulk.ts';
import type { Input } from '../src/inputs.ts';
import { newRequestId, UseCache, useLimits, type Resolved } from '../src/use.ts';
import { ENGINE, openTestDatabase, postgresOnly, rows, run, type TestDatabase } from './database.ts';
import { holding as holdingIn, namedWorld, principalLock, slowed as slowedVault } from './named-world.ts';
import { change, emptyLog, isolate, seal, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

const named = (options: Parameters<typeof world>[0] = {}) => namedWorld(db, options);
const holding = <T>(lock: ReturnType<typeof sql>, work: () => Promise<T>, owner = false) => holdingIn(db, lock, work, owner);
const slowed = () => slowedVault(db);

const uses = async () => Number((await rows<{ n: number | string }>(db.owner, sql`SELECT count(*) AS n FROM log_uses`))[0]!.n);
const bulk = async () => Number((await rows<{ n: number | string }>(db.owner, sql`SELECT count(*) AS n FROM log_bulk`))[0]!.n);
const served = (outcome: NamedUseOutcome) => {
  assert.equal(outcome.served, true);
  return outcome as Extract<NamedUseOutcome, { served: true }>;
};
/** Served on the vault's decision (`routeOf`): the caller as it decided them, and the rows the app checks. */
const byName = (outcome: NamedUseOutcome) => {
  assert.equal(served(outcome).route, 'name');
  return outcome as Extract<NamedUseOutcome, { route: 'name' }>;
};
const codeOf = (outcome: NamedUseOutcome) => {
  const { outcome: used } = served(outcome);
  return used.ok ? 'ok' : 'busy' in used ? `busy:${used.busy}` : used.code;
};

test("a named use opens the key it names, by the ids it reads once, and answers the caller as the use read them, and, on Postgres, the app's rows", async () => {
  const w = await named();
  const id = await w.key('sk_live_1');
  const { vault } = await isolate();
  const first = byName(await vault.useNamed!(w.ask(await w.nameOf(id))));
  assert.equal(first.outcome.ok, true);
  assert.equal(await uses(), 1, 'one entry: the use');
  assert.equal(first.standing?.status, 'active');
  assert.deepEqual(first.standing?.grants.map((grant) => grant.environmentId), [w.dev]);
  if (ENGINE === 'postgres') {
    const app = JSON.parse(first.app!) as { credential: { id: string }; environment: { id: string }; secrets: { secret: { id: string } }[] };
    assert.equal(app.credential.id, w.credentialId);
    assert.equal(app.environment.id, w.dev);
    assert.deepEqual(app.secrets.map((row) => row.secret.id), [id]);
  } else {
    assert.equal(first.app, null, "SQLite's app reads its own rows");
  }
  // Its map kept: the use again, by the same ids, in its one call.
  assert.equal(codeOf(await vault.useNamed!(w.ask(await w.nameOf(id)))), 'ok');
});

test('a key the place does not hold is answered as the caller stands there: missing to one who reads there, refused to one who does not, and no entry either way', async () => {
  const w = await named();
  const id = await w.key();
  const { vault } = await isolate();
  assert.equal(codeOf(await vault.useNamed!(w.ask('NEVER_MADE'))), 'missing');
  assert.equal(await uses(), 0, 'nothing used');
  await w.revoke();
  // Revoked: a key made since and one never made are answered alike (Probing.tla, SameAnswer).
  const made = await w.key();
  assert.equal(codeOf(await vault.useNamed!(w.ask(await w.nameOf(made)))), 'no_grant');
  assert.equal(codeOf(await vault.useNamed!(w.ask('NEVER_MADE'))), 'no_grant');
  assert.equal(codeOf(await vault.useNamed!(w.ask(await w.nameOf(id)))), 'no_grant');
  // Neither key held has a row of the cap's of theirs: each use would take the principal's lock, so their standing
  // decides first, refuses them there, and nothing is written, as for the key never made (T158, DecideBeforeLock). The
  // app's own entry records each request, as for a key the place does not hold.
  assert.equal(await uses(), 0, 'refused before the lock: no entry, for a key held or not');
  assert.equal(await bulk(), 0, "nor a row of the cap's");
});

test('a plain value is decided as any, handed back as its text, and neither logged nor counted', async () => {
  const w = await named({ count: 1 });
  const { name } = await w.plain('eu-west-3');
  const { vault } = await isolate();
  const allowed = served(await vault.useNamed!(w.ask(name)));
  assert.deepEqual(allowed.outcome.ok && 'plain' in allowed.outcome ? allowed.outcome.plain : null, 'eu-west-3');
  assert.equal(await uses(), 0);
  assert.equal(await bulk(), 0, 'no row of the cap: a plain value counts toward nothing');
  // A secret value beside, under a cap of one: the plain one took nothing of it.
  assert.equal(codeOf(await vault.useNamed!(w.ask(await w.nameOf(await w.key())))), 'ok');
  await w.revoke();
  assert.equal(codeOf(await vault.useNamed!(w.ask(name))), 'no_grant');
});

test('a map out of date is read again once: a key deleted and made again under its name between two uses is the new one, the first attempt having written nothing', async () => {
  const w = await named();
  const old = await w.key('old-value');
  const name = await w.nameOf(old);
  const { vault } = await isolate();
  assert.equal(codeOf(await vault.useNamed!(w.ask(name))), 'ok');
  assert.equal(await uses(), 1);
  // Archived (`secret.delete`), its row under another name, and a key of the first name made: another id.
  await change({ kind: 'secret', id: old }, { op: 'secret.delete' }, null, async (tx) => {
    await run(tx, sql`UPDATE secrets SET archived_at = ${new Date()}, key = ${`${name}_GONE`} WHERE id = ${old}`);
  });
  const fresh = await w.key('new-value');
  await run(db.owner, sql`UPDATE secrets SET key = ${name} WHERE id = ${fresh}`);
  const again = served(await vault.useNamed!(w.ask(name)));
  assert.equal(again.outcome.ok, true);
  assert.equal(await uses(), 2, "one entry more: the retry's, none for the attempt by the old id");
  const [newest] = await rows<{ secret: string }>(db.owner, sql`SELECT secret FROM log_uses ORDER BY number DESC LIMIT 1`);
  assert.equal(newest!.secret, fresh);
});

/** Each of `keys` used once while the caller stands, so that each name is mapped, then its row of the cap's gone, as a window passing leaves it: each key's next use would take the principal's lock. */
async function mapped(cost: (key: string, purpose?: NamedUseInput['purpose']) => Promise<unknown[]>, keys: string[], purpose?: NamedUseInput['purpose']) {
  for (const key of keys) await cost(key, purpose);
  await run(db.owner, sql`DELETE FROM log_bulk`);
}

test("a credential revoked around the log (0.14's code, mid-upgrade) leaves no standing kept: a key held and one never made are refused alike, in one statement, before any lock (T158, DecideEachLock; review d1 of #416)", { ...postgresOnly('advisory locks'), timeout: 60_000 }, async () => {
  const w = await named();
  const held = await w.nameOf(await w.key());
  const { cost, end } = await costed(w);
  try {
    await mapped(cost, [held, 'NEVER_MADE']);
    // As 0.14's revoke writes it: the row alone, no change of the log's, no seal.
    await run(db.owner, sql`UPDATE credentials SET revoked_at = ${new Date()} WHERE id = ${w.credentialId}`);
    const answers = await holding(principalLock(w.principal), async () => [await cost(held), await cost('NEVER_MADE')]);
    assert.deepEqual(answers[0], answers[1], JSON.stringify(answers));
    assert.equal(answers[0]![1], 1, 'one statement, no lock waited for');
    assert.notEqual(answers[0]![0], 'ok');
  } finally {
    await end();
  }
});

test("a use allowed is no standing for reading: a Contributor, who may use and not read, is refused a reveal alike for a key held and one never made, before any lock (T158; review d1 of #416)", { ...postgresOnly('advisory locks'), timeout: 60_000 }, async () => {
  const w = await named({ role: 'contributor' });
  const held = await w.nameOf(await w.key());
  const { cost, end } = await costed(w);
  try {
    await mapped(cost, [held, 'NEVER_MADE'], 'use');
    assert.deepEqual(await cost(held, 'use'), ['ok', 2], 'its row of the cap\'s gone: decided, then made');
    await run(db.owner, sql`DELETE FROM log_bulk`);
    const answers = await holding(principalLock(w.principal), async () => [await cost(held, 'reveal'), await cost('NEVER_MADE', 'reveal')]);
    assert.deepEqual(answers, [['no_grant', 1], ['no_grant', 1]]);
  } finally {
    await end();
  }
});

test("a use refused on its cover is answered in its one statement, as a key never made is: past a grant's end, which no change records (T158, CoveredRefusalAnswered; review d1 of #416)", { ...postgresOnly('statements counted'), timeout: 60_000 }, async () => {
  const w = await named();
  const held = await w.nameOf(await w.key());
  const ends = Date.now() + 1500;
  const grant = { ...w.grant, expiresAt: ends };
  await change({ kind: 'principal', id: w.principal }, { op: 'access.grant', grant },
    { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [grant] }, async (tx, value) => {
      await run(tx, sql`UPDATE vault_grants SET expires_at = ${ends} WHERE principal = ${w.principal}`);
      await seal('vault_members', 'principal', w.principal)(tx, value);
    });
  const { cost, end } = await costed(w);
  try {
    // Used twice, fresh in the set: the isolate's cover of it, which a repeat rides.
    assert.equal((await cost(held))[0], 'ok');
    assert.deepEqual(await cost(held), ['ok', 1]);
    assert.equal((await cost('NEVER_MADE'))[0], 'missing');
    await sleep(Math.max(0, ends - Date.now()) + 50);
    assert.deepEqual([await cost(held), await cost('NEVER_MADE')], [['expired', 1], ['expired', 1]]);
  } finally {
    await end();
  }
});

test("revoked, someone whose isolate holds a name as none, or a key's id, is refused in one statement once a key is made under it, or deleted, as for a key never made: the standing decides before the names are read again (T158, MovedByStanding; review d2 of #416)", { ...postgresOnly('statements counted'), timeout: 60_000 }, async () => {
  const w = await named();
  const goneId = await w.key();
  const gone = await w.nameOf(goneId);
  const { cost, end } = await costed(w);
  try {
    // Each name read once while they stand: one held, two as none.
    for (const key of [gone, 'LATER', 'NEVER_MADE']) await cost(key);
    await w.revoke();
    const entries = await uses();
    for (const key of [gone, 'LATER', 'NEVER_MADE']) assert.deepEqual(await cost(key), ['no_grant', 1], key);
    // Made under a name held as none; deleted by the id held.
    const made = await w.key();
    await run(db.owner, sql`UPDATE secrets SET key = 'LATER' WHERE id = ${made}`);
    await change({ kind: 'secret', id: goneId }, { op: 'secret.delete' }, null, async (tx) => {
      await run(tx, sql`UPDATE secrets SET archived_at = ${new Date()}, key = ${`${gone}_GONE`} WHERE id = ${goneId}`);
    });
    for (const key of ['LATER', gone, 'NEVER_MADE']) assert.deepEqual(await cost(key), ['no_grant', 1], key);
    // Nothing written, the key held fresh in the set included: a caller who does not stand there has no key read, and
    // the app's entry alone records their request (W268, NoKeyBeforeStanding).
    assert.equal(await uses(), entries);
  } finally {
    await end();
  }
});

test("a seal a writer replaced, its row's content the same, leaves no standing kept: a key held and one never made are refused alike, in one statement, before any lock (T158, DecideEachLock; review d2 of #416)", { ...postgresOnly('advisory locks'), timeout: 60_000 }, async () => {
  const w = await named();
  const held = await w.nameOf(await w.key());
  const { cost, end } = await costed(w);
  try {
    await mapped(cost, [held, 'NEVER_MADE']);
    // Another seal, of the same length, on the same row: one byte of it changed.
    await run(db.owner, sql`UPDATE credentials SET seal = set_byte(seal, 0, (get_byte(seal, 0) + 1) % 256) WHERE id = ${w.credentialId}`);
    const answers = await holding(principalLock(w.principal), async () => [await cost(held), await cost('NEVER_MADE')]);
    assert.deepEqual(answers, [['tampered', 1], ['tampered', 1]]);
  } finally {
    await end();
  }
});

test('a refusal is one statement, whatever the map holds; a use the map has no ids for is made in a second, and the map keeps them (T158, D153)', { ...postgresOnly('statements counted'), timeout: 60_000 }, async () => {
  const w = await named();
  const held = await w.nameOf(await w.key());
  const { cost, end } = await costed(w);
  try {
    assert.deepEqual(await cost(held), ['ok', 2], 'read by its names, then made by the ids read');
    assert.deepEqual(await cost('LATER'), ['missing', 1], 'decided on what its names read: nothing');
    assert.deepEqual(await cost(held), ['ok', 1], 'by the ids the map keeps');
    assert.deepEqual(await cost('LATER'), ['missing', 1], 'the map holding it as none');
    // Made since, under that name: the use reads it by its name, then makes it by its id.
    const made = await w.key('later-value');
    await run(db.owner, sql`UPDATE secrets SET key = 'LATER' WHERE id = ${made}`);
    assert.deepEqual(await cost('LATER'), ['ok', 2]);
  } finally {
    await end();
  }
});

test("a key renamed, or a token's hash swapped, is `moved`: nothing written, the names read again, and the request answered as they are now", async () => {
  const w = await named();
  const id = await w.key();
  const name = await w.nameOf(id);
  const { vault } = await isolate();
  assert.equal(codeOf(await vault.useNamed!(w.ask(name))), 'ok');
  await run(db.owner, sql`UPDATE secrets SET key = ${`${name}_RENAMED`} WHERE id = ${id}`);
  assert.equal(codeOf(await vault.useNamed!(w.ask(name))), 'missing', 'the name the request named holds nothing now');
  assert.equal(codeOf(await vault.useNamed!(w.ask(`${name}_RENAMED`))), 'ok');
  // A writer moves the token's hash off its credential: the request's token names no credential now.
  await run(db.owner, sql`UPDATE credentials SET token_hash = ${randomBytes(32)} WHERE id = ${w.credentialId}`);
  assert.equal(codeOf(await vault.useNamed!(w.ask(`${name}_RENAMED`))), 'credential');
  assert.equal(await uses(), 1, "one entry: the first use's, which the use of the key renamed rides (its cover: the same credential and key)");
});

test('a vault too busy answers busy before it reads anything: a key held and one never made alike', async () => {
  const w = await named();
  const id = await w.key();
  // Every call in flight taken: nothing is read, whatever the request names.
  const full = await isolate({ uses: { inFlight: 0 } });
  assert.equal(codeOf(await full.vault.useNamed!(w.ask(await w.nameOf(id)))), 'busy:overloaded');
  assert.equal(codeOf(await full.vault.useNamed!(w.ask('NEVER_MADE'))), 'busy:overloaded');
  assert.equal(await uses(), 0);
});

test('an archived place is served by nothing by name: archived after its names were mapped, the use writes nothing, and the app answers it as ever', async () => {
  const w = await named();
  const id = await w.key();
  const name = await w.nameOf(id);
  const { vault } = await isolate();
  assert.equal(codeOf(await vault.useNamed!(w.ask(name))), 'ok');
  for (const archive of [sql`UPDATE environments SET archived_at = ${new Date()} WHERE id = ${w.dev}`, sql`UPDATE projects SET archived_at = ${new Date()} WHERE id = ${w.project}`]) {
    await run(db.owner, archive);
    assert.deepEqual(await vault.useNamed!(w.ask(name)), { served: false }, 'mapped before: the use finds it archived (`nowhere`), writing nothing');
    assert.deepEqual(await (await isolate()).vault.useNamed!(w.ask(name)), { served: false }, 'mapped afresh: named by nothing');
    await run(db.owner, sql`UPDATE environments SET archived_at = NULL WHERE id = ${w.dev}`);
    await run(db.owner, sql`UPDATE projects SET archived_at = NULL WHERE id = ${w.project}`);
  }
  assert.equal(await uses(), 1, "the first use's entry alone");
});

test("a handle's one environment, no place named: found by the vault, its slugs answered, and served by nothing where the request says it does not mean it", async () => {
  const w = await named();
  const id = await w.key();
  const name = await w.nameOf(id);
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev, personal: false }])} WHERE id = ${w.credentialId}`);
  const { vault } = await isolate();
  const made = byName(await vault.useNamed!(w.ask(name, { place: null })));
  assert.equal(made.outcome.ok, true);
  assert.deepEqual(made.place, { project: w.slug, environment: 'dev' });
  // The URL's own segments name that environment: not the stable URL's, nothing used.
  const before = await uses();
  assert.deepEqual(await vault.useNamed!(w.ask(name, { place: null, unless: [{ project: w.slug, environment: 'dev' }] })), { served: false });
  assert.equal(await uses(), before, 'nothing written');
  assert.equal(codeOf(await vault.useNamed!(w.ask(name, { place: null, unless: [{ project: w.slug, environment: 'prod' }] }))), 'ok');
  // Renamed since its slugs were read (a change, sealed, as the app makes it): held to them, `moved`, read again, and
  // answered as it is named now.
  await change({ kind: 'environment', id: w.dev }, { op: 'environment.rename', slug: 'development' },
    { ...(w.objects.environment as Extract<Input, { kind: 'environment' }>), slug: 'development' }, async (tx, value) => {
      await run(tx, sql`UPDATE environments SET slug = 'development' WHERE id = ${w.dev}`);
      await seal('environments', 'id', w.dev)(tx, value);
    });
  assert.deepEqual(byName(await vault.useNamed!(w.ask(name, { place: null }))).place, { project: w.slug, environment: 'development' });
  assert.deepEqual(await vault.useNamed!(w.ask(name, { place: null, unless: [{ project: w.slug, environment: 'development' }] })), { served: false });
  // A handle of two environments: none of them.
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev, personal: false }, { environmentId: w.dev, personal: true }])} WHERE id = ${w.credentialId}`);
  const after = await uses();
  assert.deepEqual(await (await isolate()).vault.useNamed!(w.ask(name, { place: null })), { served: false });
  assert.equal(await uses(), after, 'nothing written');
});


test("a place renamed and its slug taken by a new one, the caller's grant moved there: a key the map holds for the old place is decided, and used, at the place named now (D150; review d4 of #416)", async () => {
  const w = await named({ role: 'developer' });
  const old = await w.key('sk_old');
  const name = await w.nameOf(old);
  const { vault } = await isolate();
  assert.equal(codeOf(await vault.useNamed!(w.ask(name))), 'ok', "the map holds the old place, and its key's id");
  await w.rename(w.dev, 'dev-old');
  const fresh = await w.environment('dev');
  const now = await w.key('sk_new', false, fresh);
  await run(db.owner, sql`UPDATE secrets SET key = ${name} WHERE id = ${now}`);
  await w.revoke();
  await w.grantAt(fresh, 'developer');
  const used = byName(await vault.useNamed!(w.ask(name)));
  assert.equal(used.outcome.ok, true, 'standing where the request names, not where the map pointed');
  assert.equal(used.secretId, now);
  // Never asked before: the same.
  assert.equal(codeOf(await (await isolate()).vault.useNamed!(w.ask(name))), 'ok');
});

test("a handle's stable URL is held to the handle's own place by its id, whatever slugs the map holds for it: another place's, their key's, is not used (D150)", async () => {
  const w = await named({ role: 'developer' });
  const own = await w.key('sk_own');
  const name = await w.nameOf(own);
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev, personal: false }])} WHERE id = ${w.credentialId}`);
  const qa = await w.environment('qa');
  const there = await w.key('sk_there', false, qa);
  await run(db.owner, sql`UPDATE secrets SET key = ${name} WHERE id = ${there}`);
  await w.grantAt(qa, 'developer');
  const { vault, cache } = await isolate();
  // The map holds `qa` for the handle, its slugs and its key's id, all of them consistent: only its id tells.
  cache.name(`${w.tokenHash.toString('base64')}\n\n`, { credential: w.credentialId, environment: qa, slugs: { project: w.slug, environment: 'qa' } });
  cache.key(qa, name, there);
  const used = byName(await vault.useNamed!(w.ask(name, { place: null })));
  assert.equal(used.secretId, own, "the handle's own place's key");
  assert.deepEqual(used.place, { project: w.slug, environment: 'dev' });
  assert.equal(used.outcome.ok && 'value' in used.outcome, true);
});

test("revoked, their principal's lock held and every statement 1.1 s slow (review r4 of #412): a key made since, one used before, one deleted since and one never made are refused alike, at once, nothing locked or written (T158)", { ...postgresOnly('advisory locks'), timeout: 120_000 }, async () => {
  const w = await named();
  const used = await w.nameOf(await w.key());
  const deletedId = await w.key();
  const deleted = await w.nameOf(deletedId);
  // The key used before stays fresh in the cap's set only within its period (a minute, at the 15-minute window): one
  // passed between its use and its request would move it on, a `share` that decides first and writes no entry. So the
  // test starts with half a minute left of one, which it takes far less than.
  const period = refreshMs({ count: 1000, windowMs: 15 * 60_000 });
  if (period - (Date.now() % period) < 30_000) await sleep(period - (Date.now() % period) + 50);
  const { vault, statements, slow, end } = await slowed();
  try {
    // Allowed, before: two keys used (each now fresh in the cap's set), one never made asked (`missing`); the isolate
    // keeps the caller's standing at dev, as of the log's newest change.
    for (const key of [used, deleted]) assert.equal(codeOf(await vault.useNamed!(w.ask(key))), 'ok');
    assert.equal(codeOf(await vault.useNamed!(w.ask('NEVER_MADE'))), 'missing');
    await w.revoke();
    const made = await w.nameOf(await w.key());
    await change({ kind: 'secret', id: deletedId }, { op: 'secret.delete' }, null, async (tx) => {
      await run(tx, sql`UPDATE secrets SET archived_at = ${new Date()}, key = ${`${deleted}_GONE`} WHERE id = ${deletedId}`);
    });
    const keys = [made, used, deleted, 'NEVER_MADE'];
    // Each name read once since the changes, as any request of theirs does: the map then holds each, an id or none.
    for (const key of keys) assert.equal(codeOf(await vault.useNamed!(w.ask(key))), 'no_grant', key);
    const entries = await uses();
    const rowsOfCap = await bulk();
    slow(1100);
    const answers = await holding(principalLock(w.principal), async () => {
      const answered: { key: string; code: string; statements: number; ms: number }[] = [];
      for (const key of keys) {
        const before = statements();
        const started = performance.now();
        const code = codeOf(await vault.useNamed!(w.ask(key)));
        answered.push({ key, code, statements: statements() - before, ms: performance.now() - started });
      }
      return answered;
    });
    slow(0);
    // The same answer, in one statement each, which waits for no lock: a key that took the lock would wait its 1 s
    // lock_timeout and answer busy, a statement more would show in the count. Each well within the 3 s deadline, a
    // loaded host's slack beside the statement's 1.1 s.
    assert.deepEqual(answers.map(({ code, statements: n }) => [code, n]), keys.map(() => ['no_grant', 1]), JSON.stringify(answers));
    for (const { key, ms } of answers) assert.ok(ms < 2900, `${key}: ${Math.round(ms)} ms`);
    assert.equal(await bulk(), rowsOfCap, "no row of the cap's written");
    // None wrote anything, the key used before, fresh in the set, included: no key is read for a caller who does not
    // stand there, so no use of one is made (W268, NoKeyBeforeStanding).
    assert.equal(await uses(), entries);
  } finally {
    await end();
  }
});

test("a credential the app's config does not accept is answered as a token no credential has, in one statement, before its place, its key or any lock: behind Cloudflare Access, or a browser session of a provider the deployment no longer configures (reviews r6 and r7 of D153; Probing.tla, AcceptedFirst)", { timeout: 60_000 }, async () => {
  const w = await named({ caller: 'person', identity: { provider: 'github', issuerHash: 'f00d' } });
  // A key held, which they have never used, so that its use would take their principal's lock; and one never made.
  const held = await w.nameOf(await w.key());
  const { vault, statements, end } = await slowed();
  try {
    const asked = async (accepts: NamedUseInput['accepts']) => {
      const answered: { key: string; route: string; statements: number; ms: number }[] = [];
      for (const key of [held, 'NEVER_MADE']) {
        const before = statements();
        const started = performance.now();
        const outcome = served(await vault.useNamed!(w.ask(key, { accepts })));
        answered.push({ key, route: outcome.route, statements: statements() - before, ms: performance.now() - started });
      }
      return answered;
    };
    const [entries, rowsOfCap] = [await uses(), await bulk()];
    for (const accepts of [{ signin: false, issuers: ['github:f00d'] }, { signin: true, issuers: ['google:beef'] }]) {
      const answers = ENGINE === 'postgres' ? await holding(principalLock(w.principal), () => asked(accepts)) : await asked(accepts);
      // Each the credential's own check's (401), in one statement, none waiting for the lock it holds.
      assert.deepEqual(answers.map(({ route, statements: n }) => [route, n]), [['credential', 1], ['credential', 1]], JSON.stringify({ accepts, answers }));
      for (const { key, ms } of answers) assert.ok(ms < 900, `${key}: ${Math.round(ms)} ms`);
    }
    assert.deepEqual([await uses(), await bulk()], [entries, rowsOfCap], 'nothing written');
    // Accepted, its provider configured: served by name.
    assert.equal(codeOf(await vault.useNamed!(w.ask(held, { accepts: { signin: true, issuers: ['github:f00d'] } }))), 'ok');
  } finally {
    await end();
  }
});

for (const lost of ['revoked', 'its grant lapsed'] as const) {
  test(`a named call never runs the cached form, so a refusal after a use allowed costs what one of a key never made does: ${lost} (Fable's review, review r12 of D153)`, { timeout: 60_000 }, async () => {
    const w = await named();
    const held = await w.nameOf(await w.key());
    // Its grant ends in 1.5 s with no change of the log's when it lapses (a change of its own, sealed, sets the end).
    const ends = Date.now() + 1500;
    if (lost === 'its grant lapsed') {
      const grant = { ...w.grant, expiresAt: ends };
      await change({ kind: 'principal', id: w.principal }, { op: 'access.grant', grant },
        { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [grant] }, async (tx, value) => {
          await run(tx, sql`UPDATE vault_grants SET expires_at = ${ends} WHERE principal = ${w.principal}`);
          await seal('vault_members', 'principal', w.principal)(tx, value);
        });
    }
    const { vault, cache, last, end } = await slowed();
    try {
      // Allowed, by name: nothing kept for a later call's cached form, which by ids it would be.
      assert.equal(codeOf(await vault.useNamed!(w.ask(held))), 'ok');
      assert.equal(cache.seals.size, 0, 'a named use keeps no seals');
      if (lost === 'revoked') await w.revoke();
      else await sleep(Math.max(0, ends - Date.now()) + 50);
      // Refused, three times each: the probe's form each time, whatever the key, and still nothing kept.
      for (let round = 0; round < 3; round += 1) {
        for (const key of [held, 'NEVER_MADE']) {
          assert.equal(codeOf(await vault.useNamed!(w.ask(key))), lost === 'revoked' ? 'no_grant' : 'expired', `${key}, round ${round}`);
          if (ENGINE === 'postgres') assert.equal(last()!.args[11], null, `${key}, round ${round}: the probe's form, no seals passed`);
          assert.equal(cache.seals.size, 0, `${key}, round ${round}: no seals kept`);
        }
      }
    } finally {
      await end();
    }
  });
}

/** A vault over a slowed pool, and a use's answer and the statements it took. */
async function costed(w: Awaited<ReturnType<typeof named>>) {
  const slow = await slowed();
  const cost = async (key: string, purpose?: NamedUseInput['purpose']) => {
    const before = slow.statements();
    const code = codeOf(await slow.vault.useNamed!(w.ask(key, purpose === undefined ? {} : { purpose })));
    return [code, slow.statements() - before];
  };
  return { cost, end: slow.end };
}

test("no use is kept for a later one to take the principal's lock on: each that would take it is decided first, a second statement, whatever happened since (T158, D153; DecideEachLock)", { ...postgresOnly('advisory locks'), timeout: 60_000 }, async () => {
  const w = await named();
  const a = await w.nameOf(await w.key());
  const { cost, end } = await costed(w);
  // Its row of the cap's gone, as a window passed: its next use would take the principal's lock.
  const passed = () => run(db.owner, sql`DELETE FROM log_bulk WHERE principal = ${w.principal}`);
  try {
    // Read by its names, then made, decided.
    assert.deepEqual(await cost(a), ['ok', 2]);
    // Nothing changed since: decided again all the same, then made.
    await passed();
    assert.deepEqual(await cost(a), ['ok', 2]);
    // A 0.14 write of the principal's access, mid-upgrade, which is no change of the log's: decided, and the rows it read
    // refuse it (UsesSeeOldWrites), before any lock, the principal's lock held all the while.
    // Written at the 0.14 log's head, which it moves on, as 0.14's code writes one: the log stays whole for what follows.
    await run(db.owner, sql`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, subject_principal, metadata, prev_hash, mac, hash)
      SELECT h.next_seq, 'vault', 'vault:x', ${Date.now()}, 'system:x', 'access.grant', 'allow', ${w.principal}, '{}', h.head_hash, ${Buffer.alloc(32)}, ${Buffer.alloc(32)}
        FROM audit_chain_head h WHERE h.only_row`);
    await run(db.owner, sql`UPDATE audit_chain_head SET next_seq = next_seq + 1, head_hash = ${Buffer.alloc(32)} WHERE only_row`);
    await passed();
    assert.deepEqual(await holding(principalLock(w.principal), () => cost(a)), ['stale', 1]);
  } finally {
    await end();
  }
});

test("past a grant's end, which no change records, the use is decided first, before any lock (T158; DecideEachLock)", { ...postgresOnly('advisory locks'), timeout: 60_000 }, async () => {
  const w = await named();
  const a = await w.nameOf(await w.key());
  // Its grant ends in 1.5 s: a change of its own, sealed, before any use.
  const ends = Date.now() + 1500;
  const grant = { ...w.grant, expiresAt: ends };
  await change({ kind: 'principal', id: w.principal }, { op: 'access.grant', grant },
    { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [grant] }, async (tx, value) => {
      await run(tx, sql`UPDATE vault_grants SET expires_at = ${ends} WHERE principal = ${w.principal}`);
      await seal('vault_members', 'principal', w.principal)(tx, value);
    });
  const { cost, end } = await costed(w);
  try {
    assert.deepEqual(await cost(a), ['ok', 2]);
    // Past the grant's end: no use kept passes, the use is decided first, and refused, the principal's lock held all the
    // while.
    await sleep(Math.max(0, ends - Date.now()) + 50);
    await run(db.owner, sql`DELETE FROM log_bulk WHERE principal = ${w.principal}`);
    assert.deepEqual(await holding(principalLock(w.principal), () => cost(a)), ['expired', 1]);
  } finally {
    await end();
  }
});

test('a read of ids left behind at its deadline keeps its place in admission until it settles (review r1 of #412)', postgresOnly('a table lock'), async () => {
  const w = await named();
  const name = await w.nameOf(await w.key());
  const { vault } = await isolate({ uses: { inFlight: 1 } });
  // The credentials table locked: the use's read of its names waits for it, past the request's deadline.
  const [first, second] = await holding(sql`LOCK TABLE credentials IN ACCESS EXCLUSIVE MODE`, async () => {
    const at = Date.now();
    const late = codeOf(await vault.useNamed!(w.ask(name, { at, deadline: at + 200 })));
    return [late, codeOf(await vault.useNamed!(w.ask(name)))];
  }, true);
  assert.equal(first, 'busy:late');
  assert.equal(second, 'busy:overloaded', 'the first read still holds its connection, and its place');
  await sleep(100);
  assert.equal(codeOf(await vault.useNamed!(w.ask(name))), 'ok', 'settled, it gave its place back');
});

test("rows the seals do not bear out give no standing: a grant a writer put back after its revoke is the account's, which routes the request to the credential's own check (reviews r1 of #412, r2 of D153)", async () => {
  const w = await named();
  const name = await w.nameOf(await w.key());
  const { vaultGrants } = tablesOf(db.owner);
  const grants = await db.owner.select().from(vaultGrants).where(sql`${vaultGrants.principal} = ${w.principal}`);
  await w.revoke();
  await db.owner.insert(vaultGrants).values(grants);
  const { vault } = await isolate();
  const forged = served(await vault.useNamed!(w.ask(name)));
  assert.equal(forged.outcome.ok, false);
  assert.equal(forged.route, 'credential', "the account's row is not as sealed: the app asks the vault, as ever");
});

test("a use by ids logs its request whatever it finds, as before names, its key in the principal's set: a key archived since the app read it; one not in the set is decided first, and logs nothing (reviews r2 of #412, r2 of D153)", async () => {
  const w = await named();
  const id = await w.key();
  const other = await w.key();
  const { use } = await isolate();
  const asked = (secretId: string) => {
    const at = Date.now();
    return use({ credential: w.credentialId, secretId, place: null, purpose: 'use', requestId: newRequestId(), at, deadline: at + 3000 });
  };
  assert.equal((await asked(id)).ok, true);
  for (const key of [id, other]) {
    await change({ kind: 'secret', id: key }, { op: 'secret.delete' }, null, async (tx) => {
      await run(tx, sql`UPDATE secrets SET archived_at = ${new Date()} WHERE id = ${key}`);
    });
  }
  const outcome = await asked(id);
  assert.deepEqual(outcome.ok ? 'ok' : 'code' in outcome ? outcome.code : 'busy', 'missing');
  assert.equal(await uses(), 2, 'the refused request, logged');
  assert.deepEqual(await asked(other), { ok: false, code: 'missing', number: null });
  assert.equal(await uses(), 2, 'nothing written: the app asks again');
});

test('a fork, which the app reads with its layers, is not served by name', async () => {
  const w = await named();
  const fork = randomUUID();
  await db.owner.insert(tablesOf(db.owner).environments).values({ id: fork, projectId: w.project, slug: 'fork', name: 'Fork', protected: false, parentId: w.dev });
  const { vault } = await isolate();
  assert.deepEqual(await vault.useNamed!(w.ask('ANY', { place: { project: w.slug, environment: 'fork' } })), { served: false });
});

test("an isolate's map of names keeps the most recently used, up to its cap, and none at a cap of 0", () => {
  const ids = (credential: string): Resolved => ({ credential, environment: 'e', slugs: { project: 'p', environment: 'e' } });
  const cache = new UseCache(useLimits(1, { names: 2 }));
  cache.name('a', ids('a'));
  cache.name('b', ids('b'));
  assert.equal(cache.named('a')?.credential, 'a', 'a, used: the most recent now');
  cache.name('c', ids('c'));
  assert.deepEqual([...cache.names.keys()], ['a', 'c'], 'b, the least recently used, gone');
  const none = new UseCache(useLimits(1, { names: 0 }));
  none.name('a', ids('a'));
  assert.equal(none.named('a'), undefined);
  // Key ids apart, by environment and name, bounded alike: names asked and dropped leave none behind (review r3 of #412).
  const keys = new UseCache(useLimits(1, { names: 2 }));
  for (const name of ['A', 'B', 'C', 'D']) keys.key('e', name, `id-${name}`);
  assert.deepEqual([...keys.keyIds.keys()], ['e\nC', 'e\nD']);
  assert.equal(keys.keyed('e', 'A'), undefined);
});

test("a stable URL's places it does not mean are judged against the slugs the call reads, never the map's: renamed since, a warm map costs what a cold one does (review r2 of D153)", async () => {
  const w = await named();
  const name = await w.nameOf(await w.key('sk_handle'));
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev, personal: false }])} WHERE id = ${w.credentialId}`);
  const warm = await slowed();
  const cold = await slowed();
  try {
    // The map holds the handle's place as `dev`; then it is renamed `live`, and they lose their grant.
    assert.equal(codeOf(await warm.vault.useNamed!(w.ask(name, { place: null }))), 'ok');
    await w.rename(w.dev, 'live');
    await w.revoke();
    // The URL's segments name `dev`, which the handle's place no longer is: its own place's key, refused by name.
    const ask = () => w.ask(name, { place: null, unless: [{ project: w.slug, environment: 'dev' }] });
    const answered = async (slow: typeof warm) => {
      const before = slow.statements();
      const answer = await slow.vault.useNamed!(ask());
      return [served(answer).route, codeOf(answer), slow.statements() - before];
    };
    assert.deepEqual(await answered(warm), await answered(cold));
    assert.equal((await answered(cold))[0], 'name');
    // Its own place named by the URL: not served by name, warm or cold, as its slugs are read now.
    const own = () => w.ask(name, { place: null, unless: [{ project: w.slug, environment: 'live' }] });
    assert.deepEqual(await warm.vault.useNamed!(own()), { served: false });
    assert.deepEqual(await cold.vault.useNamed!(own()), { served: false });
  } finally {
    await warm.end();
    await cold.end();
  }
});

test("a handle's places that are no single place, read before its credential is checked, resolve to none, never an error: the credential's own check answers (review r2 of D153)", async () => {
  const w = await named();
  const name = await w.nameOf(await w.key('sk_forged'));
  const { vault } = await isolate();
  for (const places of ['[{"environmentId":"not-a-uuid","personal":false}]', 'not json', '{"environmentId":"x"}', '[1]', '[{"environmentId":5}]', `[{"environmentId":"${w.dev}","personal":"yes"}]`, '[]']) {
    // Written around its MAC, as only someone who owns the database could.
    await run(db.owner, sql`UPDATE credentials SET places = ${places} WHERE id = ${w.credentialId}`);
    assert.deepEqual(await vault.useNamed!(w.ask(name, { place: null })), { served: false }, places);
  }
  // A place it names by slugs is read as ever: the credential is the app's to check, on its MAC.
  assert.equal(served(await vault.useNamed!(w.ask(name))).served, true);
});

test("a reference whose source's environment is archived is the vault's refusal, by name, as a key never made is, map or none: never the app's path (review r4 of D153)", async () => {
  const w = await named();
  const elsewhere = await w.environment('src');
  const held = await w.reference('API_KEY', elsewhere);
  const name = 'API_KEY';
  const warm = await slowed();
  const cold = await slowed();
  try {
    // Read while its source is live: allowed, and the warm isolate's map holds its ids.
    assert.equal(codeOf(await warm.vault.useNamed!(w.ask(name))), 'ok');
    await w.archive(elsewhere, false);
    const answered = async (slow: typeof warm, key: string) => {
      const before = slow.statements();
      const answer = await slow.vault.useNamed!(w.ask(key));
      return [served(answer).route, codeOf(answer), slow.statements() - before];
    };
    const archived = await answered(warm, name);
    assert.deepEqual(archived, ['name', 'archived', 1], 'refused by name, in its one call, nothing written');
    assert.deepEqual(await answered(cold, name), archived, 'a cold map: the same');
    // A key never made, through either isolate: the same route and work, refused.
    assert.deepEqual((await answered(cold, 'NEVER_MADE')).filter((_, i) => i !== 1), ['name', 1]);
    assert.equal(held.source !== undefined, true);
  } finally {
    await warm.end();
    await cold.end();
  }
});
