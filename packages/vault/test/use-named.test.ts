// 0.15's use as the request names it (T145, PR B; use.ts, `useNamed`; formal/Probing.tla): the vault maps a token's
// hash, a place's slugs and a key's name to ids, from its isolate's map or with one read on a miss (`use_resolve`),
// and uses the key by them, holding its rows to the names (`moved`). A key the place does not hold, and a plain value,
// are decided on the caller's standing there, and leave no entry: nobody refused learns whether a key is held, at any
// load. A map out of date is read again once, its attempt having written and released nothing.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { encrypt, freshDek } from '@coffre/core/envelope';
import type { NamedUseInput, NamedUseOutcome } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { sql } from 'drizzle-orm';

import type { Input } from '../src/inputs.ts';
import { newRequestId, UseCache, useLimits, type Resolved } from '../src/use.ts';
import { ENGINE, openTestDatabase, postgresOnly, rows, run, type TestDatabase } from './database.ts';
import { change, CONFIG, emptyLog, genesis, isolate, ROOT, seal, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

/** A world whose credential's token is known, and the names its requests use: its project's slug, `dev`, a key's name. */
async function named(options: Parameters<typeof world>[0] = {}) {
  const w = await world(options);
  const tokenHash = randomBytes(32);
  await run(db.owner, sql`UPDATE credentials SET token_hash = ${tokenHash} WHERE id = ${w.credentialId}`);
  const [project] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM projects WHERE id = ${w.project}`);
  const nameOf = async (id: string) => (await rows<{ key: string }>(db.owner, sql`SELECT key FROM secrets WHERE id = ${id}`))[0]!.key;
  const ask = (key: string, extra: Partial<NamedUseInput> = {}): NamedUseInput => {
    const at = Date.now();
    return { tokenHash: tokenHash.toString('base64'), place: { project: project!.slug, environment: 'dev' }, key, purpose: 'use', requestId: newRequestId(), at, deadline: at + 3000, ...extra };
  };
  /** A plain value in `dev`, sealed: its text's digest in its object, no key. */
  const plain = async (text: string, name = `PLAIN_${randomUUID().slice(0, 4)}`) => {
    const t = tablesOf(db.owner);
    const id = randomUUID();
    const version = randomUUID();
    // Its version as the app writes a plain one: sealed as any, its text beside (app-places.test.ts, `newVersion`).
    const dek = freshDek();
    const context = { projectId: w.project, environmentId: w.dev, secretId: id };
    const sealed = encrypt(Buffer.from(text), context, dek);
    const wrapped = await CONFIG.keks.wrap(dek, context, { deadline: Date.now() + 5000, signal: new AbortController().signal });
    await db.owner.insert(t.secrets).values({ id, projectId: w.project, environmentId: w.dev, key: name });
    await db.owner.insert(t.secretVersions).values({
      id: version, secretId: id, version: 1, envelopeVersion: sealed.envelopeVersion, ciphertext: sealed.ciphertext, iv: sealed.iv, authTag: sealed.authTag,
      wrappedDek: wrapped.bytes, kekProvider: wrapped.kekProvider, kekId: wrapped.kekId, kekVersion: wrapped.kekVersion, createdBy: ROOT, sensitive: false, plaintext: text,
    });
    await run(db.owner, sql`UPDATE secrets SET current_version_id = ${version}, current_version = 1 WHERE id = ${id}`);
    const object: Input = {
      kind: 'secret', id, projectId: w.project, environmentId: w.dev, version, nature: 'plain', key: null,
      digest: createHash('sha256').update(text).digest('base64'), source: null, reference: null,
    };
    await genesis({ kind: 'secret', id }, object);
    return { id, name };
  };
  /** Revoke the member's grant on dev: a change to their object, as `access.revoke` makes it. */
  const revoke = () => change({ kind: 'principal', id: w.principal }, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } },
    { ...(w.objects.principal as Extract<Input, { kind: 'principal' }>), grants: [] }, async (tx, value) => {
      await run(tx, sql`DELETE FROM vault_grants WHERE principal = ${w.principal}`);
      await seal('vault_members', 'principal', w.principal)(tx, value);
    });
  return { ...w, tokenHash, project: w.project, slug: project!.slug, nameOf, ask, plain, revoke };
}

const uses = async () => Number((await rows<{ n: number | string }>(db.owner, sql`SELECT count(*) AS n FROM log_uses`))[0]!.n);
const bulk = async () => Number((await rows<{ n: number | string }>(db.owner, sql`SELECT count(*) AS n FROM log_bulk`))[0]!.n);
const served = (outcome: NamedUseOutcome) => {
  assert.equal(outcome.served, true);
  return outcome as Extract<NamedUseOutcome, { served: true }>;
};
const codeOf = (outcome: NamedUseOutcome) => {
  const { outcome: used } = served(outcome);
  return used.ok ? 'ok' : 'busy' in used ? `busy:${used.busy}` : used.code;
};

test("a named use opens the key it names, by the ids it reads once, and answers the caller as the use read them, and, on Postgres, the app's rows", async () => {
  const w = await named();
  const id = await w.key('sk_live_1');
  const { vault } = await isolate();
  const first = served(await vault.useNamed!(w.ask(await w.nameOf(id))));
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
  // Its map kept: the use again, by the same ids, with nothing read first, even with `use_resolve` gone.
  if (ENGINE === 'postgres') await run(db.owner, sql`REVOKE EXECUTE ON FUNCTION use_resolve(bytea, text, text, text[]) FROM coffre_vault`);
  try {
    assert.equal(codeOf(await vault.useNamed!(w.ask(await w.nameOf(id)))), 'ok');
  } finally {
    if (ENGINE === 'postgres') await run(db.owner, sql`GRANT EXECUTE ON FUNCTION use_resolve(bytea, text, text, text[]) TO coffre_vault`);
  }
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
  assert.equal(await uses(), 2, "the two uses of keys held are logged as their requests; the one never made, nothing");
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
    assert.deepEqual(await vault.useNamed!(w.ask(name)), { served: false }, 'mapped before: the use finds it archived (`unnamed`), writing nothing');
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
  const made = served(await vault.useNamed!(w.ask(name, { place: null })));
  assert.equal(made.outcome.ok, true);
  assert.deepEqual(made.place, { project: w.slug, environment: 'dev' });
  // The URL's own segments name that environment: not the stable URL's, nothing used.
  const before = await uses();
  assert.deepEqual(await vault.useNamed!(w.ask(name, { place: null, unless: [{ project: w.slug, environment: 'dev' }] })), { served: false });
  assert.equal(await uses(), before, 'nothing written');
  assert.equal(codeOf(await vault.useNamed!(w.ask(name, { place: null, unless: [{ project: w.slug, environment: 'prod' }] }))), 'ok');
  // Renamed since its slugs were read: held to them, `moved`, read again, and answered as it is named now.
  await run(db.owner, sql`UPDATE environments SET slug = 'development' WHERE id = ${w.dev}`);
  assert.deepEqual(served(await vault.useNamed!(w.ask(name, { place: null }))).place, { project: w.slug, environment: 'development' });
  assert.deepEqual(await vault.useNamed!(w.ask(name, { place: null, unless: [{ project: w.slug, environment: 'development' }] })), { served: false });
  // A handle of two environments: none of them.
  await run(db.owner, sql`UPDATE credentials SET places = ${JSON.stringify([{ environmentId: w.dev, personal: false }, { environmentId: w.dev, personal: true }])} WHERE id = ${w.credentialId}`);
  const after = await uses();
  assert.deepEqual(await (await isolate()).vault.useNamed!(w.ask(name, { place: null })), { served: false });
  assert.equal(await uses(), after, 'nothing written');
});

/** Hold `lock` on a connection of its own (the vault's, or with `owner` the database owner's) while `work` runs, then let it go. */
async function holding<T>(lock: ReturnType<typeof sql>, work: () => Promise<T>, owner = false): Promise<T> {
  const holder = owner ? db.owner : await db.connect(1);
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const held = holder.transaction(async (tx) => {
    await run(tx, lock);
    await released;
  });
  await sleep(50);
  try {
    return await work();
  } finally {
    release();
    await held;
  }
}

test("a lock held on the caller past the use's deadline: refused alike for a key made since, before and after a request of theirs wrote its cap's row, one never made and a plain value; busy to one who may act there (review r2 of #412)", postgresOnly('advisory locks'), async () => {
  const w = await named();
  await w.revoke();
  // Made since the revoke: a key, sealed, whose cap's row the caller has not written yet, and a plain value.
  const made = await w.nameOf(await w.key());
  const { name: plain } = await w.plain('eu-west-3');
  const { vault } = await isolate();
  const ask = (key: string) => {
    const at = Date.now();
    return w.ask(key, { at, deadline: at + 300 });
  };
  const all = async (keys: string[]) => {
    const codes: string[] = [];
    for (const key of keys) codes.push(codeOf(await vault.useNamed!(ask(key))));
    return codes;
  };
  // The principal's lock (0022: 1668244066, hashtext(principal)), which a key with no cap's row of theirs waits for.
  const lock = sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${w.principal}))`;
  // Its first request: the key made since waits for it, then its standing, asked without a lock, refuses.
  assert.deepEqual(await holding(lock, () => all([made, 'NEVER_MADE', plain])), ['no_grant', 'no_grant', 'no_grant']);
  // A request of theirs not held up writes its cap's row: the next waits for nothing, and is refused alike.
  assert.deepEqual(await all([made]), ['no_grant']);
  assert.deepEqual(await holding(lock, () => all([made, 'NEVER_MADE', plain])), ['no_grant', 'no_grant', 'no_grant']);
  // Someone who may act there waits, and is told busy: what they may know of the place.
  const other = await named();
  const key = await other.nameOf(await other.key());
  const busy = await holding(sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${other.principal}))`, async () => {
    const at = Date.now();
    return codeOf(await vault.useNamed!(other.ask(key, { at, deadline: at + 300 })));
  });
  assert.equal(busy, 'busy:late');
});

test("a late use's standing is asked within its own place in admission, once its call has let it go: refused alike with one place in all (review r3 of #412)", postgresOnly('advisory locks'), async () => {
  const w = await named();
  await w.revoke();
  const made = await w.nameOf(await w.key());
  // One place in admission: the late use's call, still waiting for the lock past its deadline, holds it.
  const { vault } = await isolate({ uses: { inFlight: 1 } });
  const ask = (key: string) => {
    const at = Date.now();
    return w.ask(key, { at, deadline: at + 300 });
  };
  const codes = await holding(sql`SELECT pg_advisory_xact_lock(1668244066, hashtext(${w.principal}))`, async () => [
    codeOf(await vault.useNamed!(ask(made))),
    codeOf(await vault.useNamed!(ask('NEVER_MADE'))),
  ]);
  assert.deepEqual(codes, ['no_grant', 'no_grant']);
});

test('a read of ids left behind at its deadline keeps its place in admission until it settles (review r1 of #412)', postgresOnly('a table lock'), async () => {
  const w = await named();
  const name = await w.nameOf(await w.key());
  const { vault } = await isolate({ uses: { inFlight: 1 } });
  // The credentials table locked: `use_resolve` waits for it, past the request's deadline.
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

test('rows the seals do not bear out give no standing: a grant a writer put back after its revoke (review r1 of #412)', async () => {
  const w = await named();
  const name = await w.nameOf(await w.key());
  const { vaultGrants } = tablesOf(db.owner);
  const grants = await db.owner.select().from(vaultGrants).where(sql`${vaultGrants.principal} = ${w.principal}`);
  await w.revoke();
  await db.owner.insert(vaultGrants).values(grants);
  const { vault } = await isolate();
  const forged = served(await vault.useNamed!(w.ask(name)));
  assert.equal(forged.outcome.ok, false);
  assert.equal(forged.standing, null, 'no standing: the app asks the vault, as ever');
});

test('a use by ids logs its request whatever it finds, as before names: a key archived since the app read it (review r2 of #412)', async () => {
  const w = await named();
  const id = await w.key();
  await change({ kind: 'secret', id }, { op: 'secret.delete' }, null, async (tx) => {
    await run(tx, sql`UPDATE secrets SET archived_at = ${new Date()} WHERE id = ${id}`);
  });
  const { use } = await isolate();
  const at = Date.now();
  const outcome = await use({ credential: w.credentialId, secretId: id, place: null, purpose: 'use', requestId: newRequestId(), at, deadline: at + 3000 });
  assert.deepEqual(outcome.ok ? 'ok' : 'code' in outcome ? outcome.code : 'busy', 'missing');
  assert.equal(await uses(), 1, 'the refused request, logged');
});

test('a fork, which the app reads with its layers, is not served by name', async () => {
  const w = await named();
  const fork = randomUUID();
  await db.owner.insert(tablesOf(db.owner).environments).values({ id: fork, projectId: w.project, slug: 'fork', name: 'Fork', protected: false, parentId: w.dev });
  const { vault } = await isolate();
  assert.deepEqual(await vault.useNamed!(w.ask('ANY', { place: { project: w.slug, environment: 'fork' } })), { served: false });
});

test("an isolate's map of names keeps the most recently used, up to its cap, and none at a cap of 0", () => {
  const ids = (credential: string): Resolved => ({ credential, project: 'p', environment: 'e', slugs: { project: 'p', environment: 'e' }, shared: false, keys: new Map() });
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
