import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { sql } from 'drizzle-orm';

import { entryOf, type Entry } from '../src/entry.ts';
import { Busy } from '../src/change.ts';
import { memoryOf, recall, read, answer, use, type Ask, type Value } from '../src/use.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, ask, binding, credential, dismissed, environment, grant, identity, instance, principal, project, role, rows, secret, session, user, value, write } from './world.ts';

const vault = await openTestVault();
after(() => vault.close());

const [ada, bo, cy, dee, ci] = [user('ada'), user('bo'), user('cy'), user('dee'), 'token:ci'];
const READS = ['secret.read', 'secret.use'];

/**
 * market: prod, staging (a fork of prod), Ada's personal config of staging,
 * and vault, protected. billing: prod, which market/prod's LINK refers to.
 * Ada views market; Bo, staging alone; Cy owns the instance; Dee holds
 * nothing; ci, a service account, views market.
 */
async function world() {
  const [market, billing] = [project('market'), project('billing')];
  const prod = environment(market, 'prod');
  const staging = environment(market, 'staging', { parentId: prod.id });
  const adas = environment(market, 'staging-ada', { parentId: staging.id, owner: ada });
  const guarded = environment(market, 'vault', { protected: true });
  const billed = environment(billing, 'prod');

  const token = await value(vault, secret(billed, 'API_TOKEN'), 'billing-token');
  const database = await value(vault, await value(vault, secret(prod, 'DATABASE_URL'), 'postgres://old'), 'postgres://prod');
  const stripe = await value(vault, secret(prod, 'STRIPE_KEY'), 'sk_live', { sensitive: true });
  const flag = await value(vault, secret(prod, 'FLAG'), 'on', { plain: true });
  const gone = await value(vault, secret(prod, 'OLD', { archivedAt: new Date(0) }), 'gone');
  const link = secret(prod, 'LINK', { sourceId: token.id });
  const hollow = secret(prod, 'HOLLOW');
  const forked = await value(vault, secret(staging, 'DATABASE_URL'), 'postgres://staging');
  const own = await value(vault, secret(adas, 'DATABASE_URL'), 'postgres://ada', { owner: ada });
  const root = await value(vault, secret(guarded, 'ROOT'), 'root-key');

  const scope = (more: object = {}) => JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer', ...more }]);
  await write(
    vault,
    ...rows('projects', market, billing),
    ...rows('environments', prod, staging, adas, guarded, billed),
    ...rows('secrets', token, database, stripe, flag, gone, link, hollow, forked, own, root),
    ...rows('dismissedKeys', dismissed(staging, 'FLAG')),
    ...rows('roles', role(true, 'owner', READS), role(true, 'member', []), role(false, 'viewer', READS, ['secret.use'])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { role: 'owner' }), principal(dee), principal(ci)),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant(bo, 'viewer', { environment: staging }), grant(ci, 'viewer', { project: market }), grant(ci, 'viewer', { project: billing })),
    ...rows('credentials', credential('ada', ada), credential('bo', bo), credential('cy', cy), credential('dee', dee), credential('ci', ci, { scope: scope() }), credential('ci-sensitive', ci, { scope: scope({ sensitive: true }) })),
  );
  return { market, billing, prod, staging, adas, guarded, billed, token, database, stripe, flag, link, forked, own, root };
}

let w: Awaited<ReturnType<typeof world>>;
beforeEach(async () => {
  await emptyDatabase(vault.owner);
  vault.woken.length = 0;
  Object.assign(vault, { memory: memoryOf(2), cap: { count: 1000, windowMs: 15 * 60_000 }, workloads: { noReads: false, useOnly: false } });
  w = await world();
  await vault.owner.execute(sql`DELETE FROM log_pending`);
  vault.woken.length = 0;
});

const given = (values: Value[]) => Object.fromEntries(values.map((each) => [each.key, 'refused' in each ? `refused: ${each.refused}` : each.value.toString()]));
/** A use's values by key, or the reason the whole of it is refused. */
async function got(asked: Ask): Promise<Record<string, string> | string> {
  const result = await use(vault, asked);
  return 'refused' in result ? result.refused : given(result.values);
}
const logged = async (): Promise<Entry[]> => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(vault.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => entryOf(vault.keys, row)!);
const exposed = () => rowsOf<{ principal: string; secret_id: string }>(vault.owner, sql`SELECT principal, secret_id FROM exposures ORDER BY principal, secret_id`);
/** Nothing written: no entry, no exposure, nobody woken. */
async function untouched(): Promise<void> {
  assert.deepEqual([await logged(), await exposed(), vault.woken], [[], [], []]);
}

test('a use is dated as its entry is written, and its write gives up after two seconds behind a lock', async () => {
  // Every look at the clock is a second later: the read, the decision, values opened through a slow key service, the write.
  let [last, step] = [vault.now(), 1000];
  const slow = { ...vault, now: () => (last += step) };
  assert.ok('values' in (await use(slow, ask('ada', 'market/prod', ['DATABASE_URL']))));
  assert.equal((await logged())[0]!.at, last);
  // What says Ada has seen the key is dated as the entry is.
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT (extract(epoch FROM seen_at) * 1000)::float8 AS at FROM exposures`), [{ at: last }]);
  // The minute it is logged once in starts at the entry's date: more than a minute after it was decided, it is not logged again.
  [last, step] = [last + 59_999, 0];
  assert.ok('values' in (await use(slow, ask('ada', 'market/prod', ['DATABASE_URL']))));
  assert.equal((await logged()).length, 1);

  // Past the minute a use is logged once in, behind someone who holds the row that says Ada has seen the key.
  vault.tick(120_000);
  let release!: () => void;
  const held = vault.owner.transaction(async (tx) => {
    await tx.execute(sql`SELECT 1 FROM exposures FOR UPDATE`);
    await new Promise<void>((resolve) => (release = resolve));
  });
  try {
    await new Promise((resolve) => setTimeout(resolve, 100));
    const started = Date.now();
    await assert.rejects(use(vault, ask('ada', 'market/prod', ['DATABASE_URL'])), Busy);
    assert.ok(Date.now() - started < 4000);
  } finally {
    release();
    await held;
  }
  // Nothing of it was written, nobody was told, and the next use is logged.
  assert.deepEqual([(await logged()).length, vault.woken.length], [1, 1]);
  assert.ok('values' in (await use(vault, ask('ada', 'market/prod', ['DATABASE_URL']))));
  assert.equal((await logged()).length, 2);
});

test('a reader is handed a key, and the use is logged once: who, with what, where, which version', async () => {
  const result = await use(vault, ask('ada', 'market/prod', ['DATABASE_URL']));
  assert.ok('values' in result);
  assert.deepEqual(result, { principal: ada, credential: result.credential, workload: null, values: [{ key: 'DATABASE_URL', secret: w.database.id, version: 2, sensitive: false, value: Buffer.from('postgres://prod') }] });
  const [entry, ...more] = await logged();
  assert.deepEqual(more, []);
  assert.deepEqual(
    { ...entry, id: null },
    {
      id: null, at: vault.now(), action: 'secret.read', actor: ada, credential: result.credential, request: 'req-1', ip: '192.0.2.7', rows: [],
      objects: [`project:${w.market.id}`, `environment:${w.prod.id}`, `principal:${ada}`, `credential:${result.credential}`, `secret:${w.database.id}`],
      detail: { purpose: 'reveal', keys: [{ key: 'DATABASE_URL', secret: w.database.id, version: 2 }] },
    },
  );
  assert.deepEqual(await exposed(), [{ principal: ada, secret_id: w.database.id }]);
  assert.equal(vault.woken.length, 1);
  // A use ages out of the log, and its credential says when it was last used.
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT kept FROM log_pending`), [{ kept: false }]);
  assert.deepEqual(await rowsOf(vault.owner, sql`SELECT last_used_ip FROM credentials WHERE last_used_at IS NOT NULL`), [{ last_used_ip: '192.0.2.7' }]);
});

test('whoever the credential does not make a caller gets one answer, and nothing is written', async () => {
  const far = new Date(Date.UTC(2027, 0, 1));
  const linked = identity(ada, { revokedAt: new Date(0), revokedBy: cy });
  await write(
    vault,
    ...rows('principals', principal(user('eve'), { status: 'removed', generation: 1 }), principal(user('fay'), { generation: 1 })),
    ...rows('identities', linked),
    ...rows(
      'credentials',
      credential('expired', ada, { expiresAt: new Date(vault.now()) }),
      credential('revoked', ada, { revokedAt: new Date(0), revokedBy: cy }),
      credential('frozen', ada, { frozenAt: new Date(0) }),
      credential('removed', user('eve'), { generation: 1 }),
      credential('readmitted', user('fay')),
      credential('unlinked', ada, { identityId: linked.id }),
      credential('workload', ci, { kind: 'workload', jkt: 'thumb', notAfter: far }),
      credential('no-account', ada, { kind: 'browser' }),
      credential('exchanged', ci, { createdBy: 'binding:7' }),
    ),
  );
  // Rows written around the vault: one with no MAC, and a real one whose expiry was moved.
  await vault.owner.execute(sql`INSERT INTO credentials (id, kind, token_hash, generation, principal, created_at, created_by, expires_at) SELECT gen_random_uuid(), 'cli', sha256('forged'), 0, ${cy}, now(), ${cy}, now() + interval '1 day'`);
  await write(vault, ...rows('credentials', credential('edited', ada, { expiresAt: new Date(0) })));
  await vault.owner.execute(sql`UPDATE credentials SET expires_at = now() + interval '1 year' WHERE label = 'edited'`);
  await vault.owner.execute(sql`DELETE FROM log_pending`);
  vault.woken.length = 0;

  for (const label of ['nobody', 'expired', 'revoked', 'frozen', 'removed', 'readmitted', 'unlinked', 'workload', 'no-account', 'exchanged', 'forged', 'edited']) {
    assert.equal(await got(ask(label, 'market/prod', ['DATABASE_URL'])), 'unauthenticated', label);
  }
  await untouched();
});

test('a place that is not there, and one the caller holds nothing in, are told apart by nobody', async () => {
  const lapsed = environment(w.market, 'lapsed');
  await write(vault, ...rows('environments', lapsed, environment(w.market, 'archived', { archivedAt: new Date(0) }), environment(w.market, 'old~deleted-2026-10-05')), ...rows('grants', grant(dee, 'viewer', { environment: lapsed }, { expiresAt: new Date(vault.now()) })));
  await vault.owner.execute(sql`DELETE FROM log_pending`);
  vault.woken.length = 0;
  for (const [who, place] of [['dee', 'market/prod'], ['dee', 'market/lapsed'], ['ada', 'market/nowhere'], ['ada', 'nowhere/prod'], ['cy', 'market/archived'], ['cy', 'market/old~deleted-2026-10-05'], ['bo', 'market/prod'], ['ada', 'billing/prod']] as const) {
    assert.equal(await got(ask(who, place, ['DATABASE_URL'])), 'no_access', `${who} at ${place}`);
  }
  await untouched();
});

test('each key is its own answer: unknown, archived, empty, sensitive, a reference', async () => {
  assert.deepEqual(await got(ask('ada', 'market/prod', ['DATABASE_URL', 'NOPE', 'OLD', 'HOLLOW', 'STRIPE_KEY', 'FLAG'])), {
    DATABASE_URL: 'postgres://prod', NOPE: 'refused: unknown_key', OLD: 'refused: unknown_key', HOLLOW: 'refused: no_value', STRIPE_KEY: 'refused: sensitive', FLAG: 'on',
  });
  // Only what was handed over is logged and counted, in the order asked.
  assert.deepEqual((await logged())[0]!.detail.keys, [w.database, w.flag].map((row) => ({ key: row.key, secret: row.id, version: row.currentVersion })));
  assert.deepEqual((await exposed()).map((row) => row.secret_id).sort(), [w.database.id, w.flag.id].sort());
});

test('a sensitive value is used for a person and never handed to them, and handed to a service only on a credential an Owner issued', async () => {
  assert.deepEqual(await got(ask('ada', 'market/prod', ['STRIPE_KEY'], { purpose: 'use' })), { STRIPE_KEY: 'sk_live' });
  assert.deepEqual(await got(ask('cy', 'market/prod', ['STRIPE_KEY'])), { STRIPE_KEY: 'refused: sensitive' });
  assert.deepEqual(await got(ask('ci', 'market/prod', ['STRIPE_KEY'])), { STRIPE_KEY: 'refused: not_owner_issued' });
  assert.deepEqual(await got(ask('ci-sensitive', 'market/prod', ['STRIPE_KEY'])), { STRIPE_KEY: 'sk_live' });
});

test('a token reaches no further than its scope, and a person in a protected environment holds their role\'s other column', async () => {
  // ci holds billing by a grant, and its tokens were issued for market alone.
  assert.equal(await got(ask('ci', 'billing/prod', ['API_TOKEN'])), 'no_access');
  // A Viewer uses a protected environment's values, and reads none; a service account's grant is not narrowed.
  assert.equal(await got(ask('ada', 'market/vault', ['ROOT'])), 'no_access');
  assert.deepEqual(await got(ask('ada', 'market/vault', ['ROOT'], { purpose: 'use' })), { ROOT: 'root-key' });
  assert.deepEqual(await got(ask('ci', 'market/vault', ['ROOT'])), { ROOT: 'root-key' });
  // A role with no row is no role.
  await vault.owner.execute(sql`DELETE FROM roles WHERE id = 'viewer'`);
  vault.tick(2000);
  assert.equal(await got(ask('ada', 'market/prod', ['DATABASE_URL'])), 'no_access');
});

test('a fork has its own keys, then its parent\'s, but for those it dismissed; its reader reads the parent too, or is not given them', async () => {
  assert.deepEqual(await got(ask('ada', 'market/staging', null)), { DATABASE_URL: 'postgres://staging', HOLLOW: 'refused: no_value', LINK: 'billing-token', STRIPE_KEY: 'refused: sensitive' });
  assert.deepEqual(await got(ask('ada', 'market/staging', ['FLAG', 'DATABASE_URL'])), { FLAG: 'refused: unknown_key', DATABASE_URL: 'postgres://staging' });
  assert.deepEqual(await got(ask('bo', 'market/staging', ['DATABASE_URL', 'LINK'])), { DATABASE_URL: 'postgres://staging', LINK: 'refused: parent_unreadable' });
  // A dismissal written around the vault hides nothing, and one deleted around it is caught by the signer, not here.
  await vault.owner.execute(sql`INSERT INTO dismissed_keys (environment_id, key, dismissed_at, dismissed_by) VALUES (${w.staging.id}, 'LINK', now(), ${ada})`);
  vault.tick(2000);
  assert.deepEqual(await got(ask('ada', 'market/staging', ['LINK', 'FLAG'])), { LINK: 'billing-token', FLAG: 'refused: unknown_key' });
  // Three parents at most.
  const chain = [environment(w.market, 'fork-1', { parentId: w.staging.id })];
  for (const n of [2, 3]) chain.push(environment(w.market, `fork-${n}`, { parentId: chain.at(-1)!.id }));
  await write(vault, ...rows('environments', ...chain));
  assert.deepEqual(await got(ask('ada', 'market/fork-2', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://staging' });
  assert.equal(await got(ask('ada', 'market/fork-3', ['DATABASE_URL'])), 'broken_chain');
  // A parent that is gone stops the whole read: the fork's keys are not all there.
  await vault.owner.execute(sql`UPDATE environments SET archived_at = now() WHERE slug = 'prod' AND project_id = ${w.market.id}`);
  vault.tick(2000);
  // The edit was made around the vault, so the row is none: the same answer.
  assert.equal(await got(ask('ada', 'market/staging', ['DATABASE_URL'])), 'broken_chain');
});

test('a personal config is its owner\'s alone, over the environment it is a config of', async () => {
  assert.deepEqual(await got(ask('ada', 'market/staging', ['DATABASE_URL', 'LINK'], { mine: true })), { DATABASE_URL: 'postgres://ada', LINK: 'billing-token' });
  // Someone with none of their own reads the environment itself; and nobody else's, an Owner included.
  assert.deepEqual(await got(ask('cy', 'market/staging', ['DATABASE_URL'], { mine: true })), { DATABASE_URL: 'postgres://staging' });
  assert.equal(await got(ask('cy', 'market/staging-ada', ['DATABASE_URL'])), 'no_access');
  assert.deepEqual(await got(ask('ada', 'market/staging-ada', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://ada' });
});

test('a reference is read where it lives and counted where its value is held; one whose source is gone is not read', async () => {
  assert.deepEqual(await got(ask('ada', 'market/prod', ['LINK'])), { LINK: 'billing-token' });
  assert.deepEqual(await exposed(), [{ principal: ada, secret_id: w.token.id }]);
  const [entry] = await logged();
  assert.deepEqual(entry!.detail.keys, [{ key: 'LINK', secret: w.token.id, version: 1, through: w.link.id }]);
  assert.ok(entry!.objects.includes(`secret:${w.link.id}`) && entry!.objects.includes(`secret:${w.token.id}`));

  const archived = await value(vault, secret(w.billed, 'RETIRED', { archivedAt: new Date(0) }), 'x');
  const chained = secret(w.billed, 'CHAINED', { sourceId: w.token.id });
  await write(vault, ...rows('secrets', archived, chained, secret(w.prod, 'TO_ARCHIVED', { sourceId: archived.id }), secret(w.prod, 'TO_REFERENCE', { sourceId: chained.id }), secret(w.prod, 'INTO_PERSONAL', { sourceId: w.own.id })));
  assert.deepEqual(await got(ask('ada', 'market/prod', ['TO_ARCHIVED', 'TO_REFERENCE', 'INTO_PERSONAL'])), { TO_ARCHIVED: 'refused: unreadable', TO_REFERENCE: 'refused: unreadable', INTO_PERSONAL: 'refused: unreadable' });
});

test('what a database writer does to a value or a place is not honoured', async () => {
  // An old version's row copied over the current one's.
  const columns = sql.raw(['ciphertext', 'iv', 'auth_tag', 'wrapped_dek'].map((column) => `${column} = old.${column}`).join(', '));
  await vault.owner.execute(sql`UPDATE secret_versions v SET ${columns} FROM secret_versions old WHERE v.secret_id = ${w.database.id} AND v.version = 2 AND old.secret_id = v.secret_id AND old.version = 1`);
  // A sensitive value relabelled a secret, and a secret's version relabelled as 0.14's format.
  await vault.owner.execute(sql`UPDATE secret_versions SET sensitive = false WHERE secret_id = ${w.stripe.id}`);
  await vault.owner.execute(sql`UPDATE secret_versions SET envelope_version = 1 WHERE secret_id = ${w.flag.id}`);
  // A secret marked plain, with a copy of the writer's own choosing, for whoever is handed plain values.
  await vault.owner.execute(sql`UPDATE secret_versions SET plaintext = 'x' WHERE secret_id = ${w.root.id}`);
  assert.deepEqual(await got(ask('ada', 'market/prod', ['DATABASE_URL', 'STRIPE_KEY', 'FLAG'])), { DATABASE_URL: 'refused: unreadable', STRIPE_KEY: 'refused: unreadable', FLAG: 'refused: unreadable' });
  assert.deepEqual(await got(ask('ci', 'market/vault', ['ROOT'])), { ROOT: 'refused: unreadable' });
  await untouched();

  // Two projects' slugs swapped: market's values would be handed over as billing's.
  const rename = (from: string, to: string) => vault.owner.execute(sql`UPDATE projects SET slug = ${to} WHERE slug = ${from}`);
  await rename('market', 'swap');
  await rename('billing', 'market');
  await rename('swap', 'billing');
  vault.tick(2000);
  assert.equal(await got(ask('ci', 'market/prod', ['API_TOKEN'])), 'no_access');
  assert.equal(await got(ask('ada', 'billing/prod', ['FLAG'])), 'no_access');
  // A grant written around the vault gives nothing.
  await rename('market', 'swap');
  await rename('billing', 'market');
  await rename('swap', 'billing');
  await vault.owner.execute(sql`INSERT INTO grants (id, principal, project_id, role, granted_at, granted_by) VALUES (gen_random_uuid(), ${dee}, ${w.market.id}, 'viewer', now(), ${dee})`);
  assert.equal(await got(ask('dee', 'market/prod', ['FLAG'])), 'no_access');
});

test('within its memory a use reads nothing again, counted from the read; within a minute it logs nothing again, but for another purpose', async () => {
  const asked = ask('ada', 'market/prod', ['FLAG']);
  assert.deepEqual(await got(asked), { FLAG: 'on' });
  // The credential's row deleted behind the vault: what was read still answers, for two seconds from the read.
  await vault.owner.execute(sql`DELETE FROM credentials WHERE label = 'ada'`);
  vault.tick(1999);
  assert.deepEqual(await got(asked), { FLAG: 'on' });
  assert.equal((await logged()).length, 1);
  vault.tick(1);
  assert.equal(await got(asked), 'unauthenticated');

  // A read that takes its time is no fresher for it: its memory is dated when it read.
  const slow = ask('cy', 'market/prod', ['FLAG']);
  const found = await read(vault, slow);
  vault.tick(1500);
  assert.ok('values' in (await answer(vault, slow, found)));
  vault.tick(499);
  assert.ok(recall(vault, slow) !== undefined);
  vault.tick(1);
  assert.equal(recall(vault, slow), undefined);

  // A minute on, the same read is logged again; another purpose is another entry at once.
  assert.deepEqual(await got(slow), { FLAG: 'on' });
  assert.equal((await logged()).length, 2);
  vault.tick(60_000 - 500 - 1);
  assert.deepEqual(await got(slow), { FLAG: 'on' });
  assert.equal((await logged()).length, 2);
  vault.tick(1);
  assert.deepEqual(await got(slow), { FLAG: 'on' });
  assert.equal((await logged()).length, 3);
  assert.deepEqual(await got({ ...slow, purpose: 'run' }), { FLAG: 'on' });
  assert.equal((await logged()).length, 4);

  // With no memory, every use reads.
  Object.assign(vault, { memory: memoryOf(0) });
  assert.deepEqual(await got(slow), { FLAG: 'on' });
  await vault.owner.execute(sql`DELETE FROM credentials WHERE label = 'cy'`);
  assert.equal(await got(slow), 'unauthenticated');
});

test('a memory decides again as of now: a credential that expires within it stops at once', async () => {
  await write(vault, ...rows('credentials', credential('brief', ada, { expiresAt: new Date(vault.now() + 1000) })));
  assert.deepEqual(await got(ask('brief', 'market/prod', ['FLAG'])), { FLAG: 'on' });
  vault.tick(1000);
  assert.equal(await got(ask('brief', 'market/prod', ['FLAG'])), 'unauthenticated');
});

test('the bulk cap refuses the read that would pass it, writes nothing for it, and lets the window slide', async () => {
  Object.assign(vault, { cap: { count: 3, windowMs: 60_000 } });
  assert.deepEqual(Object.keys(await got(ask('ci', 'market/prod', ['DATABASE_URL', 'FLAG'])) as object), ['DATABASE_URL', 'FLAG']);
  vault.tick(30_000);
  // A key given before counts once, here asked for another purpose so that it is written again, with a third.
  assert.deepEqual(await got(ask('ci', 'market/prod', ['FLAG', 'LINK'], { purpose: 'run' })), { FLAG: 'on', LINK: 'billing-token' });
  const before = [await logged(), await exposed()];
  assert.equal(await got(ask('ci', 'market/vault', ['ROOT'])), 'bulk_limit');
  assert.deepEqual([await logged(), await exposed()], before);
  // Another principal has its own count; and once the first two have left the window, there is room.
  assert.deepEqual(await got(ask('ada', 'market/prod', ['FLAG'])), { FLAG: 'on' });
  vault.tick(30_001);
  assert.deepEqual(await got(ask('ci', 'market/vault', ['ROOT'])), { ROOT: 'root-key' });
});

test('a credential\'s last use moves on every five minutes, under no MAC, and takes none off its row', async () => {
  const used = () => rowsOf<{ at: number | null }>(vault.owner, sql`SELECT (extract(epoch FROM last_used_at) * 1000)::float8 AS at FROM credentials WHERE label = 'ada'`);
  const first = vault.now();
  await got(ask('ada', 'market/prod', ['FLAG']));
  assert.deepEqual(await used(), [{ at: first }]);
  vault.tick(5 * 60_000 - 1);
  await got(ask('ada', 'market/prod', ['FLAG']));
  assert.deepEqual(await used(), [{ at: first }]);
  vault.tick(1);
  assert.deepEqual(await got(ask('ada', 'market/prod', ['FLAG'])), { FLAG: 'on' });
  assert.deepEqual(await used(), [{ at: first + 5 * 60_000 }]);
});

/** Whatever was remembered is forgotten, and nothing the setup wrote is counted. */
async function settled(): Promise<void> {
  vault.memory = memoryOf(2);
  await vault.owner.execute(sql`DELETE FROM log_pending`);
  vault.woken.length = 0;
}
const scopeOf = (...grants: object[]) => JSON.stringify(grants);

test('what a trust binding issued reaches what its binding does, while the binding stands', async () => {
  const viewer = scopeOf({ projectId: w.market.id, environmentId: null, role: 'viewer' });
  const [github, moved, others, sessions] = [binding(ci, { scope: viewer }), binding(ci, { scope: viewer, generation: 1 }), binding('token:other', { scope: viewer }), binding(ci, { scope: viewer, policy: '{}' })];
  const run = (label: string, by: { id: string }) => credential(label, ci, { createdBy: `binding:${by.id}` });
  await write(vault, ...rows('principals', principal('token:other')), ...rows('bindings', github, moved, others, sessions), ...rows('credentials', run('run', github), run('moved', moved), run('others', others), run('sessions', sessions)));
  await settled();

  // Its binding's scope, not its own row's, which holds none: market, and nothing of billing, which ci holds too.
  assert.deepEqual(await got(ask('run', 'market/prod', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://prod' });
  assert.equal(await got(ask('run', 'billing/prod', ['API_TOKEN'])), 'no_access');
  // A binding of another generation, of another service, and one that makes sessions, issue no token.
  for (const label of ['moved', 'others', 'sessions']) assert.equal(await got(ask(label, 'market/prod', ['DATABASE_URL'])), 'unauthenticated', label);
  // Unbound: what it issued goes with it, once the vault reads again.
  await amend(vault, 'bindings', sql`id = ${github.id}`, { revokedAt: new Date(vault.now()), revokedBy: cy });
  assert.deepEqual(await got(ask('run', 'market/prod', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://prod' });
  vault.tick(2000);
  assert.equal(await got(ask('run', 'market/prod', ['DATABASE_URL'])), 'unauthenticated');
  // An instance whose services are key-bound sessions or nothing takes no service token at all.
  vault.workloads = { noReads: false, useOnly: true };
  assert.equal(await got(ask('ci', 'market/prod', ['DATABASE_URL'])), 'unauthenticated');
  vault.workloads = null;
  assert.deepEqual(await got(ask('ci', 'market/prod', ['DATABASE_URL'])), { DATABASE_URL: 'postgres://prod' });
});

/** api, a workload bound with a policy: it uses market, and is handed prod's DATABASE_URL alone. `pod` is a session of it. */
async function workload(policy: object = {}, more: Parameters<typeof session>[2] = {}) {
  const api = 'token:api';
  const bound = binding(api, { profile: 'kubernetes', scope: scopeOf({ projectId: w.market.id, environmentId: null, role: 'viewer' }, { projectId: w.market.id, environmentId: w.prod.id, role: 'viewer' }), policy: JSON.stringify({ reads: { [w.prod.id]: { keys: [w.database.id] } }, ...policy }) });
  const pod = session('pod', bound, more);
  await write(vault, ...rows('principals', principal(api)), ...rows('grants', grant(api, 'viewer', { project: w.market })), ...rows('policy', instance()), ...rows('bindings', bound), ...rows('credentials', pod));
  await settled();
  return { api, bound, pod };
}
const keyed = { proof: 'pod' };

test('a workload\'s session is its key\'s: it uses what its service does, and is handed what its binding lists', async () => {
  const { api, bound, pod } = await workload();
  // The token alone, or with another key, is nobody's.
  for (const proof of [null, 'another']) assert.equal(await got(ask('pod', 'market/prod', ['DATABASE_URL'], { proof })), 'unauthenticated');
  await untouched();
  const result = await use(vault, ask('pod', 'market/prod', ['DATABASE_URL', 'STRIPE_KEY', 'FLAG'], keyed));
  assert.ok('values' in result);
  // Listed, handed; not listed, used only; plain, no secret.
  assert.deepEqual(given(result.values), { DATABASE_URL: 'postgres://prod', STRIPE_KEY: 'refused: use_only', FLAG: 'on' });
  // What only the app can hold the request to comes back with it.
  assert.deepEqual([result.principal, result.credential, result.workload], [api, pod.id, { binding: bound.id, profile: 'kubernetes', policy: JSON.parse(bound.policy!), constraints: null }]);
  assert.deepEqual(await got(ask('pod', 'market/prod', ['STRIPE_KEY'], { ...keyed, purpose: 'use', credential: 'stripe' })), { STRIPE_KEY: 'sk_live' });
  assert.equal((await logged()).at(-1)!.detail.credential, 'stripe');
  // Listed where the value is held, never where a request names it: staging inherits prod's, and its own is not listed.
  assert.deepEqual(await got(ask('pod', 'market/staging', ['DATABASE_URL', 'STRIPE_KEY'], keyed)), { DATABASE_URL: 'refused: use_only', STRIPE_KEY: 'refused: use_only' });
  // A deployment that takes no workloads takes none; and a session's hard end is its own, whatever its expiry says.
  vault.workloads = null;
  assert.equal(await got(ask('pod', 'market/prod', ['FLAG'], keyed)), 'unauthenticated');
  vault.workloads = { noReads: false, useOnly: false };
  assert.deepEqual(await got(ask('pod', 'market/prod', ['FLAG'], keyed)), { FLAG: 'on' });
  await amend(vault, 'credentials', sql`id = ${pod.id}`, { notAfter: new Date(vault.now() + 2000) });
  vault.tick(2000);
  assert.equal(await got(ask('pod', 'market/prod', ['FLAG'], keyed)), 'unauthenticated');
});

test('a session that stands and is stopped is told why, writes nothing, and serves again once that is lifted', async () => {
  const { api, bound, pod } = await workload({ approve: true, sources: ['10.0.0.0/8'] });
  const inside = { ...keyed, ip: '10.1.2.3' };
  const asks = (more: Partial<Ask> = inside) => got(ask('pod', 'market/prod', ['FLAG'], more));
  /** Each freeze is a field of the row it stops: set, the session is frozen; lifted, it serves. */
  const frozen = async (table: 'policy' | 'principals' | 'bindings' | 'credentials', where: ReturnType<typeof sql>, field: 'frozenAt' | 'workloadsFrozenAt') => {
    await amend(vault, table, where, { [field]: new Date(vault.now()) } as never);
    vault.tick(2000);
    assert.equal(await asks(), 'frozen', table);
    await amend(vault, table, where, { [field]: null } as never);
    vault.tick(2000);
    assert.deepEqual(await asks(), { FLAG: 'on' }, table);
  };

  assert.equal(await asks(), 'pending');
  await amend(vault, 'credentials', sql`id = ${pod.id}`, { approvedAt: new Date(vault.now()), approvedBy: cy });
  vault.tick(2000);
  // Outside the binding's sources, or from nowhere the app can tell.
  for (const ip of ['192.0.2.7', null]) assert.equal(await asks({ ...keyed, ip }), 'source');
  vault.workloads = { noReads: true, useOnly: false };
  assert.equal(await asks(), 'no_reads');
  vault.workloads = { noReads: false, useOnly: false };
  await settled();
  await untouched();
  assert.deepEqual(await asks(), { FLAG: 'on' });

  await frozen('policy', sql`true`, 'workloadsFrozenAt');
  await frozen('principals', sql`id = ${api}`, 'frozenAt');
  await frozen('bindings', sql`id = ${bound.id}`, 'frozenAt');
  await frozen('credentials', sql`id = ${pod.id}`, 'frozenAt');
  // An instance whose policy row is gone cannot say it is not frozen.
  await vault.owner.execute(sql`DELETE FROM policy`);
  vault.tick(2000);
  assert.equal(await asks(), 'frozen');
});

test('a narrowed session uses values within its limits, is handed none, and stands while every session above it does', async () => {
  const { bound, pod } = await workload();
  const narrowed = (label: string, above: string[], constraints: object | null = null) => session(label, bound, { ancestors: JSON.stringify(above), constraints: constraints && JSON.stringify(constraints) });
  // `narrow` stores a child's limits within its parent's: `tool`, made from `agent`, holds the same.
  const limits = { places: ['market/prod'], credentials: ['stripe'] };
  const agent = narrowed('agent', [pod.id], limits);
  const stray = credential('stray', ci, { kind: 'workload', jkt: 'stray', notAfter: new Date(Date.UTC(2027, 0, 1)) });
  await write(vault, ...rows('credentials', agent, narrowed('tool', [pod.id, agent.id], limits), narrowed('free', [pod.id]), session('limited', bound, { constraints: JSON.stringify(limits) }), stray, narrowed('adopted', [stray.id]), narrowed('deep', [pod.id, pod.id, pod.id, pod.id, pod.id])));
  await settled();
  const uses = (label: string, place: string, credential: string | null, purpose = 'use') => got(ask(label, place, ['STRIPE_KEY'], { proof: label, purpose, credential }));

  assert.deepEqual(await uses('agent', 'market/prod', 'stripe'), { STRIPE_KEY: 'sk_live' });
  // Handed nothing, a plain value included; and nothing past the places and credentials it was narrowed to.
  assert.equal(await got(ask('agent', 'market/prod', ['FLAG'], { proof: 'agent', credential: 'stripe' })), 'narrowed');
  for (const [place, credential] of [['market/staging', 'stripe'], ['market/prod', 'openai'], ['market/prod', null]] as const) assert.equal(await uses('agent', place, credential), 'narrowed', `${place} ${credential}`);
  // One narrowed with no limit uses what its service does; and limits bind whatever the row says of sessions above it.
  assert.deepEqual(await uses('free', 'market/staging', null), { STRIPE_KEY: 'sk_live' });
  assert.equal(await uses('limited', 'market/prod', 'openai'), 'narrowed');
  // Above it, only its own service's sessions, four at most.
  for (const label of ['adopted', 'deep']) assert.equal(await uses(label, 'market/prod', null), 'unauthenticated', label);
  // A session above it frozen stops it; one ended ends it.
  await amend(vault, 'credentials', sql`id = ${agent.id}`, { frozenAt: new Date(vault.now()) });
  vault.tick(2000);
  assert.equal(await uses('tool', 'market/prod', 'stripe'), 'frozen');
  await amend(vault, 'credentials', sql`id = ${pod.id}`, { revokedAt: new Date(vault.now()), revokedBy: cy });
  vault.tick(2000);
  for (const label of ['agent', 'tool']) assert.equal(await uses(label, 'market/prod', 'stripe'), 'unauthenticated', label);
  // Sessions above it written around the vault are no row's: nobody, and no error.
  for (const junk of ['not json', '{}', '["not-an-id"]']) {
    await vault.owner.execute(sql`UPDATE credentials SET ancestors = ${junk} WHERE label = 'free'`);
    vault.tick(2000);
    assert.equal(await uses('free', 'market/prod', null), 'unauthenticated', junk);
  }
});

test('a handle reaches what its scope does; an upstream credential frozen in an environment is used by nobody there', async () => {
  await write(vault, ...rows('credentials', credential('handle', ada, { kind: 'handle', scope: scopeOf({ projectId: w.market.id, environmentId: w.prod.id, role: 'viewer' }) })));
  await settled();
  // `coffre run` reads its plan through the handle: what its person reads where it was made, and nothing elsewhere.
  assert.deepEqual(await got(ask('handle', 'market/prod', ['DATABASE_URL'], { purpose: 'expose' })), { DATABASE_URL: 'postgres://prod' });
  assert.equal(await got(ask('handle', 'market/staging', ['DATABASE_URL'], { purpose: 'expose' })), 'no_access');
  assert.deepEqual(await got(ask('handle', 'market/prod', ['DATABASE_URL'], { purpose: 'use', credential: 'stripe' })), { DATABASE_URL: 'postgres://prod' });

  await amend(vault, 'environments', sql`id = ${w.prod.id}`, { frozenCredentials: ['stripe'] });
  await settled();
  for (const label of ['handle', 'ada', 'cy']) assert.equal(await got(ask(label, 'market/prod', ['DATABASE_URL'], { purpose: 'use', credential: 'stripe' })), 'frozen', label);
  // Another credential there, and the same one elsewhere, are not.
  assert.deepEqual(await got(ask('ada', 'market/prod', ['DATABASE_URL'], { purpose: 'use', credential: 'openai' })), { DATABASE_URL: 'postgres://prod' });
  assert.deepEqual(await got(ask('ada', 'market/staging', ['DATABASE_URL'], { purpose: 'use', credential: 'stripe' })), { DATABASE_URL: 'postgres://staging' });
  // Nobody is told a credential is frozen in a place they hold nothing in.
  assert.equal(await got(ask('dee', 'market/prod', ['DATABASE_URL'], { purpose: 'use', credential: 'stripe' })), 'no_access');
});
