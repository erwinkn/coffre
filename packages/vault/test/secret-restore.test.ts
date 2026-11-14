// A version restored (src/ops/secrets.ts, `restore`): the key's next
// version is an older one's value, which the engine opens and seals again
// (change.ts, `Value`'s `copy`), as it was kept, sensitive while the key is,
// with its first date; who may; and a version row that is not what it says.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import { KekUnavailableError } from '@coffre/core/kek';
import type { Presented, SecretWrite, UseInput } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { secrets } from '@coffre/db/schema';
import { eq, sql } from 'drizzle-orm';

import { commit, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { emptyDatabase, openTestVault } from './database.ts';
import { amend, credential, environment, grant, instance, principal, project, role, rows, secret, tokenOf, user, value, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const day = 86_400_000;
const [ada, bo, cy] = [user('ada'), user('bo'), user('cy')];
let market: ReturnType<typeof project>;
let prod: ReturnType<typeof environment>;
let ids: Record<string, string>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  world.memory.reads.clear();
  world.memory.logged.clear();
  world.refused.clear();
  market = project('market');
  prod = environment(market, 'prod');
  const billing = project('billing');
  const there = environment(billing, 'prod');
  // Each key's version 1, written by the world on its day 0; the tests write the rest.
  const keys = [
    value(world, secret(prod, 'DATABASE_URL'), 'postgres://one'),
    value(world, secret(prod, 'STRIPE_KEY'), 'sk_one', { sensitive: true }),
    value(world, secret(prod, 'ACCOUNT'), 'acct_1', { plain: true }),
    value(world, secret(there, 'SOURCE'), 'from billing'),
  ];
  ids = Object.fromEntries(keys.map((row) => [row.key, row.id]));
  await write(world, ...rows('projects', market, billing), ...rows('environments', prod, there), ...rows('secrets', ...keys),
    // A developer reads and writes; a deployer writes and uses, and reads nothing back; a viewer reads; a maintainer archives too.
    ...rows('roles', role(false, 'developer', ['secret.read', 'secret.use', 'secret.write']), role(false, 'deployer', ['secret.use', 'secret.write']), role(false, 'viewer', ['secret.read', 'secret.use']),
      role(false, 'maintainer', ['secret.read', 'secret.use', 'secret.write', 'secret.archive']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy)), ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'maintainer', { project: market }), grant(ada, 'developer', { project: billing }), grant(bo, 'deployer', { project: market }), grant(cy, 'viewer', { project: market })),
    ...rows('credentials', credential('ada-cli', ada), credential('bo-cli', bo), credential('cy-cli', cy)));
  world.woken.length = 0;
});

const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const writing = (label: string, keys: SecretWrite['keys']): Presented & SecretWrite => ({ ...shown(label), op: 'secret.write', project: 'market', environment: 'prod', keys });
const restoring = (label: string, key: string, version: number) => writing(label, [{ key, restore: version }]);
const reveal = (keys: string[]): UseInput => ({ ...shown('ada-cli'), project: 'market', environment: 'prod', mine: false, keys, purpose: 'reveal', upstream: null });
const given = async (keys: string[]) => {
  const answer = await vault.use(reveal(keys));
  assert.ok(!('refused' in answer), JSON.stringify(answer));
  return answer.values.map((item) => ('refused' in item ? item.refused : [item.version, item.value.toString()]));
};
/** A day later, a value written over the key, as typed. */
const typed = async (key: string, text: string, nature: 'secret' | 'sensitive' | 'plain' = 'secret') => {
  world.tick(day);
  assert.ok(!('refused' in (await vault.change(writing('ada-cli', [{ key, value: text, nature }])))));
};
type Version = { version: number; sensitive: boolean; plaintext: string | null; first: number; created: number; iv: Buffer };
const versionsOf = async (key: string) =>
  (await rowsOf<Version>(world.owner, sql`SELECT v.version, v.sensitive, v.plaintext, v.first_written_at AS first, v.created_at AS created, v.iv FROM secret_versions v WHERE v.secret_id = ${ids[key]!} ORDER BY v.version`))
    .map((row) => ({ ...row, first: new Date(row.first).getTime(), created: new Date(row.created).getTime() }));
const rowOf = async (key: string) => (await rowsOf<{ nature: string | null; versions: number; current: number | null; source: string | null; recipe: string | null; pair: string | null }>(world.owner,
  sql`SELECT nature, versions, current_version AS current, source_id AS source, recipe, pair_id AS pair FROM secrets WHERE id = ${ids[key]!}`))[0]!;
const counts = async () => (await rowsOf<{ log: number; versions: number }>(world.owner, sql`SELECT (SELECT count(*)::int FROM log_pending WHERE kept) AS log, (SELECT count(*)::int FROM secret_versions) AS versions`))[0]!;
const newest = async () => {
  const [row] = await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending WHERE kept ORDER BY id DESC LIMIT 1`);
  return entryOf(world.keys, row!)!;
};

test('a restore makes the old value the key\'s next version, sealed again, first written when its source was', async () => {
  await typed('DATABASE_URL', 'postgres://two');
  world.tick(day);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'DATABASE_URL', 1)), { answer: { keys: { DATABASE_URL: { version: 3, nature: 'secret' } } } });
  assert.deepEqual(await given(['DATABASE_URL']), [[3, 'postgres://one']]);
  const [one, two, three] = await versionsOf('DATABASE_URL');
  // Its own date is today's; its value's, version 1's; and it is encrypted anew, under its own number.
  assert.deepEqual([three!.created, three!.first], [world.now(), one!.first]);
  assert.notDeepEqual(three!.iv, one!.iv);
  assert.equal(two!.first, two!.created, 'a typed value is first written when it is');
  const entry = await newest();
  assert.deepEqual((entry.detail as { keys: object[] }).keys, [{ key: 'DATABASE_URL', secret: ids.DATABASE_URL, version: 3, nature: 'secret', restored: 1 }]);

  // A restore of the restore keeps the first date, and of the version that is current makes another copy of it.
  world.tick(day);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'DATABASE_URL', 3)), { answer: { keys: { DATABASE_URL: { version: 4, nature: 'secret' } } } });
  assert.deepEqual(await given(['DATABASE_URL']), [[4, 'postgres://one']]);
  assert.equal((await versionsOf('DATABASE_URL'))[3]!.first, one!.first);
});

test('a value comes back as it was kept, and sensitive while the key is, or its newest value was', async () => {
  // Plain over a secret: plain, with its copy for the pages.
  await typed('ACCOUNT', 'acct_2');
  assert.deepEqual(await vault.change(restoring('ada-cli', 'ACCOUNT', 1)), { answer: { keys: { ACCOUNT: { version: 3, nature: 'plain' } } } });
  assert.deepEqual([(await versionsOf('ACCOUNT'))[2]!.plaintext, (await rowOf('ACCOUNT')).nature], ['acct_1', 'plain']);
  // A secret over a sensitive value: sensitive. Plain over a sensitive one too.
  await typed('DATABASE_URL', 'postgres://two', 'sensitive');
  assert.deepEqual(await vault.change(restoring('ada-cli', 'DATABASE_URL', 1)), { answer: { keys: { DATABASE_URL: { version: 3, nature: 'sensitive' } } } });
  assert.deepEqual(await given(['DATABASE_URL']), ['sensitive']);
  await typed('ACCOUNT', 'acct_4', 'sensitive');
  assert.deepEqual(await vault.change(restoring('ada-cli', 'ACCOUNT', 1)), { answer: { keys: { ACCOUNT: { version: 5, nature: 'sensitive' } } } });
  assert.deepEqual([(await versionsOf('ACCOUNT'))[4]!.plaintext, (await rowOf('ACCOUNT')).nature], [null, 'sensitive']);
  // A sensitive value over a secret: sensitive still.
  await typed('STRIPE_KEY', 'sk_two');
  assert.deepEqual(await vault.change(restoring('ada-cli', 'STRIPE_KEY', 1)), { answer: { keys: { STRIPE_KEY: { version: 3, nature: 'sensitive' } } } });
  assert.deepEqual(await given(['STRIPE_KEY']), ['sensitive']);
});

test('a key made a reference is restored from its own history: the reference ends, and its newest sensitive value holds', async () => {
  await typed('STRIPE_KEY', 'sk_two');
  // Version 3 sensitive, then the key reads billing's SOURCE, a secret: its row says no nature now.
  await typed('STRIPE_KEY', 'sk_three', 'sensitive');
  assert.ok(!('refused' in (await vault.change(writing('ada-cli', [{ key: 'STRIPE_KEY', ref: { project: 'billing', environment: 'prod', key: 'SOURCE' } }])))));
  assert.deepEqual([(await rowOf('STRIPE_KEY')).nature, (await rowOf('STRIPE_KEY')).source], [null, ids.SOURCE]);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'STRIPE_KEY', 2)), { answer: { keys: { STRIPE_KEY: { version: 4, nature: 'sensitive' } } } });
  assert.deepEqual(await rowOf('STRIPE_KEY'), { nature: 'sensitive', versions: 4, current: 4, source: null, recipe: null, pair: null });
  const entry = await newest();
  assert.deepEqual((entry.detail as { keys: object[] }).keys, [{ key: 'STRIPE_KEY', secret: ids.STRIPE_KEY, version: 4, nature: 'sensitive', restored: 2, source: ids.SOURCE }]);
});

test('a key with no value of its own goes by its newest version\'s label, which its encryption holds: relabelled, the restore is refused', async () => {
  // ACCOUNT: plain at 1, sensitive at 2, then a reference to billing's SOURCE, a secret: its row says no nature now.
  await typed('ACCOUNT', 'acct_2', 'sensitive');
  const source = { project: 'billing', environment: 'prod', key: 'SOURCE' };
  assert.ok(!('refused' in (await vault.change(writing('ada-cli', [{ key: 'ACCOUNT', ref: source }])))));
  // Version 2's row said not sensitive behind the vault, so that version 1 would come back plain. It does not open as that.
  await world.owner.execute(sql`UPDATE secret_versions SET sensitive = false WHERE secret_id = ${ids.ACCOUNT!} AND version = 2`);
  const before = await counts();
  assert.deepEqual(await vault.change(restoring('ada-cli', 'ACCOUNT', 1)), { refused: 'unreadable' });
  assert.deepEqual(await counts(), before);
  // As it was, the restore is sensitive; and so once the reference is broken, when the key's row says no nature either.
  await world.owner.execute(sql`UPDATE secret_versions SET sensitive = true WHERE secret_id = ${ids.ACCOUNT!} AND version = 2`);
  assert.ok(!('refused' in (await vault.change({ ...shown('ada-cli'), op: 'reference.break', project: 'market', environment: 'prod', key: 'ACCOUNT' }))));
  assert.deepEqual([(await rowOf('ACCOUNT')).nature, (await rowOf('ACCOUNT')).current, (await rowOf('ACCOUNT')).source], [null, null, null]);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'ACCOUNT', 1)), { answer: { keys: { ACCOUNT: { version: 3, nature: 'sensitive' } } } });
  // Restoring the newest itself opens it as the copy: no second opening, and the same refusal relabelled.
  assert.ok(!('refused' in (await vault.change(writing('ada-cli', [{ key: 'ACCOUNT', ref: source }])))));
  await world.owner.execute(sql`UPDATE secret_versions SET sensitive = false WHERE secret_id = ${ids.ACCOUNT!} AND version = 3`);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'ACCOUNT', 3)), { refused: 'unreadable' });
});

test('a version restored counts as the most a value weighs against a write\'s 1 MiB, checked before anything is read', async () => {
  // 5 restores fit, 192 KiB each: the keys are not there, which the vault finds only once it reads.
  const keys = (count: number) => Array.from({ length: count }, (_, at) => ({ key: `K${at}`, restore: 1 }));
  assert.deepEqual(await vault.change(writing('ada-cli', keys(5))), { refused: 'unknown_key' });
  await assert.rejects(vault.change(writing('ada-cli', keys(6))), TypeError);
  // One restore and 832 KiB typed is 1 MiB; one byte more is past it.
  const full = Array.from({ length: 13 }, (_, at) => ({ key: `V${at}`, value: 'x'.repeat(65_536) }));
  assert.ok(!('refused' in (await vault.change(writing('ada-cli', [...full, { key: 'DATABASE_URL', restore: 1 }])))));
  await assert.rejects(vault.change(writing('ada-cli', [...full, { key: 'ONE', value: 'x' }, { key: 'DATABASE_URL', restore: 1 }])), TypeError);
});

test('a generated value restored comes back typed: no recipe, in no pair', async () => {
  await amend(world, 'secrets', eq(secrets.id, ids.DATABASE_URL!), { recipe: 'bytes:32:hex', pairId: crypto.randomUUID(), pairHalf: 'private' });
  assert.ok(!('refused' in (await vault.change(restoring('ada-cli', 'DATABASE_URL', 1)))));
  assert.deepEqual(await rowOf('DATABASE_URL'), { nature: 'secret', versions: 2, current: 2, source: null, recipe: null, pair: null });
});

test('whoever restores writes and reads the key there; a version the key never had, a key not there and an archived key are refused', async () => {
  await typed('DATABASE_URL', 'postgres://two');
  const before = await counts();
  // Bo writes and uses, and reads nothing back; Cy reads, and writes nothing.
  assert.deepEqual(await vault.change(restoring('bo-cli', 'DATABASE_URL', 1)), { refused: 'no_access' });
  assert.deepEqual(await vault.change(restoring('bo-cli', 'STRIPE_KEY', 1)), { refused: 'no_access' });
  assert.deepEqual(await vault.change(restoring('cy-cli', 'DATABASE_URL', 1)), { refused: 'no_access' });
  assert.deepEqual(await vault.change(restoring('ada-cli', 'DATABASE_URL', 3)), { refused: 'unknown_version' });
  assert.deepEqual(await vault.change(restoring('ada-cli', 'NOT_THERE', 1)), { refused: 'unknown_key' });
  // One key refused refuses the write: the other is not written either.
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'ACCOUNT', value: 'x', nature: 'plain' }, { key: 'DATABASE_URL', restore: 9 }])), { refused: 'unknown_version' });
  assert.deepEqual(await counts(), before);
  await amend(world, 'secrets', eq(secrets.id, ids.DATABASE_URL!), { archivedAt: new Date(world.now()) });
  const archived = await counts();
  assert.deepEqual(await vault.change(restoring('ada-cli', 'DATABASE_URL', 1)), { refused: 'archived' });
  assert.deepEqual(await counts(), archived);
  // Brought back in the same write, it is restored.
  assert.deepEqual(await vault.change(writing('ada-cli', [{ key: 'DATABASE_URL', restore: 1, archived: false }])), { answer: { keys: { DATABASE_URL: { version: 3, nature: 'secret' } } } });
  assert.deepEqual(await given(['DATABASE_URL']), [[3, 'postgres://one']]);
});

test('a version row that is not what it says refuses the restore, unreadable, and nothing is written', async () => {
  await typed('DATABASE_URL', 'postgres://two');
  await typed('ACCOUNT', 'acct_2', 'plain');
  const before = await counts();
  const edit = (statement: ReturnType<typeof sql>) => world.owner.execute(statement);
  // Relabelled: version 1 of STRIPE_KEY said not sensitive, to come back a secret. It does not open.
  await edit(sql`UPDATE secret_versions SET sensitive = false WHERE secret_id = ${ids.STRIPE_KEY!} AND version = 1`);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'STRIPE_KEY', 1)), { refused: 'unreadable' });
  // A plain value whose copy in its row is not the value.
  await edit(sql`UPDATE secret_versions SET plaintext = 'acct_forged' WHERE secret_id = ${ids.ACCOUNT!} AND version = 1`);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'ACCOUNT', 1)), { refused: 'unreadable' });
  // Erased: nothing to open.
  await edit(sql`UPDATE secret_versions SET ciphertext = ''::bytea, wrapped_dek = ''::bytea WHERE secret_id = ${ids.DATABASE_URL!} AND version = 1`);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'DATABASE_URL', 1)), { refused: 'unreadable' });
  // Gone, though the key's row counts it, and the key's newest gone, whose label a restore reads.
  await edit(sql`DELETE FROM secret_versions WHERE secret_id = ${ids.DATABASE_URL!} AND version = 1`);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'DATABASE_URL', 1)), { refused: 'unreadable' });
  await edit(sql`DELETE FROM secret_versions WHERE secret_id = ${ids.ACCOUNT!} AND version = 2`);
  await edit(sql`UPDATE secret_versions SET plaintext = 'acct_1' WHERE secret_id = ${ids.ACCOUNT!} AND version = 1`);
  assert.deepEqual(await vault.change(restoring('ada-cli', 'ACCOUNT', 1)), { refused: 'unreadable' });
  // The two versions deleted here, and nothing written.
  assert.deepEqual(await counts(), { log: before.log, versions: before.versions - 2 });
});

test('a version row changed after the read makes the write start over; a key service that fails fails the restore', async () => {
  await typed('DATABASE_URL', 'postgres://two');
  const deciding = { workloads: world.workloads, owners: world.owners };
  const prepared = await prepare(world, OPERATIONS['secret.write'](restoring('ada-cli', 'DATABASE_URL', 1), deciding));
  assert.ok(!('refused' in prepared));
  // Its row has no MAC: it is read again whole.
  await world.owner.execute(sql`UPDATE secret_versions SET created_by = 'someone' WHERE secret_id = ${ids.DATABASE_URL!} AND version = 1`);
  const before = await counts();
  assert.equal(await commit(world, prepared), false);
  assert.deepEqual(await counts(), before);

  const down = openLocalVault(world.db, { ...world, keks: { ...world.keks, unwrap: () => Promise.reject(new KekUnavailableError('the key service is down')) } as never }, { wake: world.wake, now: world.now });
  await assert.rejects(down.change(restoring('ada-cli', 'DATABASE_URL', 1)), /key service is down/);
  assert.deepEqual(await counts(), before);
});
