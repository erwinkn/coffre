// A device login (src/ops/signin.ts, docs/design/0.16.md, "Signing in"):
// a CLI starts it, a person approves or denies it in a browser, and the CLI
// collects its session. Two of the three changes nobody asks. Through the
// contract as the app calls it, with the signer reading what it wrote.
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, beforeEach, test } from 'node:test';

import { DEVICE_TTL_SECONDS } from '@coffre/core/access';
import type { Asked, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { commit, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, binding, credential, identity, instance, principal, role, rows, session, tokenOf, user, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [root, ada, bo, cy, dee] = [user('root'), user('ada'), user('bo'), user('cy'), user('dee')];
const ci = 'token:ci';
const TTL_MS = DEVICE_TTL_SECONDS * 1000;
let signer: Signer;

/**
 * Root runs the instance. Ada and Bo are members, Ada on a browser session,
 * a CLI's, a personal token and a handle; Cy was removed; Dee was removed
 * and let back in, and signs in again since. The service
 * account `ci` has a token, and a workload's session through a binding.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: 90 });
  const adas = identity(ada, { provider: 'github', issuerHash: 'issuer-of-github', subject: 'gh-ada' });
  const bos = identity(bo, { provider: 'github', issuerHash: 'issuer-of-github', subject: 'gh-bo' });
  const dees = identity(dee, { provider: 'github', issuerHash: 'issuer-of-github', subject: 'gh-dee', generation: 1 });
  const pod = binding(ci, { policy: '{}' });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', [])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(cy, { status: 'removed', generation: 1 }), principal(dee, { generation: 1 }), principal(ci)),
    ...rows('identities', adas, bos, dees),
    ...rows('bindings', pod),
    ...rows('credentials',
      credential('ada-web', ada, { kind: 'browser', identityId: adas.id }),
      credential('ada-cli', ada),
      credential('ada-pat', ada, { kind: 'personal', scope: '[]' }),
      credential('ada-handle', ada, { kind: 'handle', scope: '[]', places: '[]' }),
      credential('bo-web', bo, { kind: 'browser', identityId: bos.id }),
      credential('dee-web', dee, { kind: 'browser', identityId: dees.id, generation: 1 }),
      credential('ci-token', ci, { scope: '[]' }),
      session('ci-pod', pod),
      // A service's token with no scope, as none is made: it is still no person.
      credential('ci-unscoped', ci, { scope: null }),
    ),
  );
  // The signer has signed the instance as made: what it finds after is a test's own.
  assert.deepEqual(await checked(), []);
});

const from = { request: 'req-1', ip: '192.0.2.7' };
const hex = (label: string) => tokenOf(label).toString('hex');
const shown = (label: string): Presented => ({ token: hex(label), proof: label === 'ci-pod' ? 'ci-pod' : null, ...from });
const start = (code: string, userCode: string, label: string | null = 'coffre on laptop'): Asked<'device.start'> => ({ ...from, ip: '198.51.100.4', op: 'device.start', code: hex(code), userCode, label });
const decide = (label: string, userCode: string, approve = true): Asked<'device.decide'> => ({ ...shown(label), op: 'device.decide', userCode, approve });
const redeem = (code: string, token: string, minutes = 30 * 24 * 60): Asked<'device.redeem'> => ({ ...from, op: 'device.redeem', code: hex(code), session: { token: hex(token), minutes } });
const deciding = { workloads: world.workloads, owners: world.owners };

/** Who a token is, as the vault answers any request that shows it. */
const who = async (label: string) => {
  world.memory.callers.clear();
  const answer = await vault.caller(shown(label));
  return 'refused' in answer ? answer.refused : `${answer.principal} ${answer.credential.kind}`;
};
const entries = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(world.keys, row)! }));
const logins = () => rowsOf<{ user_code: string; decision: string | null; principal: string | null; generation: number; consumed: boolean }>(
  world.owner, sql`SELECT user_code, decision, principal, generation, consumed_at IS NOT NULL AS consumed FROM device_logins ORDER BY user_code`);
/** Everything the vault told the signer of, signed, and the rows held to its mirror: what it found. */
async function checked() {
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  return (await signer.take()).map((finding) => finding.found);
}
/** A change's answer, which the test needs made. */
async function made<O extends 'device.start' | 'device.decide' | 'device.redeem'>(input: Asked<O>) {
  const done = await vault.change(input);
  assert.ok(!('refused' in done), JSON.stringify(done));
  return done.answer;
}

test('a CLI starts a device login, Ada approves it from her browser, and the CLI collects a session of hers: three rows written, three entries that age out', async () => {
  const before = (await entries()).length;
  const started = await made(start('dev-1', 'BCDF-GHJK'));
  assert.equal(started.expiresAt, new Date(world.now() + TTL_MS).toISOString());
  // Nobody has decided yet: the CLI keeps polling.
  assert.deepEqual(await vault.change(redeem('dev-1', 'ada-cli-2')), { refused: 'pending' });
  assert.deepEqual(await made(decide('ada-web', 'BCDF-GHJK')), { deviceLogin: started.deviceLogin });
  world.tick(60_000);
  const collected = await made(redeem('dev-1', 'ada-cli-2', 7 * 24 * 60));
  assert.deepEqual([collected.principal, collected.expiresAt], [ada, new Date(world.now() + 7 * 86_400_000).toISOString()]);
  assert.equal(await who('ada-cli-2'), `${ada} cli`);
  const [cli] = await rowsOf<{ label: string; generation: number; created_by: string; identity_id: string | null; scope: string | null }>(world.owner, sql`SELECT label, generation, created_by, identity_id, scope FROM credentials WHERE id = ${collected.credential}::uuid`);
  assert.deepEqual(cli, { label: 'coffre on laptop', generation: 0, created_by: ada, identity_id: null, scope: null });
  assert.deepEqual(await logins(), [{ user_code: 'BCDF-GHJK', decision: 'approved', principal: ada, generation: 0, consumed: true }]);
  // Once: a second poll, or another CLI that learned the device code, finds it collected.
  assert.deepEqual(await vault.change(redeem('dev-1', 'ada-cli-3')), { refused: 'expired' });
  assert.equal(await who('ada-cli-3'), 'unauthenticated');

  const written = (await entries()).slice(before);
  assert.deepEqual(written.map((entry) => [entry.action, entry.actor, entry.credential, entry.kept]), [
    ['device.start', null, null, false],
    ['device.approve', ada, (await rowsOf<{ id: string }>(world.owner, sql`SELECT id FROM credentials WHERE label = 'ada-web'`))[0]!.id, false],
    ['sign_in', ada, collected.credential, false],
  ]);
  const [begun, approved, signed] = written;
  assert.deepEqual([begun!.ip, begun!.objects, begun!.detail], ['198.51.100.4', [`device_login:${started.deviceLogin}`], { deviceLogin: started.deviceLogin, userCode: 'BCDF-GHJK', label: 'coffre on laptop', expiresAt: started.expiresAt }]);
  assert.deepEqual(approved!.detail, { deviceLogin: started.deviceLogin, label: 'coffre on laptop', clientIp: '198.51.100.4' });
  assert.deepEqual(signed!.objects, [`principal:${ada}`, `credential:${collected.credential}`, `device_login:${started.deviceLogin}`]);
  assert.deepEqual(signed!.detail, { kind: 'cli', deviceLogin: started.deviceLogin, label: 'coffre on laptop', clientIp: '198.51.100.4' });
  assert.deepEqual(await checked(), []);
});

test('a device login denied is never collected; one decided is decided for good; and one past its 10 minutes is good for nothing, approved or not', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  await made(start('dev-2', 'CDFG-HJKL', null));
  await made(start('dev-3', 'DFGH-JKLM'));
  assert.ok(!('refused' in await vault.change(decide('ada-web', 'BCDF-GHJK', false))));
  assert.deepEqual(await vault.change(redeem('dev-1', 'x-cli')), { refused: 'denied' });
  // Denied, and approved after by someone else: the first decision stands, and the second is told the code is not one waiting.
  assert.deepEqual(await vault.change(decide('bo-web', 'BCDF-GHJK')), { refused: 'unknown_code' });
  assert.deepEqual(await vault.change(redeem('dev-1', 'x-cli')), { refused: 'denied' });
  // A code that is not there.
  assert.deepEqual(await vault.change(decide('ada-web', 'ZZZZ-ZZZZ')), { refused: 'unknown_code' });
  // dev-2 approved and never collected, dev-3 never decided: past their 10 minutes neither is anything.
  await made(decide('bo-web', 'CDFG-HJKL'));
  world.tick(TTL_MS);
  assert.deepEqual(await vault.change(redeem('dev-2', 'x-cli')), { refused: 'expired' });
  assert.deepEqual(await vault.change(redeem('dev-3', 'x-cli')), { refused: 'expired' });
  assert.deepEqual(await vault.change(decide('ada-web', 'DFGH-JKLM')), { refused: 'unknown_code' });
  assert.deepEqual(await vault.change(redeem('dev-4', 'x-cli')), { refused: 'expired' }, 'and one never started');
  assert.equal(await who('x-cli'), 'unauthenticated');
  assert.deepEqual((await logins()).map((row) => [row.user_code, row.decision, row.consumed]), [['BCDF-GHJK', 'denied', false], ['CDFG-HJKL', 'approved', false], ['DFGH-JKLM', null, false]]);
  assert.deepEqual(await checked(), []);
});

test('a person decides, on a session of theirs, a CLI\'s too; a token, a person\'s or a service\'s, or a workload\'s session does not, and a refusal to someone who stands is logged', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  for (const label of ['ada-pat', 'ci-token', 'ci-pod', 'ci-unscoped']) assert.deepEqual(await vault.change(decide(label, 'BCDF-GHJK')), { refused: 'no_access' }, label);
  // A handle is the proxy's, and asks nothing of its own; a token the vault does not know, nobody.
  for (const label of ['ada-handle', 'nobody']) assert.deepEqual(await vault.change(decide(label, 'BCDF-GHJK')), { refused: 'unauthenticated' }, label);
  // Still waiting: what was refused wrote nothing.
  assert.deepEqual((await logins()).map((row) => row.decision), [null]);
  const refusals = (await entries()).filter((entry) => entry.detail.refused !== undefined);
  assert.deepEqual(refusals.map((entry) => [entry.action, entry.actor, entry.detail.refused]), [['device.approve', ada, 'no_access'], ['device.approve', ci, 'no_access']], 'once a minute per caller and action, and nothing for a caller who does not stand');
  // Ada's CLI session approves it, as 0.14.7's did.
  await made(decide('ada-cli', 'BCDF-GHJK'));
  assert.ok(!('refused' in await vault.change(redeem('dev-1', 'ada-cli-2'))));
  assert.equal(await who('ada-cli-2'), `${ada} cli`);
});

test('an approval given before its approver was removed, or let back in, collects nothing: the session would be of a generation that is gone', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  await made(start('dev-2', 'CDFG-HJKL'));
  await made(decide('bo-web', 'BCDF-GHJK'));
  await made(decide('bo-web', 'CDFG-HJKL'));
  // His row says removed, and then of a generation after the one he approved in, let back in.
  await amend(world, 'principals', sql`${principals.id} = ${bo}`, { status: 'removed' });
  assert.deepEqual(await vault.change(redeem('dev-1', 'bo-cli')), { refused: 'denied' });
  await amend(world, 'principals', sql`${principals.id} = ${bo}`, { status: 'active', generation: 1 });
  assert.deepEqual(await vault.change(redeem('dev-2', 'bo-cli')), { refused: 'denied' });
  assert.equal(await who('bo-cli'), 'unauthenticated');
  // Nothing is consumed by a refusal: neither is anything, and stays so until it expires.
  assert.deepEqual((await logins()).map((row) => row.consumed), [false, false]);
  // Dee, let back in before she approves, collects a session of the generation she is now.
  await made(start('dev-3', 'DFGH-JKLM'));
  await made(decide('dee-web', 'DFGH-JKLM'));
  const collected = await made(redeem('dev-3', 'dee-cli'));
  assert.equal(await who('dee-cli'), `${dee} cli`);
  assert.deepEqual((await rowsOf<{ generation: number }>(world.owner, sql`SELECT generation FROM credentials WHERE id = ${collected.credential}::uuid`))[0], { generation: 1 });
});

test('nobody starts or collects a device login on a database the vault has not adopted', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  await made(decide('ada-web', 'BCDF-GHJK'));
  const before = (await entries()).length;
  await world.owner.execute(sql`UPDATE policy SET mac = decode(repeat('00', 36), 'hex')`);
  assert.deepEqual(await vault.change(start('dev-2', 'CDFG-HJKL')), { refused: 'tampered' });
  assert.deepEqual(await vault.change(redeem('dev-1', 'ada-cli-2')), { refused: 'tampered' });
  await world.owner.execute(sql`DELETE FROM policy`);
  assert.deepEqual(await vault.change(start('dev-2', 'CDFG-HJKL')), { refused: 'adopting' });
  assert.deepEqual(await vault.change(redeem('dev-1', 'ada-cli-2')), { refused: 'adopting' });
  assert.deepEqual([(await entries()).length, (await logins()).length, await who('ada-cli-2')], [before, 1, 'unauthenticated']);
});

test('a code that is taken, by a device login waiting, decided, past its time or written behind the vault, is refused: the app draws another', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  assert.deepEqual(await vault.change(start('dev-2', 'BCDF-GHJK')), { refused: 'taken' }, 'its user code');
  assert.deepEqual(await vault.change(start('dev-1', 'CDFG-HJKL')), { refused: 'taken' }, 'its device code');
  await made(decide('ada-web', 'BCDF-GHJK'));
  world.tick(TTL_MS);
  assert.deepEqual(await vault.change(start('dev-2', 'BCDF-GHJK')), { refused: 'taken' }, 'until the upkeep deletes it, a day after');
  await world.owner.execute(sql`UPDATE device_logins SET mac = decode(repeat('00', 36), 'hex')`);
  assert.deepEqual(await vault.change(start('dev-2', 'BCDF-GHJK')), { refused: 'taken' });
  assert.ok(!('refused' in await vault.change(start('dev-2', 'CDFG-HJKL'))));
  assert.equal((await logins()).length, 2);
});

test('a device login or its approver written behind the vault is refused, tampered: a row that says someone approved it would become their session', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  await made(start('dev-2', 'CDFG-HJKL'));
  // A writer approves a waiting one in Root's name, and collects it.
  await world.owner.execute(sql`UPDATE device_logins SET decision = 'approved', decided_at = now(), principal = ${root} WHERE user_code = 'BCDF-GHJK'`);
  assert.deepEqual(await vault.change(redeem('dev-1', 'x-cli')), { refused: 'tampered' });
  assert.deepEqual(await vault.change(decide('ada-web', 'BCDF-GHJK')), { refused: 'tampered' }, 'nor does anyone decide it');
  // Or writes one whole, approved, with a device code of its own.
  await world.owner.execute(sql`INSERT INTO device_logins (id, device_code_hash, user_code, created_at, expires_at, decided_at, decision, principal, generation, mac)
    VALUES (gen_random_uuid(), ${tokenOf('forged')}, 'FGHJ-KLMN', now(), now() + interval '5 minutes', now(), 'approved', ${root}, 0, decode(repeat('00', 36), 'hex'))`);
  assert.deepEqual(await vault.change(redeem('forged', 'x-cli')), { refused: 'tampered' });
  // Ada approves dev-2, and a writer edits her row: whether she is still a member of that generation is not the row's to say.
  await made(decide('ada-web', 'CDFG-HJKL'));
  await world.owner.execute(sql`UPDATE principals SET mac = decode(repeat('00', 36), 'hex') WHERE id = ${ada}`);
  assert.deepEqual(await vault.change(redeem('dev-2', 'x-cli')), { refused: 'tampered' });
  assert.equal((await rowsOf(world.owner, sql`SELECT 1 FROM credentials WHERE token_hash = ${tokenOf('x-cli')}`)).length, 0);
  const found = await checked();
  assert.ok(found.length > 0, 'the signer names the rows');
});

test('two CLIs collecting one device login at once get one session: the second starts over, and finds it collected', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  await made(decide('ada-web', 'BCDF-GHJK'));
  const [first, second] = await Promise.all(['ada-cli-2', 'ada-cli-3'].map((token) => prepare(world, OPERATIONS['device.redeem'](redeem('dev-1', token), deciding))));
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.deepEqual([await commit(world, first), await commit(world, second)], [true, false]);
  assert.deepEqual(await vault.change(redeem('dev-1', 'ada-cli-3')), { refused: 'expired' });
  assert.deepEqual([await who('ada-cli-2'), await who('ada-cli-3')], [`${ada} cli`, 'unauthenticated']);
});

test('two people deciding one device login at once: the first decides it, and the second starts over and finds it decided', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  const [approval, denial] = [await prepare(world, OPERATIONS['device.decide'](decide('ada-web', 'BCDF-GHJK'), deciding)), await prepare(world, OPERATIONS['device.decide'](decide('bo-web', 'BCDF-GHJK', false), deciding))];
  assert.ok(!('refused' in approval) && !('refused' in denial));
  assert.deepEqual([await commit(world, denial), await commit(world, approval)], [true, false]);
  assert.deepEqual(await vault.change(decide('ada-web', 'BCDF-GHJK')), { refused: 'unknown_code' });
  assert.deepEqual(await vault.change(redeem('dev-1', 'ada-cli-2')), { refused: 'denied' });
});

test('a decision or a collection made in a device login\'s last moments is written only if it starts before it expires, by the database\'s clock', async () => {
  await made(start('dev-1', 'BCDF-GHJK'));
  await made(start('dev-2', 'CDFG-HJKL'));
  await made(decide('ada-web', 'CDFG-HJKL'));
  // 50 ms before both expire, by the vault's clock: each is decided, and its write waits longer than that.
  world.tick(TTL_MS - 50);
  const late = [await prepare(world, OPERATIONS['device.decide'](decide('ada-web', 'BCDF-GHJK'), deciding)), await prepare(world, OPERATIONS['device.redeem'](redeem('dev-2', 'ada-cli-2'), deciding))];
  assert.ok(late.every((prepared) => !('refused' in prepared)));
  await sleep(120);
  assert.deepEqual([await commit(world, late[0] as never), await commit(world, late[1] as never)], [false, false]);
  world.tick(120);
  assert.deepEqual([await vault.change(decide('ada-web', 'BCDF-GHJK')), await vault.change(redeem('dev-2', 'ada-cli-2'))], [{ refused: 'unknown_code' }, { refused: 'expired' }]);
  assert.equal(await who('ada-cli-2'), 'unauthenticated');
});

test('a device login that is not what the contract says is a fault, before anything is read', async () => {
  const wrong: Asked<'device.start' | 'device.decide' | 'device.redeem'>[] = [
    { ...start('dev-1', 'bcdf-ghjk') }, { ...start('dev-1', 'BCDFGHJK') }, { ...start('dev-1', 'BCDA-GHJK') }, { ...start('dev-1', 'BCDF-GHJ0') }, { ...start('dev-1', 'BCDF-GHJK'), code: 'abc' },
    { ...start('dev-1', 'BCDF-GHJK'), code: hex('dev-1').toUpperCase() }, { ...start('dev-1', 'BCDF-GHJK', '') }, { ...start('dev-1', 'BCDF-GHJK', ' padded') }, { ...start('dev-1', 'BCDF-GHJK', 'x'.repeat(121)) },
    { ...start('dev-1', 'BCDF-GHJK', 'tab\there') }, { ...start('dev-1', 'BCDF-GHJK', 'half \ud800') }, { ...start('dev-1', 'BCDF-GHJK'), ip: 7 as never },
    { ...decide('ada-web', 'bcdf-ghjk') }, { ...decide('ada-web', 'BCDF-GHJK'), approve: 'yes' as never }, { ...decide('ada-web', 'BCDF-GHJK'), token: 'abc' },
    { ...redeem('dev-1', 'x-cli'), code: 'abc' }, { ...redeem('dev-1', 'x-cli', 0) }, { ...redeem('dev-1', 'x-cli', 365 * 24 * 60 + 1) }, { ...redeem('dev-1', 'x-cli', 1.5) },
    { ...redeem('dev-1', 'x-cli'), session: { token: 'abc', minutes: 60 } }, { ...redeem('dev-1', 'x-cli'), session: null as never },
  ];
  for (const input of wrong) await assert.rejects(vault.change(input), TypeError, JSON.stringify(input).slice(0, 120));
  assert.deepEqual(await logins(), []);
  // The longest a CLI's session may be asked for: a year.
  await made(start('dev-1', 'BCDF-GHJK'));
  await made(decide('ada-web', 'BCDF-GHJK'));
  assert.ok(!('refused' in await vault.change(redeem('dev-1', 'ada-cli-2', 365 * 24 * 60))));
});

test('Cy, removed, signs in to nothing through a device login he approved before: none of his sessions stands to approve one', async () => {
  // Cy's CLI session is of a generation that is gone, so he is nobody who stands.
  await write(world, ...rows('credentials', credential('cy-cli', cy)));
  await made(start('dev-1', 'BCDF-GHJK'));
  assert.deepEqual(await vault.change(decide('cy-cli', 'BCDF-GHJK')), { refused: 'unauthenticated' });
  assert.deepEqual((await logins()).map((row) => row.decision), [null]);
});
