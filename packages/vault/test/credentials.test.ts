// Ending a credential, and linking and unlinking an account
// (src/ops/signin.ts, docs/design/0.16.md, "Signing in"): changes a caller
// asks. Through the contract as the app calls it, with the signer reading
// what it wrote.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { Account, Asked, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { grants, policy, principals } from '@coffre/db/schema';
import { sql, type SQL } from 'drizzle-orm';

import { change, commit, drop, part, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, binding, credential, environment, grant, identity, instance, principal, project, role, rows, session, TABLES, tokenOf, user, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const [root, ada, bo, cy, dee] = [user('root'), user('ada'), user('bo'), user('cy'), user('dee')];
const [ci, bare] = ['token:ci', 'token:bare'];
const GITHUB = 'issuer-of-github';
let signer: Signer;
/** The rows' ids, by label. */
const ids: Record<string, string> = {};

/**
 * Root runs the instance. Ada, Bo and Cy are members: Bo a Developer of
 * market/dev, Cy a Viewer there. Dee was removed and let back in. The
 * service account `ci` holds Developer on market/dev and was admitted by
 * Bo; `bare` holds nothing and was admitted by Ada. market protects prod.
 * Ada signs in with GitHub and Okta; Bo and Dee with GitHub.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: 90 });
  const market = project('market');
  const dev = environment(market, 'dev');
  const prod = environment(market, 'prod', { protected: true });
  const adaGithub = identity(ada, { provider: 'github', issuerHash: GITHUB, subject: 'gh-ada' });
  const adaOkta = identity(ada, { provider: 'okta', issuerHash: 'issuer-of-okta', subject: 'okta-ada' });
  const boGithub = identity(bo, { provider: 'github', issuerHash: GITHUB, subject: 'gh-bo' });
  const deeGithub = identity(dee, { provider: 'github', issuerHash: GITHUB, subject: 'gh-dee', generation: 1 });
  const made = [
    credential('root-cli', root),
    credential('ada-web', ada, { kind: 'browser', identityId: adaGithub.id }),
    credential('ada-okta-web', ada, { kind: 'browser', identityId: adaOkta.id }),
    credential('ada-cli', ada),
    credential('ada-pat', ada, { kind: 'personal', scope: '[]' }),
    credential('ada-handle', ada, { kind: 'handle', scope: '[]', places: '[]' }),
    credential('ada-old', ada, { expiresAt: new Date(world.now() - 1000) }),
    credential('ada-ended', ada, { revokedAt: new Date(world.now() - 1000), revokedBy: ada }),
    credential('bo-web', bo, { kind: 'browser', identityId: boGithub.id }),
    credential('bo-cli', bo),
    credential('bo-pat', bo, { kind: 'personal', scope: '[]' }),
    credential('cy-cli', cy),
    credential('dee-web', dee, { kind: 'browser', identityId: deeGithub.id, generation: 1 }),
    credential('ci-token', ci, { scope: '[]', createdBy: bo }),
    credential('ci-other', ci, { scope: '[]', createdBy: bo }),
    credential('bare-token', bare, { scope: '[]', createdBy: ada }),
  ];
  for (const row of made) ids[row.label!] = row.id;
  Object.assign(ids, { adaGithub: adaGithub.id, adaOkta: adaOkta.id, boGithub: boGithub.id, dev: dev.id, prod: prod.id, market: market.id });
  await write(
    world,
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write']), role(false, 'viewer', ['secret.read', 'secret.use'])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(ada), principal(bo), principal(cy), principal(dee, { generation: 1 }), principal(ci, { statusChangedBy: bo }), principal(bare, { statusChangedBy: ada })),
    ...rows('projects', market),
    ...rows('environments', dev, prod),
    ...rows('grants', grant(ci, 'developer', { environment: dev }), grant(bo, 'developer', { environment: dev }), grant(cy, 'viewer', { environment: dev })),
    ...rows('policy', instance()),
    ...rows('identities', adaGithub, adaOkta, boGithub, deeGithub),
    ...rows('credentials', ...made),
  );
  // The signer has signed the instance as made: what it finds after is a test's own.
  assert.deepEqual(await checked(), []);
});

const from = { request: 'req-1', ip: '192.0.2.7' };
const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, ...from });
const end = (label: string, credential: string | null, of: Asked<'credential.end'>['of'] = null) => ({ ...shown(label), op: 'credential.end', credential, of }) as Asked<'credential.end'>;
const okta = (subject: string, ...emails: string[]): Account => ({ provider: 'okta', issuer: 'issuer-of-okta', subject, emails });
const github = (subject: string, ...emails: string[]): Account => ({ provider: 'github', issuer: GITHUB, subject, emails });
const link = (label: string, account: Account): Asked<'account.link'> => ({ ...shown(label), op: 'account.link', account });
const unlink = (label: string, identity: string): Asked<'account.unlink'> => ({ ...shown(label), op: 'account.unlink', identity });
const deciding = { workloads: world.workloads, owners: world.owners };

/** Who a token is, as the vault answers any request that shows it. */
const who = async (label: string) => {
  world.memory.callers.clear();
  const answer = await vault.caller(shown(label));
  return 'refused' in answer ? answer.refused : `${answer.principal} ${answer.credential.kind}`;
};
const entries = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(world.keys, row)! }));
/** What an entry did to the rows it names: `<table> <made|read|replaced>`, sorted. */
const touched = (entry: Awaited<ReturnType<typeof entries>>[number]) =>
  [...new Set(entry.rows.filter(({ was, now }) => was !== now).map(({ row, was }) => `${(JSON.parse(row) as string[])[0]} ${was === null ? 'made' : 'replaced'}`))].sort();
const revoked = async () => (await rowsOf<{ label: string }>(world.owner, sql`SELECT label FROM credentials WHERE revoked_at IS NOT NULL ORDER BY label`)).map((row) => row.label);
/** Everything the vault told the signer of, signed, and the rows held to its mirror: what it found. */
async function checked() {
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  return (await signer.take()).map((finding) => finding.found);
}
/** One change that deletes the rows a condition finds, as a revocation of a grant does. */
async function dropped(table: keyof typeof TABLES, where: SQL) {
  const result = await change(world, {
    read: { found: part(TABLES[table], where) },
    decide: ({ found }) => ({ writes: found.map((row) => drop(TABLES[table], row as never)), entry: { kept: true, action: 'test.write', actor: null, credential: null, request: null, ip: null, objects: [], detail: {} }, answer: null }),
  });
  assert.ok(!('refused' in result));
}
/** Rows edited behind the vault: their MAC no longer the vault's, so no decision sees them. Undone by what it returns, which puts each MAC back. */
async function forged(table: string, where: SQL): Promise<() => Promise<void>> {
  const was = await rowsOf<{ mac: Buffer }>(world.owner, sql`SELECT mac FROM ${sql.identifier(table)} WHERE ${where}`);
  assert.equal(was.length, 1);
  await world.owner.execute(sql`UPDATE ${sql.identifier(table)} SET mac = decode(repeat('00', 36), 'hex') WHERE ${where}`);
  return async () => void (await world.owner.execute(sql`UPDATE ${sql.identifier(table)} SET mac = ${was[0]!.mac} WHERE ${where}`));
}

test('signing out ends the credential the request came in on: one row, an entry that ages out; anything else of theirs stands', async () => {
  const done = await vault.change(end('ada-web', null));
  assert.deepEqual(done, { answer: { credential: ids['ada-web'] } });
  assert.deepEqual([await who('ada-web'), await who('ada-cli'), await who('ada-okta-web')], ['unauthenticated', `${ada} cli`, `${ada} browser`]);
  const entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.action, entry.actor, entry.credential, entry.request, entry.ip], [false, 'sign_out', ada, ids['ada-web'], 'req-1', '192.0.2.7']);
  assert.deepEqual(entry.detail, { credential: ids['ada-web'], kind: 'browser', principal: ada });
  assert.deepEqual(touched(entry), ['credentials replaced']);
  // A token a service, or a person's personal token, signs out the same way.
  for (const label of ['ci-token', 'ada-pat']) assert.ok(!('refused' in await vault.change(end(label, null))), label);
  assert.deepEqual(await revoked(), ['ada-ended', 'ada-pat', 'ada-web', 'ci-token']);
  assert.deepEqual(await checked(), []);
});

test('signing out with a token that does not stand is unauthenticated, writes nothing and logs nothing: unknown, ended, expired, or a handle', async () => {
  await vault.change(end('ada-web', null));
  const before = (await entries()).length;
  world.woken.length = 0;
  for (const label of ['nobody', 'ada-web', 'ada-old', 'ada-ended', 'ada-handle']) assert.deepEqual(await vault.change(end(label, null)), { refused: 'unauthenticated' }, label);
  assert.deepEqual([(await entries()).length, world.woken.length, await revoked()], [before, 0, ['ada-ended', 'ada-web']]);
  assert.equal(await who('ada-handle'), 'unauthenticated', 'a handle is no caller of the API at all');
});

test('a person ends their own credentials by id, on a session: a session or a handle of theirs ages out, a token is kept', async () => {
  assert.ok(!('refused' in await vault.change(end('ada-cli', ids['ada-web']!))));
  let entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.action, entry.detail.kind, touched(entry)], [false, 'token.revoke', 'browser', ['credentials replaced']]);
  // Their personal token, from the members route: kept.
  assert.ok(!('refused' in await vault.change(end('ada-cli', ids['ada-pat']!, { member: ada }))));
  entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.action, entry.detail.kind], [true, 'token.revoke', 'personal']);
  // The credential they came in on, by its id: ended, as an ending and not a sign-out.
  assert.ok(!('refused' in await vault.change(end('ada-cli', ids['ada-cli']!))));
  assert.deepEqual([(await entries()).at(-1)!.action, await who('ada-cli')], ['token.revoke', 'unauthenticated']);
  assert.deepEqual(await revoked(), ['ada-cli', 'ada-ended', 'ada-pat', 'ada-web']);
  assert.deepEqual(await checked(), []);
});

test('a handle of their own ends on the handles route, from a personal token too; that route ends nothing else', async () => {
  const pat = await vault.change(end('ada-pat', ids['ada-cli']!, 'handle'));
  assert.deepEqual(pat, { refused: 'unknown_credential' });
  assert.deepEqual(await vault.change(end('bo-cli', ids['ada-handle']!, 'handle')), { refused: 'unknown_credential' });
  assert.deepEqual(await vault.change(end('ada-pat', ids['ada-handle']!, 'handle')), { answer: { credential: ids['ada-handle'] } });
  assert.equal((await entries()).at(-1)!.kept, false);
  assert.deepEqual(await revoked(), ['ada-ended', 'ada-handle']);
  assert.deepEqual(await checked(), []);
});

test("a personal token ends nothing by id but its person's handle; a service's token ends its own service's, on either route, and no other's", async () => {
  for (const asked of [end('ada-pat', ids['ada-cli']!), end('ada-pat', ids['ada-pat']!), end('ada-pat', ids['ada-web']!, { member: ada }), end('ci-token', ids['bare-token']!, { member: bare }), end('ci-token', ids['ada-cli']!)]) {
    assert.deepEqual(await vault.change(asked), { refused: 'unknown_credential' }, `${asked.token} ${JSON.stringify(asked.of)}`);
  }
  assert.deepEqual(await vault.change(end('ci-token', ids['ci-other']!)), { answer: { credential: ids['ci-other'] } });
  const entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.actor, entry.detail.kind], [true, ci, 'service']);
  assert.deepEqual(await vault.change(end('ci-token', ids['ci-token']!, { member: ci })), { answer: { credential: ids['ci-token'] } });
  assert.deepEqual(await revoked(), ['ada-ended', 'ci-other', 'ci-token']);
  assert.deepEqual(await checked(), []);
});

test("a workload's session ends its service's tokens on the members route, as 0.14.7's reached it, and nothing on the sessions route", async () => {
  const bound = binding(ci, { profile: 'kubernetes', policy: '{}' });
  await write(world, ...rows('bindings', bound), ...rows('credentials', session('ci-pod', bound)));
  const pod = (credential: string, of: Asked<'credential.end'>['of']) => ({ ...end('ci-pod', credential, of), proof: 'ci-pod' }) as Asked<'credential.end'>;
  assert.deepEqual(await vault.change(pod(ids['ci-other']!, null)), { refused: 'unknown_credential' });
  assert.deepEqual(await vault.change(pod(ids['ci-other']!, { member: ci })), { answer: { credential: ids['ci-other'] } });
  assert.deepEqual(await revoked(), ['ada-ended', 'ci-other']);
  assert.deepEqual(await checked(), []);
});

test('an environment unprotected behind the vault refuses, tampered: it may be protected, where whoever would manage the service holds less', async () => {
  // A role that only uses what it holds in a protected environment: a Maker of all market, as ci is, holds less in prod than ci's grant gives.
  await write(world, ...rows('roles', role(false, 'maker', ['secret.read', 'secret.use', 'secret.write'], ['secret.use'])), ...rows('grants', grant(ci, 'maker', { project: { id: ids.market! } }), grant(bo, 'maker', { project: { id: ids.market! } })));
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: 'unknown_credential' });
  // prod's row, edited to say it is not protected: the caller's read, which takes the protected ones, no longer finds it.
  await world.owner.execute(sql`UPDATE environments SET protected = false WHERE id = ${ids.prod!}`);
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: 'tampered' });
  assert.deepEqual(await revoked(), ['ada-ended']);
});

test("someone else's credential is no member's to end: one answer, as for one that is not there or is ended; logged once a minute", async () => {
  const before = (await entries()).length;
  const refusedAll = [ids['ada-cli']!, ids['ada-ended']!, ids['ada-old']!, '00000000-0000-4000-8000-000000000000'].map((id) => vault.change(end('bo-cli', id)));
  for (const answer of await Promise.all(refusedAll)) assert.deepEqual(answer, { refused: 'unknown_credential' });
  // Bo's own token, named as Ada's: not hers, so not one of hers to end.
  assert.deepEqual(await vault.change(end('bo-cli', ids['bo-pat']!, { member: ada })), { refused: 'unknown_credential' });
  const logged = (await entries()).slice(before);
  assert.equal(logged.length, 1);
  assert.deepEqual([logged[0]!.kept, logged[0]!.action, logged[0]!.actor, logged[0]!.detail], [false, 'token.revoke', bo, { refused: 'unknown_credential' }]);
  assert.deepEqual(await revoked(), ['ada-ended']);
});

test("whoever runs the instance ends anyone's credential, a person's or a service's, and the ending is kept", async () => {
  assert.ok(!('refused' in await vault.change(end('root-cli', ids['ada-cli']!))));
  assert.ok(!('refused' in await vault.change(end('root-cli', ids['bare-token']!, { member: bare }))));
  const entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.actor, entry.detail.principal], [true, root, bare]);
  assert.ok(entry.objects.includes(`principal:${bare}`) && entry.objects.includes(`credential:${ids['bare-token']}`));
  assert.deepEqual([await who('ada-cli'), await who('bare-token')], ['unauthenticated', 'unauthenticated']);
  assert.deepEqual(await checked(), []);
});

test('an Owner whose instance role has no row runs nothing: ends nobody else\'s credential', async () => {
  await forged('roles', sql`instance AND id = 'owner'`);
  // Told so: the app scopes its pages by what the vault decides by, the role a member holds.
  const roleOf = async () => {
    world.memory.callers.clear();
    const answer = await vault.caller(shown('root-cli'));
    return 'refused' in answer ? answer.refused : answer.holds.role;
  };
  assert.equal(await roleOf(), 'member');
  assert.deepEqual(await vault.change(end('root-cli', ids['ada-cli']!)), { refused: 'unknown_credential' });
  assert.deepEqual(await vault.change(end('root-cli', ids['bare-token']!, { member: bare })), { refused: 'unknown_credential' });
  assert.deepEqual(await revoked(), ['ada-ended']);
  await world.owner.execute(sql`DELETE FROM roles WHERE instance AND id = 'owner'`);
  assert.equal(await roleOf(), 'member');
});

test("a service account's tokens are ended by whoever manages it: one who holds all it holds, where the setting lets people; or who admitted it while it holds nothing", async () => {
  // Cy views market/dev: he does not hold what ci holds there.
  assert.deepEqual(await vault.change(end('cy-cli', ids['ci-token']!, { member: ci })), { refused: 'unknown_credential' });
  // Bo, a Developer there, does: on the members route, never on the sessions route.
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!)), { refused: 'unknown_credential' });
  assert.deepEqual(await vault.change(end('bo-pat', ids['ci-token']!, { member: ci })), { refused: 'unknown_credential' }, 'on a session');
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: bare })), { refused: 'unknown_credential' }, "named as another's");
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { answer: { credential: ids['ci-token'] } });
  const entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.action, entry.actor, entry.detail], [true, 'token.revoke', bo, { credential: ids['ci-token'], kind: 'service', principal: ci }]);
  // What it read: the service, its grant and where, the setting, and Bo's grant there.
  const read = entry.rows.map(({ row }) => (JSON.parse(row) as string[])[0]);
  for (const table of ['principals', 'grants', 'environments', 'policy']) assert.ok(read.includes(table), table);
  // `bare` holds nothing: Ada admitted it, so she manages it, and Bo does not.
  assert.deepEqual(await vault.change(end('bo-cli', ids['bare-token']!, { member: bare })), { refused: 'unknown_credential' });
  assert.ok(!('refused' in await vault.change(end('ada-cli', ids['bare-token']!, { member: bare }))));
  assert.deepEqual(await checked(), []);
});

test('where the setting keeps people out, only whoever runs the instance manages a service account; a setting, a service or a place the read did not find manages nothing', async () => {
  await amend(world, 'policy', sql`${policy.onlyRow}`, { serviceAccounts: JSON.stringify({ projects: 'all', environments: { except: ['dev'] } }) });
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: 'unknown_credential' });
  await amend(world, 'policy', sql`${policy.onlyRow}`, { serviceAccounts: JSON.stringify({ projects: 'all', environments: 'all' }) });
  const staging = environment({ id: ids.market! }, 'staging');
  // Bo holds all of market, where ci holds staging, a place none of Bo's rows names: his read finds it as ci's alone.
  await write(world, ...rows('environments', staging), ...rows('grants', grant(ci, 'viewer', { environment: staging }), grant(bo, 'developer', { project: { id: ids.market! } })));
  for (const [table, where] of [['policy', sql`true`], ['principals', sql`id = ${ci}`], ['environments', sql`id = ${staging.id}`], ['roles', sql`NOT instance AND id = 'viewer'`]] as const) {
    const undo = await forged(table, where);
    // An environment of the service's projects written behind the vault may be a protected one: that refusal says so.
    assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: table === 'environments' ? 'tampered' : 'unknown_credential' }, table);
    // Put back as the vault wrote it: the next one is tried alone, and it stands again.
    await undo();
    assert.ok(!('refused' in await prepare(world, OPERATIONS['credential.end'](end('bo-cli', ids['ci-token']!, { member: ci }), deciding))), table);
  }
  // A service removed is managed by whoever runs the instance alone.
  await amend(world, 'principals', sql`${principals.id} = ${ci}`, { status: 'removed', generation: 1 });
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: 'unknown_credential' });
  assert.deepEqual(await revoked(), ['ada-ended']);
});

test('an expired credential is ended already, and a session is no token: one answer, to its holder and to whoever runs the instance', async () => {
  for (const asked of [end('ada-cli', ids['ada-old']!), end('root-cli', ids['ada-old']!), end('ada-cli', ids['ada-web']!, { member: ada }), end('root-cli', ids['ada-web']!, { member: ada })]) {
    assert.deepEqual(await vault.change(asked), { refused: 'unknown_credential' }, JSON.stringify(asked.of));
  }
  assert.deepEqual(await revoked(), ['ada-ended']);
});

test("someone else's credential ended is kept, and says who ended it", async () => {
  assert.ok(!('refused' in await vault.change(end('root-cli', ids['ada-cli']!))));
  assert.deepEqual([(await entries()).at(-1)!.kept, await rowsOf(world.owner, sql`SELECT revoked_by AS by FROM credentials WHERE id = ${ids['ada-cli']}`)], [true, [{ by: root }]]);
  assert.deepEqual(await checked(), []);
});

test("what a service account holds is its live grants on places that are there: an expired grant, one of another generation, one on a deleted environment or project weigh nothing", async () => {
  const staging = environment({ id: ids.market! }, 'staging');
  const old = environment({ id: ids.market! }, 'old~1');
  const gone = project('gone~1');
  await write(
    world,
    ...rows('projects', gone),
    ...rows('environments', staging, old),
    ...rows('grants', grant(ci, 'developer', { project: gone })),
    ...rows('grants', grant(ci, 'developer', { environment: staging }, { expiresAt: new Date(world.now() - 1000) }), grant(ci, 'developer', { project: { id: ids.market! } }, { generation: 1 }), grant(ci, 'developer', { environment: old })),
  );
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { answer: { credential: ids['ci-token'] } });
  assert.deepEqual(await checked(), []);
});

test("a project a service account's grant is on, which the read did not find, makes it no one's to manage but whoever runs the instance", async () => {
  await write(world, ...rows('grants', grant(bo, 'developer', { project: { id: ids.market! } }), grant(ci, 'viewer', { project: { id: ids.market! } })));
  const prepared = await prepare(world, OPERATIONS['credential.end'](end('bo-cli', ids['ci-token']!, { member: ci }), deciding));
  assert.ok(!('refused' in prepared), 'refused' in prepared ? prepared.refused : '');
  await forged('projects', sql`id = ${ids.market}`);
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: 'unknown_credential' });
  assert.ok(!('refused' in await vault.change(end('root-cli', ids['ci-token']!, { member: ci }))));
});

test('a setting that does not read as a scope lets nobody set up service accounts', async () => {
  await amend(world, 'policy', sql`${policy.onlyRow}`, { serviceAccounts: '"everywhere"' });
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: 'unknown_credential' });
});

test("a grant of the service's, or an environment the project protects, written behind the vault refuses whoever would manage it by what it holds: tampered", async () => {
  for (const [table, where] of [['grants', sql`principal = ${ci}`], ['environments', sql`id = ${ids.prod}`]] as const) {
    const undo = await forged(table, where);
    assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: 'tampered' }, table);
    await undo();
  }
  // Whoever runs the instance manages it whatever it holds.
  await forged('grants', sql`principal = ${ci}`);
  assert.ok(!('refused' in await vault.change(end('root-cli', ids['ci-token']!, { member: ci }))));
});

test('a grant the decision weighed, revoked between the read and the write, starts the change over, and it is refused', async () => {
  const prepared = await prepare(world, OPERATIONS['credential.end'](end('bo-cli', ids['ci-token']!, { member: ci }), deciding));
  assert.ok(!('refused' in prepared));
  await dropped('grants', sql`${grants.principal} = ${bo}`);
  assert.equal(await commit(world, prepared), false);
  assert.deepEqual(await vault.change(end('bo-cli', ids['ci-token']!, { member: ci })), { refused: 'unknown_credential' });
  // And the service's own grant, which says what Bo must hold: one granted meanwhile starts it over too.
  await write(world, ...rows('grants', grant(bo, 'developer', { environment: { id: ids.dev! } })));
  const again = await prepare(world, OPERATIONS['credential.end'](end('bo-cli', ids['ci-token']!, { member: ci }), deciding));
  assert.ok(!('refused' in again));
  await write(world, ...rows('grants', grant(ci, 'owner', { project: { id: ids.market! } })));
  assert.equal(await commit(world, again), false);
  assert.deepEqual(await revoked(), ['ada-ended']);
  assert.deepEqual(await checked(), []);
});

test('two endings of one credential side by side end it once: the second starts over, and finds it ended', async () => {
  const [first, second] = await Promise.all(['root-cli', 'ada-cli'].map((label) => prepare(world, OPERATIONS['credential.end'](end(label, ids['ada-web']!), deciding))));
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.deepEqual([await commit(world, first), await commit(world, second)], [true, false]);
  assert.deepEqual(await vault.change(end('ada-cli', ids['ada-web']!)), { refused: 'unknown_credential' });
  assert.deepEqual(await checked(), []);
});

test('a person links a second account from their browser session: it signs them in after; the entry is kept', async () => {
  // Bo signs in with GitHub: an Okta account that verified his address binds to him from his browser alone.
  const done = await vault.change(link('bo-web', okta('okta-bo', 'bo@acme.example')));
  assert.ok(!('refused' in done), JSON.stringify(done));
  const entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.action, entry.actor, entry.credential, touched(entry)], [true, 'account.link', bo, ids['bo-web'], ['identities made']]);
  assert.deepEqual(entry.detail, { verified: 'app', provider: 'okta', subject: 'okta-bo', emails: ['bo@acme.example'], identity: done.answer.identity });
  const [row] = await rowsOf<{ principal: string; generation: number; email: string; by: string }>(world.owner, sql`SELECT principal, generation, email, created_by AS by FROM identities WHERE id = ${done.answer.identity}`);
  assert.deepEqual(row, { principal: bo, generation: 0, email: 'bo@acme.example', by: bo });
  const signedIn = await vault.change({ ...from, op: 'signin', account: okta('okta-bo'), session: { token: tokenOf('bo-okta-web').toString('hex'), minutes: 60, label: null }, replaces: null });
  assert.ok(!('refused' in signedIn));
  assert.equal(await who('bo-okta-web'), `${bo} browser`);
  assert.deepEqual(await checked(), []);
});

test('an account bound already is refused, to the one it is bound to too; a link asks a browser session', async () => {
  assert.deepEqual(await vault.change(link('ada-web', github('gh-bo', 'ada@acme.example'))), { refused: 'already_linked' });
  assert.deepEqual(await vault.change(link('ada-web', okta('okta-ada'))), { refused: 'already_linked' });
  for (const label of ['ada-cli', 'ada-pat', 'ci-token']) assert.deepEqual(await vault.change(link(label, okta('okta-new', 'ada@acme.example'))), { refused: 'no_access' }, label);
  assert.deepEqual(await vault.change(link('nobody', okta('okta-new'))), { refused: 'unauthenticated' });
  // Another issuer's account of the same subject is another account.
  assert.ok(!('refused' in await vault.change(link('ada-web', { ...okta('okta-ada'), issuer: 'another-tenant' }))));
  const refusals = (await entries()).filter((entry) => entry.detail.refused !== undefined);
  // Refused to Ada four times within the minute, on three credentials: one entry for her, and one for ci.
  assert.deepEqual(refusals.map((entry) => `${entry.actor} ${entry.action} ${String(entry.detail.refused)}`), [`${ada} account.link already_linked`, `${ci} account.link no_access`]);
  assert.deepEqual(await checked(), []);
});

test('two links of one account side by side bind it once: the second starts over, and finds it bound', async () => {
  const [first, second] = await Promise.all(['bo-web', 'ada-web'].map((label) => prepare(world, OPERATIONS['account.link'](link(label, okta('okta-new', 'x@acme.example')), deciding))));
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.deepEqual([await commit(world, first), await commit(world, second)], [true, false]);
  assert.deepEqual(await vault.change(link('ada-web', okta('okta-new', 'x@acme.example'))), { refused: 'already_linked' });
  assert.deepEqual(await checked(), []);
});

test('an account whose row was written behind the vault is bound to someone it cannot say: the link is refused, and writes nothing', async () => {
  await forged('identities', sql`subject = 'gh-bo'`);
  assert.deepEqual(await vault.change(link('ada-web', github('gh-bo'))), { refused: 'tampered' });
  assert.equal((await rowsOf(world.owner, sql`SELECT 1 FROM identities WHERE subject = 'gh-bo'`)).length, 1);
  assert.deepEqual(await checked(), ['row']);
});

test('a member let back in links an account in the generation they are in: it signs them in after', async () => {
  const done = await vault.change(link('dee-web', okta('okta-dee')));
  assert.ok(!('refused' in done));
  const [row] = await rowsOf<{ generation: number }>(world.owner, sql`SELECT generation FROM identities WHERE id = ${done.answer.identity}`);
  assert.equal(row!.generation, 1);
  assert.ok(!('refused' in await vault.change({ ...from, op: 'signin', account: okta('okta-dee'), session: { token: tokenOf('dee-okta-web').toString('hex'), minutes: 60, label: null }, replaces: null })));
  assert.equal(await who('dee-okta-web'), `${dee} browser`);
  assert.deepEqual(await checked(), []);
});

test('unlinking an account revokes its identity alone: the sessions it opened end with no write; the others stand', async () => {
  const done = await vault.change(unlink('ada-cli', ids.adaGithub!));
  assert.deepEqual(done, { answer: { identity: ids.adaGithub } });
  const entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.action, entry.actor, touched(entry)], [true, 'account.unlink', ada, ['identities replaced']]);
  assert.deepEqual(entry.detail, { identity: ids.adaGithub, provider: 'github', subject: 'gh-ada' });
  assert.deepEqual([await who('ada-web'), await who('ada-okta-web'), await who('ada-cli')], ['unauthenticated', `${ada} browser`, `${ada} cli`]);
  // No credential's row was written.
  assert.deepEqual(await revoked(), ['ada-ended']);
  assert.deepEqual(await checked(), []);
});

test('the last account too, as 0.14.7 let it: its sessions end, and the next sign-in binds an account anew by a verified email', async () => {
  for (const id of [ids.adaGithub!, ids.adaOkta!]) assert.ok(!('refused' in await vault.change(unlink('ada-cli', id))));
  assert.deepEqual([await who('ada-web'), await who('ada-okta-web'), await who('ada-cli')], ['unauthenticated', 'unauthenticated', `${ada} cli`]);
  const signedIn = await vault.change({ ...from, op: 'signin', account: github('gh-ada', 'ada@acme.example'), session: { token: tokenOf('ada-web-2').toString('hex'), minutes: 60, label: null }, replaces: null });
  assert.ok(!('refused' in signedIn));
  assert.deepEqual([await who('ada-web-2'), (await entries()).at(-1)!.detail.bound], [`${ada} browser`, 'ada@acme.example']);
  assert.deepEqual(await checked(), []);
});

test("an account that is not the caller's, or is unlinked already, is one refusal; a credential with a scope unlinks nothing", async () => {
  assert.deepEqual(await vault.change(unlink('ada-cli', ids.boGithub!)), { refused: 'unknown_identity' });
  assert.deepEqual(await vault.change(unlink('ada-cli', '00000000-0000-4000-8000-000000000000')), { refused: 'unknown_identity' });
  await vault.change(unlink('ada-cli', ids.adaOkta!));
  assert.deepEqual(await vault.change(unlink('ada-web', ids.adaOkta!)), { refused: 'unknown_identity' });
  assert.deepEqual(await vault.change(unlink('ada-pat', ids.adaGithub!)), { refused: 'no_access' });
  assert.deepEqual(await vault.change(unlink('ci-token', ids.adaGithub!)), { refused: 'no_access' });
  assert.equal(await who('bo-web'), `${bo} browser`);
  // An identity hidden from the read is none of hers.
  await forged('identities', sql`id = ${ids.adaGithub}`);
  assert.deepEqual(await vault.change(unlink('ada-cli', ids.adaGithub!)), { refused: 'unknown_identity' });
});

test('two unlinkings of one account side by side revoke it once: the second starts over, and is refused', async () => {
  const [first, second] = await Promise.all(['ada-cli', 'ada-okta-web'].map((label) => prepare(world, OPERATIONS['account.unlink'](unlink(label, ids.adaGithub!), deciding))));
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.deepEqual([await commit(world, first), await commit(world, second)], [true, false]);
  assert.deepEqual(await vault.change(unlink('ada-okta-web', ids.adaGithub!)), { refused: 'unknown_identity' });
  assert.deepEqual(await checked(), []);
});

test('what the contract does not take is a fault, before anything is read', async () => {
  const wrong: Asked<'credential.end' | 'account.link' | 'account.unlink'>[] = [
    end('ada-cli', null, 'handle'), end('ada-cli', null, { member: ada }), end('ada-cli', 'abc'), end('ada-cli', ids['ada-web']!.toUpperCase()),
    end('ada-cli', ids['ada-web']!, 'own' as never), end('ada-cli', ids['ada-web']!, { member: 'ada' }), end('ada-cli', ids['ada-web']!, { member: 7 } as never), end('ada-cli', 7 as never),
    { ...end('ada-cli', null), token: 'abc' },
    link('ada-web', okta('okta-x', 'Ada@acme.example')), link('ada-web', okta('')), link('ada-web', null as never),
    unlink('ada-cli', 'abc'), unlink('ada-cli', null as never),
  ];
  for (const asked of wrong) await assert.rejects(vault.change(asked), TypeError, JSON.stringify(asked).slice(0, 120));
  assert.deepEqual([await revoked(), (await rowsOf(world.owner, sql`SELECT 1 FROM identities`)).length], [['ada-ended'], 4]);
});

test('what this file wrote, the signer finds nothing wrong with', async () => {
  await vault.change(end('ada-web', null));
  await vault.change(end('root-cli', ids['ci-token']!, { member: ci }));
  await vault.change(link('bo-web', okta('okta-bo')));
  await vault.change(unlink('ada-cli', ids.adaOkta!));
  assert.deepEqual(await checked(), []);
});
