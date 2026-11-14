// A person signs in (src/ops/signin.ts, docs/design/0.16.md, "Signing in"):
// the one change nobody asks, on an account the app verified. Through the
// contract as the app calls it, with the signer reading what it wrote.
import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

import type { Account, Asked, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { credentials, identities, principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { commit, prepare } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, credential, identity, principal, role, rows, tokenOf, user, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
/** The same vault, of a deployment that names Root and Ada its Owners. */
const owned = openLocalVault(world.db, { ...world, owners: ['root@acme.example', 'ada@acme.example', 'cy@acme.example'] }, { wake: world.wake, now: world.now });
after(() => world.close());

const [ada, bo, cy, dee] = [user('ada'), user('bo'), user('cy'), user('dee')];
const GITHUB = 'issuer-of-github';
let signer: Signer;
let bos: ReturnType<typeof identity>;

/**
 * Ada and Bo are members, Cy was removed, Dee was removed and let back in.
 * Bo signs in with GitHub already, and has a session and a CLI's.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: 90 });
  bos = identity(bo, { provider: 'github', issuerHash: GITHUB, subject: 'gh-bo', email: 'bo@old.example' });
  await write(
    world,
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(bo), principal(cy, { status: 'removed', generation: 1 }), principal(dee, { generation: 1 })),
    // Dee's account from before her removal: of a generation that is gone.
    ...rows('identities', bos, identity(dee, { provider: 'github', issuerHash: GITHUB, subject: 'gh-dee', generation: 0 })),
    // Cy's CLI session from before his removal.
    ...rows('credentials', credential('bo-web', bo, { kind: 'browser', identityId: bos.id }), credential('bo-cli', bo), credential('cy-cli', cy)),
  );
  // The signer has signed the instance as made: what it finds after is a test's own.
  assert.deepEqual(await checked(), []);
});

const from = { request: 'req-1', ip: '192.0.2.7' };
const github = (subject: string, ...emails: string[]): Account => ({ provider: 'github', issuer: GITHUB, subject, emails });
const signin = (account: Account, label: string, more: Partial<Asked<'signin'>> = {}): Asked<'signin'> =>
  ({ ...from, op: 'signin', account, session: { token: tokenOf(label).toString('hex'), minutes: 12 * 60, label: 'Firefox on macOS' }, replaces: null, ...more });
const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, ...from });
/** Who a token is, as the vault answers any request that shows it. */
const who = async (label: string, through = vault) => {
  world.memory.callers.clear();
  const answer = await through.caller(shown(label));
  return 'refused' in answer ? answer.refused : `${answer.principal} ${answer.holds.role} ${answer.credential.kind}`;
};
const entries = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(world.keys, row)! }));
const accounts = () => rowsOf<{ principal: string; subject: string; email: string | null; generation: number; signed: boolean; revoked: boolean }>(
  world.owner, sql`SELECT principal, subject, email, generation, last_sign_in_at IS NOT NULL AS signed, revoked_at IS NOT NULL AS revoked FROM identities ORDER BY subject`);
/** Everything the vault told the signer of, signed, and the rows held to its mirror: what it found. */
async function checked() {
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  return (await signer.take()).map((finding) => finding.found);
}

test('a new account is bound to the member its email names, who signs in: two rows, one kept entry, and a session the vault then knows', async () => {
  const before = (await entries()).length;
  const done = await vault.change(signin(github('gh-ada', 'ada@acme.example', 'ada@home.example'), 'ada-web'));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.deepEqual([done.answer.principal, done.answer.expiresAt], [ada, new Date(world.now() + 12 * 3_600_000).toISOString()]);
  assert.equal(await who('ada-web'), `${ada} member browser`);
  assert.deepEqual((await accounts()).find((row) => row.subject === 'gh-ada'), { principal: ada, subject: 'gh-ada', email: 'ada@acme.example', generation: 0, signed: true, revoked: false });

  const logged = await entries();
  assert.equal(logged.length, before + 1);
  const entry = logged.at(-1)!;
  assert.deepEqual([entry.kept, entry.action, entry.actor, entry.credential, entry.request, entry.ip], [true, 'sign_in', ada, done.answer.credential, 'req-1', '192.0.2.7']);
  // It says the account is the app's word, and which email bound it.
  assert.deepEqual({ ...entry.detail, identity: undefined }, { kind: 'browser', verified: 'app', provider: 'github', issuer: GITHUB, subject: 'gh-ada', emails: ['ada@acme.example', 'ada@home.example'], bound: 'ada@acme.example', identity: undefined });
  assert.ok(entry.objects.includes(`principal:${ada}`) && entry.objects.includes(`credential:${done.answer.credential}`), entry.objects.join());
  const tables = entry.rows.map(({ row, was, now }) => `${(JSON.parse(row) as string[])[0]} ${was === null ? 'made' : was === now ? 'read' : 'replaced'}`).sort();
  assert.deepEqual(tables, ['credentials made', 'identities made', 'principals read']);
  assert.equal(world.woken.length, 1);
  assert.deepEqual(await checked(), []);
});

test('an account bound signs its member in again: a session, the identity\'s last sign-in and email, an entry that ages out; the session the browser showed ends', async () => {
  const done = await vault.change(signin(github('gh-bo', 'bo@acme.example'), 'bo-web-2', { replaces: tokenOf('bo-web').toString('hex') }));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.deepEqual([await who('bo-web-2'), await who('bo-web'), await who('bo-cli')], [`${bo} member browser`, 'unauthenticated', `${bo} member cli`]);
  assert.deepEqual((await accounts()).find((row) => row.subject === 'gh-bo'), { principal: bo, subject: 'gh-bo', email: 'bo@acme.example', generation: 0, signed: true, revoked: false });
  const entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.action, entry.actor, entry.detail.bound, typeof entry.detail.replaced], [false, 'sign_in', bo, undefined, 'string']);
  // The session it ended is found from the log by its own id.
  assert.ok(entry.objects.includes(`credential:${String(entry.detail.replaced)}`), entry.objects.join());
  // Whatever its emails say now: the account is the subject, never an address. No email at all keeps the one it had.
  assert.ok(!('refused' in await vault.change(signin(github('gh-bo', 'ada@acme.example'), 'bo-web-3'))));
  assert.equal(await who('bo-web-3'), `${bo} member browser`);
  assert.ok(!('refused' in await vault.change(signin(github('gh-bo'), 'bo-web-4'))));
  assert.equal((await accounts()).find((row) => row.subject === 'gh-bo')!.email, 'ada@acme.example');
  // Only a browser's session is replaced, and one that is not there is no matter.
  await vault.change(signin(github('gh-bo'), 'bo-web-5', { replaces: tokenOf('bo-cli').toString('hex') }));
  await vault.change(signin(github('gh-bo'), 'bo-web-6', { replaces: tokenOf('nobody').toString('hex') }));
  assert.deepEqual([await who('bo-cli'), await who('bo-web-5'), await who('bo-web-6')], [`${bo} member cli`, `${bo} member browser`, `${bo} member browser`]);
  // One ended already is not ended again; and a browser holds one session, whoever's the last was: Ada's sign-in ends Bo's.
  await vault.change(signin(github('gh-bo'), 'bo-web-7', { replaces: tokenOf('bo-web').toString('hex') }));
  assert.equal((await entries()).at(-1)!.detail.replaced, undefined);
  await vault.change(signin(github('gh-ada', 'ada@acme.example'), 'ada-web', { replaces: tokenOf('bo-web-7').toString('hex') }));
  assert.deepEqual([await who('ada-web'), await who('bo-web-7'), typeof (await entries()).at(-1)!.detail.replaced], [`${ada} member browser`, 'unauthenticated', 'string']);
  assert.deepEqual(await checked(), []);
});

test('a sign-in is refused to whoever is no member, was removed, or signs in with another account already; nothing is written, logged or told', async () => {
  const before = [(await entries()).length, (await accounts()).length];
  assert.equal(world.woken.length, 0);
  const refused = async (account: Account) => vault.change(signin(account, 'x-web'));
  assert.deepEqual(await refused(github('gh-eve', 'eve@acme.example')), { refused: 'not_registered' });
  assert.deepEqual(await refused(github('gh-eve')), { refused: 'not_registered' }, 'no verified email');
  assert.deepEqual(await refused(github('gh-cy', 'cy@acme.example')), { refused: 'deactivated' }, 'removed');
  // The first email that names a member says who it is: one removed is not passed over for the next.
  assert.deepEqual(await refused(github('gh-cy', 'eve@acme.example', 'cy@acme.example', 'ada@acme.example')), { refused: 'deactivated' });
  // Bo signs in with GitHub already: another account that verified his address is not his until he links it.
  assert.deepEqual(await refused({ ...github('oidc-bo', 'bo@acme.example'), provider: 'okta' }), { refused: 'account_mismatch' });
  assert.deepEqual(await refused(github('gh-bo-2', 'bo@acme.example')), { refused: 'account_mismatch' });
  // Another issuer's account of the same subject is another account.
  assert.deepEqual(await refused({ ...github('gh-bo', 'bo@acme.example'), issuer: 'another-tenant' }), { refused: 'account_mismatch' });
  // An account bound before its member's removal is dead with all they held, though they are back.
  assert.deepEqual(await refused(github('gh-dee', 'dee@acme.example')), { refused: 'deactivated' });
  assert.equal(world.woken.length, 0, 'nothing was told');
  // And one whose member was removed since: by their row's own word, whatever its generation says.
  await amend(world, 'principals', sql`${principals.id} = ${bo}`, { status: 'removed' });
  world.woken.length = 0;
  assert.deepEqual(await refused(github('gh-bo', 'bo@acme.example')), { refused: 'deactivated' });
  assert.deepEqual([(await entries()).length, (await accounts()).length, world.woken.length, await who('x-web')], [before[0]! + 1, before[1], 0, 'unauthenticated']);
});

test('the second of its emails names the member when the first names nobody; an account unlinked is free to be bound again', async () => {
  assert.ok(!('refused' in await vault.change(signin(github('gh-ada', 'a.lovelace@home.example', 'ada@acme.example'), 'ada-web'))));
  assert.equal(await who('ada-web'), `${ada} member browser`);
  assert.equal((await entries()).at(-1)!.detail.bound, 'ada@acme.example');
  // Bo unlinks his account: its sessions are dead, and it binds anew to whoever its emails name.
  await amend(world, 'identities', sql`${identities.id} = ${bos.id}`, { revokedAt: new Date(world.now()), revokedBy: bo });
  assert.equal(await who('bo-web'), 'unauthenticated');
  assert.ok(!('refused' in await vault.change(signin(github('gh-bo', 'bo@acme.example'), 'bo-web-2'))));
  assert.deepEqual((await accounts()).filter((row) => row.subject === 'gh-bo').map((row) => row.revoked).sort(), [false, true]);
  assert.deepEqual([await who('bo-web'), await who('bo-web-2')], ['unauthenticated', `${bo} member browser`]);
  // So is Dee's, once her removal's account is revoked: bound again in the generation she is back in, as her session is.
  await amend(world, 'identities', sql`${identities.subject} = 'gh-dee'`, { revokedAt: new Date(world.now()), revokedBy: dee });
  assert.ok(!('refused' in await vault.change(signin(github('gh-dee', 'dee@acme.example'), 'dee-web'))));
  assert.deepEqual([await who('dee-web'), (await accounts()).filter((row) => row.subject === 'gh-dee').map((row) => `${row.generation} ${row.revoked}`).sort()], [`${dee} member browser`, ['0 true', '1 false']]);
  assert.deepEqual(await checked(), []);
});

test('an account of a generation before its member\'s last removal is no account of theirs: another binds, as a first one does', async () => {
  // Dee's old account is dead and not revoked; she signs in with a new one.
  assert.ok(!('refused' in await vault.change(signin(github('gh-dee-2', 'dee@acme.example'), 'dee-web'))));
  assert.equal(await who('dee-web'), `${dee} member browser`);
  // Now she has one: a third is refused.
  assert.deepEqual(await vault.change(signin(github('gh-dee-3', 'dee@acme.example'), 'dee-web-2')), { refused: 'account_mismatch' });
  assert.deepEqual(await checked(), []);
});

test('an Owner the configuration names is a member whatever the rows say: made one, or made one again, as they sign in', async () => {
  // Nobody's row: not a member of a deployment that does not name them.
  assert.deepEqual(await vault.change(signin(github('gh-root', 'root@acme.example'), 'root-web')), { refused: 'not_registered' });
  const made = await owned.change(signin(github('gh-root', 'root@acme.example'), 'root-web'));
  assert.ok(!('refused' in made), JSON.stringify(made));
  assert.equal(await who('root-web', owned), 'user:root@acme.example owner browser');
  let entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.detail.owner, entry.detail.bound], [true, 'made', 'root@acme.example']);
  assert.deepEqual(entry.rows.map(({ row, was }) => `${(JSON.parse(row) as string[])[0]} ${was === null ? 'made' : 'replaced'}`).sort(), ['credentials made', 'identities made', 'principals made']);
  // Signing in again changes nothing of their row.
  await owned.change(signin(github('gh-root', 'root@acme.example'), 'root-web-2'));
  entry = (await entries()).at(-1)!;
  assert.deepEqual([entry.kept, entry.detail.owner], [false, undefined]);

  // Ada, a Member the configuration now names: an Owner from her next sign-in on, and from no request before it.
  await owned.change(signin(github('gh-ada', 'ada@acme.example'), 'ada-web'));
  entry = (await entries()).at(-1)!;
  assert.deepEqual([await who('ada-web', owned), entry.kept, entry.detail.owner], [`${ada} owner browser`, true, 'restored']);
  const standing = async (id: string) => (await rowsOf<{ status: string; role: string; scope: string | null; by: string; generation: number }>(world.owner, sql`SELECT status, role, scope, status_changed_by AS by, generation FROM principals WHERE id = ${id}`))[0]!;
  // Her status did not change, so it says what it said: who admitted her.
  const admitted = (await standing(bo)).by;
  assert.deepEqual(await standing(ada), { status: 'active', role: 'owner', scope: null, by: admitted, generation: 0 });
  // Demoted behind the configuration's back, or kept to some projects, and bound already: an Owner of the whole instance again at the next sign-in.
  await amend(world, 'principals', sql`${principals.id} = ${ada}`, { role: 'member' });
  await owned.change(signin(github('gh-ada'), 'ada-web-2'));
  assert.equal(await who('ada-web-2', owned), `${ada} owner browser`);
  await amend(world, 'principals', sql`${principals.id} = ${ada}`, { scope: JSON.stringify({ projects: { only: [] }, environments: 'all' }) });
  await owned.change(signin(github('gh-ada'), 'ada-web-3'));
  assert.deepEqual([(await standing(ada)).scope, (await entries()).at(-1)!.detail.owner], [null, 'restored']);

  // Cy was removed before the configuration named him: let back in as an Owner, in the generation his removal moved on.
  // What he held before it stays dead.
  assert.equal(await who('cy-cli', owned), 'unauthenticated');
  assert.ok(!('refused' in await owned.change(signin(github('gh-cy', 'cy@acme.example'), 'cy-web'))));
  assert.deepEqual([await standing(cy), await who('cy-web', owned), await who('cy-cli', owned)], [{ status: 'active', role: 'owner', scope: null, by: 'system:vault', generation: 1 }, `${cy} owner browser`, 'unauthenticated']);
  assert.deepEqual(await checked(), []);
});

test('two sign-ins of one new account side by side bind it once: the second starts over, and finds it bound', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const [first, second] = await Promise.all(['ada-web', 'ada-web-2'].map((label) => prepare(world, OPERATIONS.signin(signin(github('gh-ada', 'ada@acme.example'), label), deciding))));
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.deepEqual([await commit(world, first), await commit(world, second)], [true, false]);
  assert.equal(await who('ada-web-2'), 'unauthenticated');
  assert.ok(!('refused' in await vault.change(signin(github('gh-ada', 'ada@acme.example'), 'ada-web-2'))));
  assert.deepEqual([(await accounts()).filter((row) => row.subject === 'gh-ada').length, await who('ada-web'), await who('ada-web-2')], [1, `${ada} member browser`, `${ada} member browser`]);
});

test('a sign-in decided before a removal, or before another account was bound, is not written: it starts over, and is refused', async () => {
  const deciding = { workloads: world.workloads, owners: world.owners };
  const prepared = async (account: Account, label: string) => {
    const made = await prepare(world, OPERATIONS.signin(signin(account, label), deciding));
    assert.ok(!('refused' in made));
    return made;
  };
  // Bo is removed between his sign-in's read and its write.
  const bos = await prepared(github('gh-bo'), 'bo-web-2');
  await amend(world, 'principals', sql`${principals.id} = ${bo}`, { status: 'removed', generation: 1 });
  assert.equal(await commit(world, bos), false);
  assert.deepEqual([await vault.change(signin(github('gh-bo'), 'bo-web-2')), await who('bo-web-2')], [{ refused: 'deactivated' }, 'unauthenticated']);
  // Two accounts that verified Ada's address, at once: one is hers, and the other is refused as any second one.
  const [first, second] = [await prepared(github('gh-ada', 'ada@acme.example'), 'ada-web'), await prepared({ ...github('okta-ada', 'ada@acme.example'), provider: 'okta' }, 'ada-web-2')];
  assert.deepEqual([await commit(world, first), await commit(world, second)], [true, false]);
  assert.deepEqual(await vault.change(signin({ ...github('okta-ada', 'ada@acme.example'), provider: 'okta' }, 'ada-web-2')), { refused: 'account_mismatch' });
  assert.deepEqual((await accounts()).filter((row) => row.principal === ada).map((row) => row.subject), ['gh-ada']);
});

test('a sign-in that is not what the contract says is a fault, before anything is read', async () => {
  const ok = signin(github('gh-ada', 'ada@acme.example'), 'ada-web');
  const token = tokenOf('ada-web').toString('hex');
  const wrong: Partial<Asked<'signin'>>[] = [
    { account: github('gh-ada', 'Ada@acme.example') }, { account: github('gh-ada', 'ada') }, { account: github('gh-ada', 'a b@acme.example') }, { account: github('gh-ada', 'ada@acme.example', 'ada@acme.example') },
    { account: github('gh-ada', ...Array.from({ length: 21 }, (_, i) => `a${i}@acme.example`)) }, { account: github('') }, { account: { ...github('gh-ada'), provider: 'GitHub' } }, { account: { ...github('gh-ada'), issuer: '' } },
    { account: { ...github('gh-ada'), emails: 'ada@acme.example' as never } }, { account: null as never },
    { session: { token: 'abc', minutes: 60, label: null } }, { session: { token: token.toUpperCase(), minutes: 60, label: null } }, { session: { token, minutes: 0, label: null } }, { session: { token, minutes: 7 * 24 * 60 + 1, label: null } },
    { session: { token, minutes: 1.5, label: null } }, { session: { token, minutes: 60, label: 7 as never } }, { replaces: 'abc' }, { replaces: token }, { ip: 7 as never },
  ];
  for (const more of wrong) await assert.rejects(vault.change({ ...ok, ...more }), TypeError, JSON.stringify(more).slice(0, 80));
  assert.equal(await who('ada-web'), 'unauthenticated');
  // The longest it may ask: a week.
  assert.ok(!('refused' in await vault.change({ ...ok, session: { token, minutes: 7 * 24 * 60, label: null } })));
});

test('a row written behind the vault is not a row that is absent: a sign-in that would read it is refused, whoever it would have let in', async () => {
  const before = (await entries()).length;
  const edit = (table: string, where: string) => world.owner.execute(sql`UPDATE ${sql.identifier(table)} SET mac = decode(repeat('00', 36), 'hex') WHERE ${sql.raw(where)}`);
  const okta = (subject: string, ...emails: string[]): Account => ({ ...github(subject, ...emails), provider: 'okta' });
  // Cy's row, removed and edited, and Dee's old account. Bo, whose account says who he is, signs in whatever else his provider lists.
  await edit('principals', `id = '${cy}'`);
  await edit('identities', "subject = 'gh-dee'");
  assert.ok(!('refused' in await vault.change(signin(github('gh-bo', 'cy@acme.example', 'dee@acme.example', 'bo@acme.example'), 'bo-web-2'))));
  // An account of Bo's marked revoked behind the vault, the edit that would take it out of a read of his live ones: no second account is bound for it.
  await world.owner.execute(sql`UPDATE identities SET revoked_at = now() WHERE subject = 'gh-bo'`);
  assert.deepEqual(await vault.change(signin(okta('okta-bo', 'bo@acme.example'), 'x-web')), { refused: 'tampered' });
  await world.owner.execute(sql`UPDATE identities SET revoked_at = NULL WHERE subject = 'gh-bo'`);
  // Bo's account, edited: it is not his to sign in with, nor free for another to be bound in its place, to him or through his address.
  await edit('identities', "subject = 'gh-bo'");
  assert.deepEqual(await vault.change(signin(github('gh-bo', 'bo@acme.example'), 'x-web')), { refused: 'tampered' });
  assert.deepEqual(await vault.change(signin(github('gh-bo'), 'x-web')), { refused: 'tampered' }, 'by the account alone, with no email that names him');
  assert.deepEqual(await vault.change(signin(okta('okta-bo', 'bo@acme.example'), 'x-web')), { refused: 'tampered' }, 'not the second account it would hide');
  assert.equal(await who('bo-web'), 'unauthenticated', 'nor do its sessions stand');
  // Cy's row is not passed over for the next email, which names Ada.
  assert.deepEqual(await vault.change(signin(github('gh-cy', 'cy@acme.example', 'ada@acme.example'), 'x-web')), { refused: 'tampered' });
  // Nor made anew for an Owner the configuration names, over the row that is there.
  assert.deepEqual(await owned.change(signin(github('gh-cy', 'cy@acme.example'), 'x-web')), { refused: 'tampered' });
  // Dee's row, edited: the account bound to her says nothing of who she is now.
  await edit('principals', `id = '${dee}'`);
  assert.deepEqual(await vault.change(signin(github('gh-dee'), 'x-web')), { refused: 'tampered' });
  // Ada, whom none of it touches, signs in.
  assert.ok(!('refused' in await vault.change(signin(github('gh-ada', 'ada@acme.example'), 'ada-web'))));
  assert.deepEqual([await who('x-web'), (await entries()).length], ['unauthenticated', before + 2]);
  assert.equal((await rowsOf(world.owner, sql`SELECT 1 FROM ${credentials} WHERE ${credentials.tokenHash} = ${tokenOf('x-web')}`)).length, 0);
  // The signer says which rows.
  assert.deepEqual(await checked(), ['row', 'row', 'row', 'row']);
});
