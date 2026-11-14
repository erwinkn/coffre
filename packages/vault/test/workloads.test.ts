// A CI run trades its platform's ID token for a five-minute token of its
// service (src/ops/workloads.ts, docs/design/0.16.md, "A workload signing
// in"): a change nobody asks, held to the service's own rows. Through the
// contract as the app calls it, with the signer reading what it wrote.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { CARRIED, canonicalClaims } from '@coffre/core/identity';
import type { Asked, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { bindings, credentials } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { prepare, written } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, binding, environment, grant, instance, principal, project, role, rows, tokenOf, write } from './world.ts';

const world = await openTestVault();
const vault = openLocalVault(world.db, world, { wake: world.wake, now: world.now });
after(() => world.close());

const DEPLOY = 'token:deploy';
const ORIGIN = 'https://secrets.acme.example';
const GITHUB = 'https://token.actions.githubusercontent.com';
const FETCHED = { issuer: GITHUB, jwksUri: `${GITHUB}/.well-known/jwks` };
const MAIN = { repository_owner_id: '9919', repository_id: '41532', ref: 'refs/heads/main', event_name: 'push' };
const KUBE = 'https://kubernetes.acme.example';
const from = { request: 'req-1', ip: '192.0.2.7' };

const seconds = (offset: number) => Math.floor(world.now() / 1000) + offset;
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
/** A run's ID token: the app verified its signature, so its bytes are any. Each one different, by its `jti`. */
let drawn = 0;
const idToken = (claims: Record<string, unknown> = {}, header: Record<string, unknown> = { alg: 'RS256', kid: 'k1' }) => {
  drawn += 1;
  return `${b64(header)}.${b64({ iss: GITHUB, sub: 'repo:acme/api:ref:refs/heads/main', aud: ORIGIN, iat: seconds(-10), exp: seconds(290), jti: `run-${drawn}`, run_id: '7001', sha: 'abc123', ...MAIN, ...claims })}.c2ln`;
};
/** An ES256 token signed by `key`, whose JWK says `kid`. */
const signed = (key: KeyObject, kid: string, claims: Record<string, unknown> = {}) => {
  drawn += 1;
  const input = `${b64({ alg: 'ES256', kid })}.${b64({ iss: KUBE, sub: 'system:serviceaccount:ci:runner', aud: ORIGIN, iat: seconds(-10), exp: seconds(290), jti: `pod-${drawn}`, ...claims })}`;
  return `${input}.${sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
};
const pair = () => generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwksOf = (...keys: { key: KeyObject; kid: string }[]) => JSON.stringify({ keys: keys.map(({ key, kid }) => ({ ...key.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' })) });
const carriedUri = (jwks: string) => `${CARRIED}${createHash('sha256').update(jwks).digest('hex')}`;

const exchange = (token: string, label: string, more: Partial<Asked<'token.exchange'>> = {}): Asked<'token.exchange'> =>
  ({ ...from, op: 'token.exchange', service: DEPLOY, token, under: FETCHED, publicUrl: ORIGIN, credential: tokenOf(label).toString('hex'), ...more });
const refusal = async (input: Asked<'token.exchange'>, through = vault) => {
  const done = await through.change(input);
  return 'refused' in done ? done.refused : 'made';
};
const shown = (label: string): Presented => ({ token: tokenOf(label).toString('hex'), proof: null, ...from });
/** Who a token is, and what it reaches, as the vault answers any request that shows it. */
const who = async (label: string) => {
  world.memory.callers.clear();
  const answer = await vault.caller(shown(label));
  return 'refused' in answer ? answer.refused : { principal: answer.principal, kind: answer.credential.kind, scope: answer.holds.credentialScope };
};
const entries = async () => (await rowsOf<{ kept: boolean; body: string; mac: Buffer }>(world.owner, sql`SELECT kept, body, mac FROM log_pending ORDER BY id`)).map((row) => ({ kept: row.kept, ...entryOf(world.keys, row)! }));
const issued = () => rowsOf<{ principal: string; kind: string; created_by: string; scope: string | null; run: string | null; label: string | null; expires_at: Date; generation: number }>(
  world.owner, sql`SELECT principal, kind, created_by, scope, run, label, expires_at, generation FROM ${credentials} ORDER BY created_at, id`);
const spentCount = async () => Number((await rowsOf<{ n: string }>(world.owner, sql`SELECT count(*) AS n FROM spent_id_tokens`))[0]!.n);
/** When each binding was last used, by id. */
const lastUsed = async () => Object.fromEntries((await rowsOf<{ id: string; last_used_at: Date | string | null }>(world.owner, sql`SELECT id, last_used_at FROM bindings`)).map((row) => [row.id, row.last_used_at === null ? null : new Date(row.last_used_at).getTime()]));
const zero = (table: string, where: string) => world.owner.execute(sql`UPDATE ${sql.identifier(table)} SET mac = decode(repeat('00', 36), 'hex') WHERE ${sql.raw(where)}`);

let signer: Signer;
/** Everything the vault told the signer of, signed, and the rows held to its mirror: what it found. */
async function checked() {
  for (const hash of world.woken.splice(0)) await signer.wake(hash);
  await signer.run(true);
  return (await signer.take()).map((finding) => finding.found);
}

const market = project('market');
const prod = environment(market, 'prod');
const VIEWER = JSON.stringify([{ projectId: market.id, environmentId: null, role: 'viewer' }]);
/** `main`, made in March; `any`, made in May, for every branch; `other`, of another repository. */
let main: ReturnType<typeof binding>;
let any: ReturnType<typeof binding>;
let other: ReturnType<typeof binding>;

/** `deploy`, a service that holds `developer` on market and has three GitHub bindings, each reaching less. */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  signer = await Signer.open({ db: world.db, keys: world.keys, now: world.now, store: memoryStore(), keepUsesDays: 90 });
  main = binding(DEPLOY, { claims: canonicalClaims(MAIN), scope: VIEWER, label: 'main', createdAt: new Date(Date.UTC(2026, 2, 1)) });
  any = binding(DEPLOY, { claims: canonicalClaims({ repository_owner_id: '9919', repository_id: '41532' }), scope: '[]', label: 'any branch', createdAt: new Date(Date.UTC(2026, 4, 1)) });
  other = binding(DEPLOY, { claims: canonicalClaims({ ...MAIN, repository_id: '1' }), scope: VIEWER, createdAt: new Date(Date.UTC(2026, 1, 1)) });
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.write']), role(false, 'viewer', ['secret.read'])),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('principals', principal(DEPLOY), principal('token:gone', { status: 'removed', generation: 1 })),
    ...rows('grants', grant(DEPLOY, 'developer', { project: market })),
    ...rows('bindings', main, any, other),
  );
  assert.deepEqual(await checked(), []);
});

test("a CI run's token is traded at the oldest binding whose claims it carries, for a service token of five minutes that reaches what that binding does", async () => {
  const token = idToken();
  const done = await vault.change(exchange(token, 'run-1'));
  assert.ok(!('refused' in done), JSON.stringify(done));
  const expiresAt = new Date(world.now() + 5 * 60_000).toISOString();
  assert.deepEqual({ ...done.answer, credential: undefined }, { principal: DEPLOY, credential: undefined, expiresAt, binding: main.id });
  // Its row: issued by March's binding, under its MAC, with the binding's scope on its own row and the run it was made for.
  const [row] = await issued();
  assert.deepEqual({ ...row, expires_at: new Date(row!.expires_at).toISOString(), run: JSON.parse(row!.run!) }, {
    principal: DEPLOY, kind: 'service', created_by: `binding:${main.id}`, scope: VIEWER, label: 'main', expires_at: expiresAt, generation: 0,
    run: { sub: 'repo:acme/api:ref:refs/heads/main', jti: `run-${drawn}`, event_name: 'push', ref: 'refs/heads/main', sha: 'abc123', repository_id: '41532', run_id: '7001' },
  });
  // It stands as the service, within its binding's scope, though the service holds more.
  assert.deepEqual(await who('run-1'), { principal: DEPLOY, kind: 'service', scope: JSON.parse(VIEWER) });
  // One entry, which ages out: the run's claims, and the proof by its hash, never the token.
  const [entry] = (await entries()).filter((one) => one.action === 'token.exchange');
  assert.equal(entry!.kept, false);
  assert.deepEqual([entry!.actor, entry!.credential, entry!.objects], [DEPLOY, done.answer.credential, [`principal:${DEPLOY}`, `credential:${done.answer.credential}`, `binding:${main.id}`]]);
  const signedPart = token.slice(0, token.lastIndexOf('.'));
  assert.deepEqual({ ...entry!.detail, run: undefined }, { kind: 'service', credential: done.answer.credential, binding: main.id, generation: 0, issuer: GITHUB, expiresAt, run: undefined, proof: createHash('sha256').update(signedPart).digest('hex') });
  assert.ok(!JSON.stringify(entry).includes(token.split('.')[1]!), 'no token in the entry');
  // March's binding was used, at the entry's date; the others were not.
  assert.deepEqual(await lastUsed(), { [main.id]: entry!.at, [any.id]: null, [other.id]: null });
  assert.equal(await spentCount(), 1);
  // Of another branch, May's binding, the only one that takes it, which reaches nothing.
  assert.equal(await refusal(exchange(idToken({ ref: 'refs/heads/feature', sub: 'repo:acme/api:ref:refs/heads/feature' }), 'run-2')), 'made');
  assert.deepEqual(await who('run-2'), { principal: DEPLOY, kind: 'service', scope: [] });
  // Five minutes on, it is gone.
  world.tick(5 * 60_000);
  assert.equal(await who('run-1'), 'unauthenticated');
  assert.deepEqual(await checked(), []);
});

test('a proof is spent once: the same token again, for another credential, is refused replayed and writes nothing', async () => {
  const token = idToken();
  assert.equal(await refusal(exchange(token, 'run-1')), 'made');
  const before = [(await entries()).length, (await issued()).length];
  const used = await lastUsed();
  world.tick(1000);
  assert.equal(await refusal(exchange(token, 'run-2')), 'replayed');
  assert.deepEqual(await lastUsed(), used, 'a replay is no use');
  assert.deepEqual([(await entries()).length, (await issued()).length, await spentCount()], [...before, 1]);
  assert.equal(await who('run-2'), 'unauthenticated');
  assert.deepEqual(await checked(), []);
});

test('two exchanges of one token at once: the first write spends it, and the second is refused replayed', async () => {
  const token = idToken();
  const deciding = { workloads: world.workloads, owners: [] };
  const [first, second] = await Promise.all([prepare(world, OPERATIONS['token.exchange'](exchange(token, 'run-1'), deciding)), prepare(world, OPERATIONS['token.exchange'](exchange(token, 'run-2'), deciding))]);
  assert.ok(!('refused' in first) && !('refused' in second));
  assert.deepEqual([await written(world, first), await written(world, second)], ['made', 'spent']);
  assert.deepEqual([(await issued()).length, await spentCount()], [1, 1]);
  assert.deepEqual(await checked(), []);
});

test('a binding revoked, or the service removed, between the read and the write: the write is not made, and the exchange read again finds no binding', async () => {
  const deciding = { workloads: world.workloads, owners: [] };
  const token = idToken();
  const ready = await prepare(world, OPERATIONS['token.exchange'](exchange(token, 'run-1'), deciding));
  assert.ok(!('refused' in ready));
  await amend(world, 'bindings', sql`${bindings.id} = ${main.id}`, { revokedAt: new Date(world.now()), revokedBy: 'user:root@acme.example' });
  assert.equal(await written(world, ready), 'moved');
  assert.deepEqual([(await issued()).length, await spentCount(), (await lastUsed())[main.id]], [0, 0, null], 'nor the proof spent, nor the binding used');
  // Started over, May's binding answers it now, with the scope it was given.
  assert.equal(await refusal(exchange(token, 'run-1')), 'made');
  assert.deepEqual(await who('run-1'), { principal: DEPLOY, kind: 'service', scope: [] });

  const again = await prepare(world, OPERATIONS['token.exchange'](exchange(idToken(), 'run-2'), deciding));
  assert.ok(!('refused' in again));
  await amend(world, 'principals', sql`id = ${DEPLOY}`, { status: 'removed', generation: 1 });
  assert.equal(await written(world, again), 'moved');
  assert.equal(await refusal(exchange(idToken(), 'run-2')), 'no_match');
  assert.deepEqual(await checked(), []);
});

test("a token is refused for what it is: not this instance's, past its time, unreadable, or of claims no live binding of the service takes", async () => {
  const cases: [string, Asked<'token.exchange'>][] = [
    ['audience', exchange(idToken({ aud: 'https://elsewhere.example' }), 'x')],
    ['audience', exchange(idToken({ aud: [ORIGIN, 'https://elsewhere.example'] }), 'x')],
    ['expired', exchange(idToken({ iat: seconds(-400), exp: seconds(-31) }), 'x')],
    ['too_old', exchange(idToken({ iat: seconds(-3700), exp: seconds(300) }), 'x')],
    ['too_old', exchange(idToken({ nbf: seconds(120) }), 'x')],
    ['malformed', exchange('not.a.token', 'x')],
    ['malformed', exchange(idToken({}, { alg: 'RS256', kid: 'k1', crit: ['b64'], b64: false }), 'x')],
    ['no_match', exchange(idToken({ repository_id: '2' }), 'x')],
    // Another issuer than the token's, or other keys than the bindings': no binding was verified under them.
    ['no_match', exchange(idToken({ iss: 'https://gitlab.com' }), 'x', { under: { issuer: 'https://gitlab.com', jwksUri: 'https://gitlab.com/oauth/discovery/keys' } })],
    ['no_match', exchange(idToken(), 'x', { under: { issuer: GITHUB, jwksUri: 'https://elsewhere.example/jwks' } })],
    ['no_match', exchange(idToken({ iss: 'https://gitlab.com' }), 'x')],
    // No such service, one removed, or a person.
    ['no_match', exchange(idToken(), 'x', { service: 'token:nobody' })],
    ['no_match', exchange(idToken(), 'x', { service: 'token:gone' })],
    ['no_match', exchange(idToken(), 'x', { service: 'user:ada@acme.example' })],
  ];
  for (const [word, input] of cases) assert.equal(await refusal(input), word, `${word}: ${input.token.slice(0, 60)} ${input.service}`);
  // Nothing written, nothing spent, nothing logged, no binding used.
  assert.deepEqual([(await issued()).length, await spentCount(), (await entries()).filter((entry) => entry.action === 'token.exchange').length], [0, 0, 0]);
  assert.deepEqual(Object.values(await lastUsed()), [null, null, null]);
  // Within the clock's 30 seconds either way.
  assert.equal(await refusal(exchange(idToken({ iat: seconds(-300), exp: seconds(-29) }), 'y')), 'made');
});

test('a binding with a policy makes sessions, not CI tokens; one of an older generation, or revoked, takes nothing; nor does a deployment that takes no workloads, or only key-bound ones', async () => {
  await amend(world, 'bindings', sql`${bindings.id} IN (${main.id}, ${any.id})`, { policy: '{}' });
  assert.equal(await refusal(exchange(idToken(), 'x')), 'no_match');
  await amend(world, 'bindings', sql`${bindings.id} IN (${main.id}, ${any.id})`, { policy: null });
  // Removed and let back in: what it was bound to before reaches nothing.
  await amend(world, 'principals', sql`id = ${DEPLOY}`, { generation: 1 });
  assert.equal(await refusal(exchange(idToken(), 'x')), 'no_match');
  const next = binding(DEPLOY, { generation: 1, claims: canonicalClaims(MAIN), scope: '[]' });
  await write(world, ...rows('bindings', next));
  assert.equal(await refusal(exchange(idToken(), 'y')), 'made');
  await amend(world, 'bindings', sql`${bindings.id} = ${next.id}`, { revokedAt: new Date(world.now()), revokedBy: 'user:root@acme.example' });
  assert.equal(await refusal(exchange(idToken(), 'z')), 'no_match');
  await amend(world, 'principals', sql`id = ${DEPLOY}`, { generation: 0, status: 'removed' });
  assert.equal(await refusal(exchange(idToken(), 'z')), 'no_match', 'removed, in the generation its bindings were made in');
  await amend(world, 'principals', sql`id = ${DEPLOY}`, { status: 'active' });
  for (const workloads of [null, { noReads: false, useOnly: true }]) {
    const other = openLocalVault(world.db, { ...world, workloads }, { wake: world.wake, now: world.now });
    assert.equal(await refusal(exchange(idToken(), 'w'), other), 'no_match', JSON.stringify(workloads));
  }
  assert.equal(await refusal(exchange(idToken(), 'w')), 'made');
  assert.deepEqual(await checked(), []);
});

test('more bindings on an issuer than a service may hold: none of them answers, as in 0.14', async () => {
  const more = Array.from({ length: 14 }, (_, n) => binding(DEPLOY, { claims: canonicalClaims({ repository_id: String(100 + n) }), scope: '[]', createdAt: new Date(Date.UTC(2026, 5, 1, n)) }));
  await write(world, ...rows('bindings', ...more));
  assert.equal(await refusal(exchange(idToken(), 'x')), 'no_match');
  await amend(world, 'bindings', sql`${bindings.id} = ${more[0]!.id}`, { revokedAt: new Date(world.now()), revokedBy: 'user:root@acme.example' });
  assert.equal(await refusal(exchange(idToken(), 'x')), 'made');
  // Of an older generation, they count for nothing, however many: the read takes the service's generation alone.
  await write(world, ...rows('bindings', binding(DEPLOY, { claims: canonicalClaims({ repository_id: '99' }), scope: '[]', createdAt: new Date(Date.UTC(2026, 6, 1)) })));
  await amend(world, 'principals', sql`id = ${DEPLOY}`, { generation: 1 });
  await write(world, ...rows('bindings', binding(DEPLOY, { generation: 1, claims: canonicalClaims(MAIN), scope: '[]', createdAt: new Date(Date.UTC(2026, 9, 1)) })));
  assert.equal(await refusal(exchange(idToken(), 'y')), 'made');
  assert.deepEqual(await checked(), []);
});

test('a row written behind the vault is not a row that is absent: a binding or the service that is not the vault\'s refuses the exchange, tampered', async () => {
  const macs = new Map((await rowsOf<{ id: string; mac: Buffer }>(world.owner, sql`SELECT id, mac FROM bindings`)).map((row) => [row.id, row.mac]));
  const restore = (id: string) => world.owner.execute(sql`UPDATE bindings SET mac = ${macs.get(id)!} WHERE id = ${id}`);
  // `other`, the oldest, takes no run of this repository: had it been read as absent, it could have been the one that matched.
  await zero('bindings', `id = '${other.id}'`);
  assert.equal(await refusal(exchange(idToken(), 'x')), 'tampered');
  await restore(other.id);
  // March's binding: May's would answer in its place, with another scope.
  await zero('bindings', `id = '${main.id}'`);
  assert.equal(await refusal(exchange(idToken(), 'x')), 'tampered');
  await restore(main.id);
  assert.equal(await refusal(exchange(idToken(), 'x')), 'made', 'put back, it is the vault\'s again');
  // A binding written behind the vault to say it has a policy, which takes it out of the exchange's matches, is still read.
  await world.owner.execute(sql`UPDATE bindings SET policy = '{}' WHERE id = ${main.id}`);
  assert.equal(await refusal(exchange(idToken(), 'x')), 'tampered');
  await world.owner.execute(sql`UPDATE bindings SET policy = NULL WHERE id = ${main.id}`);
  // The service's row, and the instance's.
  const [{ mac }] = await rowsOf<{ mac: Buffer }>(world.owner, sql`SELECT mac FROM principals WHERE id = ${DEPLOY}`) as [{ mac: Buffer }];
  await zero('principals', `id = '${DEPLOY}'`);
  assert.equal(await refusal(exchange(idToken(), 'x')), 'tampered');
  await world.owner.execute(sql`UPDATE principals SET mac = ${mac} WHERE id = ${DEPLOY}`);
  await zero('policy', 'only_row');
  assert.equal(await refusal(exchange(idToken(), 'x')), 'tampered');
  // A database the vault has not adopted: no policy row.
  await world.owner.execute(sql`DELETE FROM policy`);
  assert.equal(await refusal(exchange(idToken(), 'x')), 'adopting');
  assert.deepEqual([(await issued()).length, await spentCount()], [1, 1]);
  assert.deepEqual(await checked(), ['row']);
});

test('keys a binding carries: the vault verifies the signature itself, under the keys on its sealed row, and tells a key it lacks from a signature that fails', async () => {
  const [known, stranger] = [pair(), pair()];
  const jwks = jwksOf({ key: known.publicKey, kid: 'k1' });
  const kube = binding(DEPLOY, { profile: 'custom', issuer: KUBE, jwksUri: carriedUri(jwks), jwks, claims: canonicalClaims({ sub: 'system:serviceaccount:ci:runner' }), scope: VIEWER });
  await write(world, ...rows('bindings', kube));
  const under = { issuer: KUBE, jwksUri: kube.jwksUri };
  assert.equal(await refusal(exchange(signed(known.privateKey, 'k1'), 'k-1', { under })), 'made');
  assert.deepEqual(await who('k-1'), { principal: DEPLOY, kind: 'service', scope: JSON.parse(VIEWER) });
  // A key the binding's keys lack: the word that raises the app's alert.
  assert.equal(await refusal(exchange(signed(stranger.privateKey, 'k2'), 'k-2', { under })), 'unknown_signer');
  // A signature that does not verify under the key it names: malformed, which raises nothing.
  assert.equal(await refusal(exchange(signed(stranger.privateKey, 'k1'), 'k-2', { under })), 'malformed');
  const forged = signed(known.privateKey, 'k1', { sub: 'system:serviceaccount:ci:other' });
  const [head, , signature] = signed(known.privateKey, 'k1').split('.');
  assert.equal(await refusal(exchange(`${head}.${forged.split('.')[1]}.${signature}`, 'k-2', { under })), 'malformed');
  // Keys an hour's lifetime at most, with no issuer to ask whether a token still stands.
  assert.equal(await refusal(exchange(signed(known.privateKey, 'k1', { exp: seconds(3700) }), 'k-2', { under })), 'too_old');
  // The app's word that it verified a token under fetched keys takes no binding that carries its own; nor carried keys a binding of fetched ones.
  assert.equal(await refusal(exchange(signed(stranger.privateKey, 'k2'), 'k-2', { under: { issuer: KUBE, jwksUri: `${KUBE}/openid/v1/jwks` } })), 'no_match');
  assert.equal(await refusal(exchange(idToken(), 'k-2', { under: { issuer: GITHUB, jwksUri: carriedUri(jwks) } })), 'no_match');
  // Two bindings under one address with different keys, which no maker writes: a row that carries other keys refuses the token, whichever matches.
  const twin = pair();
  const odd = jwksOf({ key: twin.publicKey, kid: 'k1' });
  await write(world, ...rows('bindings', binding(DEPLOY, { profile: 'custom', issuer: KUBE, jwksUri: kube.jwksUri, jwks: odd, claims: canonicalClaims({ sub: 'system:serviceaccount:ci:other' }), scope: '[]' })));
  assert.equal(await refusal(exchange(signed(known.privateKey, 'k1'), 'k-2', { under })), 'malformed');
  assert.equal(await refusal(exchange(signed(twin.privateKey, 'k1', { sub: 'system:serviceaccount:ci:other' }), 'k-2', { under })), 'malformed');
  // Keys no binding carries.
  const moved = pair();
  const jwks2 = jwksOf({ key: moved.publicKey, kid: 'k3' });
  assert.equal(await refusal(exchange(signed(moved.privateKey, 'k3'), 'k-3', { under: { issuer: KUBE, jwksUri: carriedUri(jwks2) } })), 'no_match');
  assert.deepEqual(await checked(), []);
});

test('what the contract takes is checked before anything is read: a fault, never a refusal', () => {
  const deciding = { workloads: world.workloads, owners: [] };
  const ok = exchange(idToken(), 'x');
  const wrong: Partial<Record<keyof Asked<'token.exchange'>, unknown>>[] = [
    { service: 7 }, { service: 'x'.repeat(257) }, { service: 'token:\ud800' },
    { token: null }, { token: 42 },
    { under: null }, { under: { issuer: GITHUB } }, { under: { issuer: 7, jwksUri: FETCHED.jwksUri } }, { under: { ...FETCHED, jwksUri: 'x'.repeat(2049) } }, { under: { ...FETCHED, issuer: 'a\0b' } },
    { publicUrl: null }, { publicUrl: '\udfff' },
    { credential: 'ABC' }, { credential: tokenOf('x').toString('hex').toUpperCase() }, { credential: null },
    { request: 7 }, { ip: '\ud800' },
  ];
  for (const more of wrong) assert.throws(() => OPERATIONS['token.exchange']({ ...ok, ...more } as never, deciding), TypeError, JSON.stringify(more).slice(0, 80));
});
