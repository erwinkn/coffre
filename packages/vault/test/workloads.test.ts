// A CI run trades its platform's ID token for a five-minute token of its
// service (src/ops/workloads.ts, docs/design/0.16.md, "A workload signing
// in"): a change nobody asks, held to the service's own rows. Through the
// contract as the app calls it, with the signer reading what it wrote.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';
import { setTimeout as wait } from 'node:timers/promises';

import { CARRIED, canonicalClaims } from '@coffre/core/identity';
import type { Asked, Presented } from '@coffre/core/vault';
import { rowsOf } from '@coffre/db/dialect';
import { bindings, credentials } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { CHANGE_LOCK, prepare, WRITE_MS, written } from '../src/change.ts';
import { entryOf } from '../src/entry.ts';
import { openLocalVault } from '../src/local.ts';
import { OPERATIONS } from '../src/ops/index.ts';
import { Signer } from '../src/signer.ts';
import { emptyDatabase, memoryStore, openTestVault } from './database.ts';
import { amend, binding, environment, grant, instance, principal, project, role, rows, session as sessionRow, tokenOf, write } from './world.ts';

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

// A workload trades a proof for a session bound to its key (`workload.signin`), and renews it (`workload.renew`).

const KEY = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
const OTHER_KEY = 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U';
const POD = { iss: KUBE, sub: 'system:serviceaccount:ci:runner' };
const KUBE_FETCHED = { issuer: KUBE, jwksUri: `${KUBE}/openid/v1/jwks` };
/** A pod's ID token: the app verified its signature, so its bytes are any. */
const podToken = (claims: Record<string, unknown> = {}) => idToken({ ...POD, ...claims });
const AWS_ANSWER = { account: '123456789012', arn: 'arn:aws:sts::123456789012:assumed-role/deployer/i-0abc', userId: 'AROAEXAMPLEROLEID01:i-0abc' };

const signin = (proof: Asked<'workload.signin'>['proof'], label: string, more: Partial<Asked<'workload.signin'>> = {}): Asked<'workload.signin'> =>
  ({ ...from, op: 'workload.signin', service: DEPLOY, proof, key: KEY, publicUrl: ORIGIN, credential: tokenOf(label).toString('hex'), ...more });
const oidc = (token: string, under = KUBE_FETCHED) => ({ oidc: { token, under } });
const renew = (label: string, proof: string | null = KEY, more: Partial<Presented> = {}): Asked<'workload.renew'> => ({ ...from, op: 'workload.renew', token: tokenOf(label).toString('hex'), proof, ...more });
const outcome = async (input: Asked<'workload.signin'> | Asked<'workload.renew'>, through = vault) => {
  const done = await through.change(input);
  return 'refused' in done ? done.refused : 'made';
};
/** Who a session is, with its key's proof or another's. */
const session = async (label: string, proof: string | null = KEY) => {
  world.memory.callers.clear();
  const answer = await vault.caller({ ...shown(label), proof });
  return 'refused' in answer ? answer.refused : { principal: answer.principal, kind: answer.credential.kind, scope: answer.holds.credentialScope };
};
const sessions = () => rowsOf<{ id: string; kind: string; created_by: string; scope: string | null; places: string | null; jkt: string | null; expires_at: Date | string; not_after: Date | string | null; label: string | null }>(
  world.owner, sql`SELECT id, kind, created_by, scope, places, jkt, expires_at, not_after, label FROM ${credentials} WHERE kind = 'workload' ORDER BY created_at, id`);
const iso = (value: Date | string | null) => (value === null ? null : new Date(value).toISOString());

/** `pods`, made in March, and `any pod`, made in May, take a pod's token for a session; `aws` takes STS's answer. Market has prod, staging, an archived environment and Ada's personal config. */
async function workloadWorld() {
  const staging = environment(market, 'staging');
  const old = environment(market, 'old', { archivedAt: new Date(Date.UTC(2026, 0, 1)) });
  const mine = environment(market, 'prod-ada', { owner: 'user:ada@acme.example', parentId: prod.id });
  const shop = project('shop');
  const pods = binding(DEPLOY, { profile: 'custom', issuer: KUBE, jwksUri: KUBE_FETCHED.jwksUri, claims: canonicalClaims({ sub: POD.sub }), scope: VIEWER, policy: '{}', label: 'pods', createdAt: new Date(Date.UTC(2026, 2, 1)) });
  const anyPod = binding(DEPLOY, { profile: 'custom', issuer: KUBE, jwksUri: KUBE_FETCHED.jwksUri, claims: '{}', scope: '[]', policy: '{}', label: 'any pod', createdAt: new Date(Date.UTC(2026, 4, 1)) });
  const aws = binding(DEPLOY, { profile: 'aws', issuer: 'urn:coffre:aws', jwksUri: 'urn:coffre:aws', claims: canonicalClaims({ account: AWS_ANSWER.account, role_id: 'AROAEXAMPLEROLEID01' }), scope: JSON.stringify([{ projectId: market.id, environmentId: prod.id, role: 'viewer' }]), policy: '{"sessionHours":2}', label: 'aws' });
  await write(world, ...rows('projects', shop), ...rows('environments', staging, old, mine, environment(shop, 'prod')), ...rows('bindings', pods, anyPod, aws));
  return { staging, pods, anyPod, aws };
}

test("a workload's ID token is traded at the oldest binding with a policy that takes it, for a session bound to its key, with its hard end and the places it reaches", async () => {
  const { staging, pods, anyPod } = await workloadWorld();
  const token = podToken();
  const done = await vault.change(signin(oidc(token), 's-1'));
  assert.ok(!('refused' in done), JSON.stringify(done));
  // A token that does not name the key ends the session at its own `exp`, sooner than an hour.
  const notAfter = new Date(seconds(290) * 1000).toISOString();
  assert.deepEqual({ ...done.answer, credential: undefined }, { principal: DEPLOY, credential: undefined, expiresAt: notAfter, notAfter, places: [prod.id, staging.id], binding: pods.id });
  const [row] = await sessions();
  assert.deepEqual({ ...row, id: undefined, expires_at: iso(row!.expires_at), not_after: iso(row!.not_after), places: JSON.parse(row!.places!) }, {
    id: undefined, kind: 'workload', created_by: `binding:${pods.id}`, scope: VIEWER, jkt: KEY, label: 'pods', expires_at: notAfter, not_after: notAfter,
    places: [{ environmentId: prod.id, personal: false }, { environmentId: staging.id, personal: false }],
  });
  // It stands with its key's proof alone, as the service, within its binding's scope.
  assert.deepEqual(await session('s-1'), { principal: DEPLOY, kind: 'workload', scope: JSON.parse(VIEWER) });
  assert.equal(await session('s-1', null), 'unauthenticated');
  assert.equal(await session('s-1', OTHER_KEY), 'unauthenticated');
  // One entry, which ages out, as 0.14's `token.exchange` of kind `workload`; the binding used at its date.
  const [entry] = (await entries()).filter((one) => one.action === 'token.exchange');
  assert.equal(entry!.kept, false);
  const signedPart = token.slice(0, token.lastIndexOf('.'));
  assert.deepEqual({ ...entry!.detail, run: undefined }, {
    kind: 'workload', credential: done.answer.credential, binding: pods.id, generation: 0, issuer: KUBE, proved: 'oidc', key: KEY, expiresAt: notAfter, notAfter, run: undefined,
    proof: createHash('sha256').update(signedPart).digest('hex'),
  });
  assert.deepEqual([entry!.actor, entry!.objects], [DEPLOY, [`principal:${DEPLOY}`, `credential:${done.answer.credential}`, `binding:${pods.id}`]]);
  assert.equal((await lastUsed())[pods.id], entry!.at);
  assert.equal((await lastUsed())[anyPod.id], null);
  // The token is spent: again, for another session, replayed, and nothing written.
  assert.equal(await spentCount(), 1);
  world.tick(1000);
  assert.equal(await outcome(signin(oidc(token), 's-2')), 'replayed');
  assert.deepEqual([(await sessions()).length, await spentCount()], [1, 1]);
  // Another pod: May's binding, which reaches nothing and lists no place.
  const other = await vault.change(signin(oidc(podToken({ sub: 'system:serviceaccount:ci:other' })), 's-3'));
  assert.ok(!('refused' in other));
  assert.deepEqual([other.answer.binding, other.answer.places], [anyPod.id, []]);
  assert.deepEqual(await session('s-3'), { principal: DEPLOY, kind: 'workload', scope: [] });
  // A CI run's exchange takes no binding with a policy, and a session no binding without one.
  assert.equal(await refusal(exchange(podToken(), 'r-1', { under: KUBE_FETCHED })), 'no_match');
  await amend(world, 'bindings', sql`${bindings.id} IN (${pods.id}, ${anyPod.id})`, { policy: null });
  assert.equal(await outcome(signin(oidc(podToken()), 's-4')), 'no_match');
  await amend(world, 'bindings', sql`${bindings.id} IN (${pods.id}, ${anyPod.id})`, { policy: '{}' });
  // A token past its `exp` within the clock's tolerance reads, but its session would end before it began.
  assert.equal(await outcome(signin(oidc(podToken({ exp: seconds(-10) })), 's-5')), 'expired');
  // Market archived: the session reaches no place it lists.
  await amend(world, 'projects', sql`id = ${market.id}`, { archivedAt: new Date(world.now()) });
  const archived = await vault.change(signin(oidc(podToken()), 's-6'));
  assert.ok(!('refused' in archived));
  assert.deepEqual(archived.answer.places, []);
  assert.deepEqual(await checked(), []);
});

test("a token that names the session's key is not spent, and the binding's hours end the session; one for another key is refused audience", async () => {
  // GitHub's tokens name the key: their audience is this instance's URL with its thumbprint.
  const keyed = binding(DEPLOY, { claims: canonicalClaims(MAIN), scope: VIEWER, policy: '{"keyAudience":true,"sessionHours":3}', label: 'keyed', createdAt: new Date(Date.UTC(2026, 0, 1)) });
  await write(world, ...rows('bindings', keyed));
  const token = idToken({ aud: `${ORIGIN}#jkt=${KEY}` });
  const first = await vault.change(signin(oidc(token, FETCHED), 'g-1'));
  assert.ok(!('refused' in first), JSON.stringify(first));
  assert.deepEqual([first.answer.binding, first.answer.expiresAt, first.answer.notAfter], [keyed.id, new Date(world.now() + 3_600_000).toISOString(), new Date(world.now() + 3 * 3_600_000).toISOString()]);
  // The same token again makes another session of the same key: it works for no other.
  assert.equal(await outcome(signin(oidc(token, FETCHED), 'g-2')), 'made');
  assert.equal(await spentCount(), 0);
  assert.equal(await outcome(signin(oidc(token, FETCHED), 'g-3', { key: OTHER_KEY })), 'audience');
  assert.equal(await outcome(signin(oidc(idToken({ aud: ORIGIN }), FETCHED), 'g-3')), 'audience');
  // `?jkt=`, for a platform that refuses a `#` in an audience.
  assert.equal(await outcome(signin(oidc(idToken({ aud: `${ORIGIN}?jkt=${KEY}` }), FETCHED), 'g-4')), 'made');
  assert.deepEqual(await checked(), []);
});

test("STS's answer is taken at the oldest aws binding of its role: nothing is spent, the binding's hours end the session, and a root's or a contradictory answer is refused", async () => {
  const { aws } = await workloadWorld();
  const done = await vault.change(signin({ aws: AWS_ANSWER }, 'a-1'));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.deepEqual({ ...done.answer, credential: undefined }, {
    principal: DEPLOY, credential: undefined, binding: aws.id, places: [prod.id],
    expiresAt: new Date(world.now() + 3_600_000).toISOString(), notAfter: new Date(world.now() + 2 * 3_600_000).toISOString(),
  });
  assert.equal(await outcome(signin({ aws: AWS_ANSWER }, 'a-2')), 'made', 'nothing spent');
  assert.equal(await spentCount(), 0);
  const [entry] = (await entries()).filter((one) => one.action === 'token.exchange');
  assert.deepEqual([entry!.detail.proved, entry!.detail.proof, entry!.detail.issuer], ['aws', null, 'urn:coffre:aws']);
  const cases: [string, typeof AWS_ANSWER][] = [
    ['no_match', { ...AWS_ANSWER, arn: 'arn:aws:iam::123456789012:root', userId: '123456789012' }],
    ['no_match', { ...AWS_ANSWER, arn: 'arn:aws:iam::123456789012:user/ada', userId: 'AIDAEXAMPLEUSERID01' }],
    ['no_match', { ...AWS_ANSWER, userId: 'AROAANOTHERROLEID01:i-0abc' }],
    ['malformed', { ...AWS_ANSWER, account: '210987654321' }],
    ['malformed', { ...AWS_ANSWER, userId: 'AROAEXAMPLEROLEID01:i-0def' }],
  ];
  for (const [word, answer] of cases) assert.equal(await outcome(signin({ aws: answer }, 'a-3')), word, JSON.stringify(answer));
  // An ID token takes no aws binding, nor STS's answer any other.
  await amend(world, 'bindings', sql`${bindings.id} = ${aws.id}`, { revokedAt: new Date(world.now()), revokedBy: 'user:root@acme.example' });
  assert.equal(await outcome(signin({ aws: AWS_ANSWER }, 'a-3')), 'no_match');
  assert.deepEqual(await checked(), []);
});

test("a binding's policy refuses the session: outside its sources, or listing reads where the deployment lets none; and a freeze of the service, the binding or every workload refuses it, frozen", async () => {
  const { pods, anyPod } = await workloadWorld();
  await amend(world, 'bindings', sql`${bindings.id} = ${anyPod.id}`, { revokedAt: new Date(world.now()), revokedBy: 'user:root@acme.example' });
  await amend(world, 'bindings', sql`${bindings.id} = ${pods.id}`, { policy: '{"sources":["10.0.0.0/8"]}' });
  assert.equal(await outcome(signin(oidc(podToken()), 'p-1')), 'no_match');
  assert.equal(await outcome(signin(oidc(podToken()), 'p-1', { ip: null })), 'no_match');
  assert.equal(await outcome(signin(oidc(podToken()), 'p-1', { ip: '10.1.2.3' })), 'made');
  await amend(world, 'bindings', sql`${bindings.id} = ${pods.id}`, { policy: JSON.stringify({ reads: { [prod.id]: { keys: '*' } } }) });
  const strict = openLocalVault(world.db, { ...world, workloads: { noReads: true, useOnly: false } }, { wake: world.wake, now: world.now });
  assert.equal(await outcome(signin(oidc(podToken()), 'p-2'), strict), 'no_match');
  assert.equal(await outcome(signin(oidc(podToken()), 'p-2')), 'made');
  // A deployment that takes no workloads makes no session; one that takes key-bound sessions alone makes them.
  const none = openLocalVault(world.db, { ...world, workloads: null }, { wake: world.wake, now: world.now });
  assert.equal(await outcome(signin(oidc(podToken()), 'p-3'), none), 'no_match');
  const useOnly = openLocalVault(world.db, { ...world, workloads: { noReads: false, useOnly: true } }, { wake: world.wake, now: world.now });
  assert.equal(await outcome(signin(oidc(podToken()), 'p-3'), useOnly), 'made');
  const frozen = new Date(world.now());
  for (const [table, where] of [['bindings', sql`${bindings.id} = ${pods.id}`], ['principals', sql`id = ${DEPLOY}`], ['policy', sql`only_row`]] as const) {
    await amend(world, table, where, table === 'policy' ? { workloadsFrozenAt: frozen } : { frozenAt: frozen });
    assert.equal(await outcome(signin(oidc(podToken()), 'p-4')), 'frozen', table);
    await amend(world, table, where, table === 'policy' ? { workloadsFrozenAt: null } : { frozenAt: null });
  }
  assert.equal(await outcome(signin(oidc(podToken()), 'p-4')), 'made');
  // Refusals write nothing, spend nothing, and are not logged.
  assert.deepEqual([(await sessions()).length, await spentCount(), (await entries()).filter((one) => one.action === 'token.exchange').length], [4, 4, 4]);
  assert.deepEqual(await checked(), []);
});

test("a row written behind the vault refuses the sign-in, tampered: a binding, the service, the instance's row, and a place its sessions would list", async () => {
  const { staging } = await workloadWorld();
  for (const [table, where] of [['bindings', `profile = 'custom' AND label = 'pods'`], ['principals', `id = '${DEPLOY}'`], ['policy', 'only_row'], ['environments', `id = '${staging.id}'`], ['projects', `id = '${market.id}'`]] as const) {
    const [{ mac }] = await rowsOf<{ mac: Buffer }>(world.owner, sql`SELECT mac FROM ${sql.identifier(table)} WHERE ${sql.raw(where)}`) as [{ mac: Buffer }];
    await zero(table, where);
    assert.equal(await outcome(signin(oidc(podToken()), 't-1')), 'tampered', table);
    await world.owner.execute(sql`UPDATE ${sql.identifier(table)} SET mac = ${mac} WHERE ${sql.raw(where)}`);
  }
  // A place of a project no binding's scope names decides nothing, and is not read.
  await zero('environments', `project_id <> '${market.id}'`);
  assert.equal(await outcome(signin(oidc(podToken()), 't-1')), 'made');
  await world.owner.execute(sql`DELETE FROM policy`);
  assert.equal(await outcome(signin(oidc(podToken()), 't-2')), 'adopting');
  // The signer finds the place left zeroed, and the instance's row gone.
  assert.deepEqual(await checked(), ['row', 'row']);
});

test('more bindings of a proof\'s profiles on an issuer than a service may hold: none of them answers; bindings of no policy count for nothing', async () => {
  await workloadWorld();
  const more = Array.from({ length: 15 }, (_, n) => binding(DEPLOY, { profile: 'custom', issuer: KUBE, jwksUri: KUBE_FETCHED.jwksUri, claims: canonicalClaims({ sub: `x${n}` }), scope: '[]', policy: '{}', createdAt: new Date(Date.UTC(2026, 5, 1, n)) }));
  await write(world, ...rows('bindings', ...more));
  assert.equal(await outcome(signin(oidc(podToken()), 'm-1')), 'no_match');
  await amend(world, 'bindings', sql`${bindings.id} = ${more[0]!.id}`, { policy: null });
  assert.equal(await outcome(signin(oidc(podToken()), 'm-1')), 'made');
  assert.deepEqual(await checked(), []);
});

test('two sign-ins with one token at once: the first spends it, and the second is refused; a binding revoked meanwhile makes none', async () => {
  const { pods } = await workloadWorld();
  const deciding = { workloads: world.workloads, owners: [] };
  const token = podToken();
  const [first, second] = await Promise.all(['c-1', 'c-2'].map((label) => prepare(world, OPERATIONS['workload.signin'](signin(oidc(token), label), deciding))));
  assert.ok(!('refused' in first!) && !('refused' in second!));
  assert.deepEqual([await written(world, first!), await written(world, second!)], ['made', 'spent']);
  assert.deepEqual([(await sessions()).length, await spentCount()], [1, 1]);
  const ready = await prepare(world, OPERATIONS['workload.signin'](signin(oidc(podToken()), 'c-3'), deciding));
  assert.ok(!('refused' in ready));
  await amend(world, 'bindings', sql`${bindings.id} = ${pods.id}`, { revokedAt: new Date(world.now()), revokedBy: 'user:root@acme.example' });
  assert.equal(await written(world, ready), 'moved');
  assert.deepEqual([(await sessions()).length, await spentCount()], [1, 1]);
  assert.deepEqual(await checked(), []);
});

test("keys a binding carries: a session's token is verified by the vault, under the keys on the row", async () => {
  const [known, stranger] = [pair(), pair()];
  const jwks = jwksOf({ key: known.publicKey, kid: 'k1' });
  const kube = binding(DEPLOY, { profile: 'custom', issuer: KUBE, jwksUri: carriedUri(jwks), jwks, claims: canonicalClaims({ sub: POD.sub }), scope: VIEWER, policy: '{}' });
  await write(world, ...rows('bindings', kube));
  const under = { issuer: KUBE, jwksUri: kube.jwksUri };
  assert.equal(await outcome(signin(oidc(signed(known.privateKey, 'k1'), under), 'k-1')), 'made');
  assert.equal(await outcome(signin(oidc(signed(stranger.privateKey, 'k2'), under), 'k-2')), 'unknown_signer');
  assert.equal(await outcome(signin(oidc(signed(stranger.privateKey, 'k1'), under), 'k-2')), 'malformed');
  assert.deepEqual(await checked(), []);
});

test('what a sign-in takes is checked before anything is read: a fault, never a refusal', () => {
  const deciding = { workloads: world.workloads, owners: [] };
  const ok = signin(oidc(podToken()), 'x');
  const wrong: Partial<Record<keyof Asked<'workload.signin'>, unknown>>[] = [
    { service: 7 }, { proof: null }, { proof: {} }, { proof: { oidc: { token: 'x', under: KUBE_FETCHED }, aws: AWS_ANSWER } }, { proof: { enrollment: 'code' } },
    { proof: { oidc: { token: 7, under: KUBE_FETCHED } } }, { proof: { oidc: { token: 'x', under: null } } }, { proof: { oidc: null } },
    { proof: { aws: null } }, { proof: { aws: { ...AWS_ANSWER, arn: 7 } } }, { proof: { aws: { account: AWS_ANSWER.account, arn: AWS_ANSWER.arn } } },
    { key: null }, { key: 'short' }, { key: `${KEY}=` }, { publicUrl: 7 }, { credential: 'ABC' }, { ip: 7 },
  ];
  for (const more of wrong) assert.throws(() => OPERATIONS['workload.signin']({ ...ok, ...more } as never, deciding), TypeError, JSON.stringify(more).slice(0, 80));
  assert.throws(() => OPERATIONS['workload.renew']({ ...renew('x'), token: 'ABC' } as never, deciding), TypeError);
});

test("a session renews itself with its key's proof: an hour on, never past its hard end; frozen it renews, stopped otherwise it is told why", async () => {
  const { aws } = await workloadWorld();
  const made = await vault.change(signin({ aws: AWS_ANSWER }, 'r-1'));
  assert.ok(!('refused' in made));
  const notAfter = made.answer.notAfter;
  const used = await lastUsed();
  world.tick(30 * 60_000);
  const done = await vault.change(renew('r-1'));
  assert.ok(!('refused' in done), JSON.stringify(done));
  assert.equal(done.answer.expiresAt, new Date(world.now() + 3_600_000).toISOString());
  assert.equal(iso((await sessions())[0]!.expires_at), done.answer.expiresAt);
  assert.deepEqual(await lastUsed(), used, "a renewal is no use of its binding, as in 0.14");
  const [entry] = (await entries()).filter((one) => one.action === 'workload.renew');
  assert.equal(entry!.kept, false);
  assert.deepEqual(entry!.detail, { credential: made.answer.credential, binding: aws.id, expiresAt: done.answer.expiresAt, notAfter });
  // Without its key, or with another, it is no one.
  assert.equal(await outcome(renew('r-1', null)), 'unauthenticated');
  assert.equal(await outcome(renew('r-1', OTHER_KEY)), 'unauthenticated');
  // Frozen, it renews, so that lifting the freeze restores it; outside its binding's sources, it is told so.
  await amend(world, 'bindings', sql`${bindings.id} = ${aws.id}`, { frozenAt: new Date(world.now()) });
  assert.equal(await outcome(renew('r-1')), 'made');
  assert.equal(await session('r-1'), 'frozen');
  await amend(world, 'bindings', sql`${bindings.id} = ${aws.id}`, { frozenAt: null, policy: '{"sessionHours":2,"sources":["10.0.0.0/8"]}' });
  assert.equal(await outcome(renew('r-1')), 'source');
  await amend(world, 'bindings', sql`${bindings.id} = ${aws.id}`, { policy: '{"sessionHours":2}' });
  // Near its hard end, it moves to it and no further; at it, nothing moves.
  world.tick(50 * 60_000);
  const last = await vault.change(renew('r-1'));
  assert.ok(!('refused' in last));
  assert.equal(last.answer.expiresAt, notAfter);
  const again = await vault.change(renew('r-1'));
  assert.ok(!('refused' in again));
  assert.equal(again.answer.expiresAt, notAfter);
  assert.equal((await entries()).filter((one) => one.action === 'workload.renew').at(-1)!.detail.unchanged, true);
  // Within five seconds of its end, a renewal comes too late; past it, the session is no one.
  world.tick(new Date(notAfter).getTime() - world.now() - 4_000);
  assert.equal(await outcome(renew('r-1')), 'expired');
  world.tick(4_000);
  assert.equal(await outcome(renew('r-1')), 'unauthenticated');
  assert.deepEqual(await checked(), []);
});

test('a renewal holds until five seconds before its session ends: a write that starts later writes nothing, and the change, decided again, is refused', async () => {
  await workloadWorld();
  const made = await vault.change(signin({ aws: AWS_ANSWER }, 'l-1'));
  assert.ok(!('refused' in made));
  const expiresAt = new Date(made.answer.expiresAt).getTime();
  const deciding = { workloads: world.workloads, owners: [] };
  const untouched = await sessions();
  let logged = (await entries()).length;
  // Decided with the margin and 40 ms left, written 80 ms later by the database's clock: nothing is written, no entry.
  world.tick(expiresAt - world.now() - WRITE_MS - 40);
  const late = await prepare(world, OPERATIONS['workload.renew'](renew('l-1'), deciding));
  assert.ok(!('refused' in late));
  await wait(80);
  assert.equal(await written(world, late), 'moved');
  assert.deepEqual([await sessions(), (await entries()).length], [untouched, logged]);
  // The review's case, end to end: decided with 6 s left, its write waits behind the change lock past the second it held
  // for, while the vault's clock moves on. Decided again 3 s on, it is too late to renew; 7 s on, the session is no one.
  for (const [moves, answer, said] of [[3_000, 'expired', [{ refused: 'expired' }]], [7_000, 'unauthenticated', []]] as const) {
    world.tick(expiresAt - world.now() - 6_000);
    const asked = await world.owner.transaction(async (holder) => {
      await holder.execute(sql`SELECT pg_advisory_xact_lock(${sql.raw(String(CHANGE_LOCK))})`);
      const asked = outcome(renew('l-1'));
      await wait(1_200);
      world.tick(moves);
      return { asked };
    });
    assert.equal(await asked.asked, answer);
    // The session is as it was, and what it logged is the refusal alone: no one's, none.
    assert.deepEqual([await sessions(), (await entries()).slice(logged).map((entry) => entry.detail)], [untouched, said]);
    logged += said.length;
  }
  assert.deepEqual(await checked(), []);
});

test('only a workload\'s own session renews: not a narrowed one, nor any other credential; one revoked meanwhile is not revived', async () => {
  const { aws } = await workloadWorld();
  const parent = await vault.change(signin({ aws: AWS_ANSWER }, 'n-1'));
  assert.ok(!('refused' in parent));
  await write(world, ...rows('credentials',
    sessionRow('n-2', aws, { jkt: KEY, ancestors: JSON.stringify([parent.answer.credential]), expiresAt: new Date(world.now() + 600_000), notAfter: new Date(world.now() + 3_600_000), scope: '[]' }),
    { ...sessionRow('n-3', aws), kind: 'service', jkt: null, notAfter: null, createdBy: DEPLOY }));
  assert.equal(await outcome(renew('n-2')), 'narrowed');
  assert.equal(await outcome(renew('n-3', null)), 'unauthenticated');
  const deciding = { workloads: world.workloads, owners: [] };
  world.tick(10 * 60_000);
  const ready = await prepare(world, OPERATIONS['workload.renew'](renew('n-1'), deciding));
  assert.ok(!('refused' in ready));
  await amend(world, 'credentials', sql`${credentials.id} = ${parent.answer.credential}`, { revokedAt: new Date(world.now()), revokedBy: DEPLOY });
  assert.equal(await written(world, ready), 'moved');
  assert.equal(await outcome(renew('n-1')), 'unauthenticated');
  assert.deepEqual(await checked(), []);
});
