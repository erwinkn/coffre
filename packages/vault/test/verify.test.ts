// The vault verifies a run's ID token itself, on the binding it sealed, when that binding carries its issuer's keys
// (T149, PR 3b; D148; formal/Lifecycle.tla's VaultVerifiesToken, AudienceSealed, Fetched): what an app turned hostile
// could hand it in place of the run's own proof buys nothing. Keys it forged, an audience it chose, a key it binds the
// session to. The vault opens no connection but Postgres: a binding of keys its issuer publishes takes the app's word
// for its token, and a token naming a key the uploaded set lacks is refused, never looked for. Both engines.
import test, { after, afterEach, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';

import { issuedGrant, sealedSessionScope, storedScope } from '@coffre/core/access';
import { uploadedKeys, type BindingPolicy } from '@coffre/core/identity';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { ChangeBindingsInput, MadeBinding, SignInInput } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { eq } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';

import { ISSUER, KEYS, ORIGIN, proofKey, testIssuer, type TestIssuer } from './issuer.ts';
import { emptyDatabase, newProject, openLocalVault, openTestDatabase, sealed, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const CI = 'token:ci';
const APP_KEY = 'app:0123456789abcdef';
const SIGN_IN = `${ORIGIN}/api/auth/workload`;
const CLUSTER = 'https://oidc.cluster.acme.example';
const ACCOUNT = { sub: 'system:serviceaccount:deploy:api', uid: '5f0c3b52-8f0e-4c4e-9f6e-2b8c3d1a7e90' };

let db: TestDatabase;
/** Every URL the vault asked of the network: none, ever (`afterEach`). */
let fetched: string[];
const realFetch = globalThis.fetch;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(async () => {
  fetched = [];
  globalThis.fetch = async (input) => {
    fetched.push(String(input instanceof Request ? input.url : input));
    throw new Error('the vault opens no connection but Postgres');
  };
  await emptyDatabase(db.owner);
});
afterEach(() => {
  globalThis.fetch = realFetch;
  assert.deepEqual(fetched, [], 'the vault fetched nothing');
});

function configure(): ResolvedVaultConfig {
  return {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    owners: ['root@acme.example'],
    signingKeys: [randomBytes(32)],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  };
}

/** A vault keeping 0.15's log, the test issuer, and a service account that views a project. */
async function world() {
  const issuer = testIssuer();
  const vault = await openLocalVault(db.vault, configure(), { log: '0.15', sealThrough: sealed });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  return { vault, project, issuer, live: [] as string[] };
}

type World = Awaited<ReturnType<typeof world>>;

/** A binding of CI's the Owner makes, sealed: a CI run's of `ISSUER`, whose keys it publishes, unless `as` says otherwise. */
async function bound(w: World, as: Partial<MadeBinding> = {}): Promise<MadeBinding> {
  const made: MadeBinding = {
    id: randomUUID(), principal: CI, generation: 0, profile: 'github', issuer: ISSUER, origin: ORIGIN, jwksUri: KEYS, claims: JSON.stringify({ repository_id: '1' }),
    scope: storedScope([{ ...issuedGrant({ projectId: w.project, environmentId: null, role: 'viewer' }), sensitive: false }]), policy: null, revoked: false,
    jwks: null, label: 'deploys', createdBy: 'root@acme.example', createdAt: Date.now(), authMac: randomBytes(32).toString('base64'), ...as,
  };
  const change: ChangeBindingsInput = {
    actor: ROOT, via: null, actorAccess: null, connection: null, make: made, live: [...w.live], reads: [], ends: [], reason: 'replaced', revokedAt: Date.now(),
    revokedBy: 'root@acme.example', policy: { seq: null, protected: [] }, appKey: APP_KEY,
  };
  const outcome = await w.vault.changeBindings!(change);
  assert.ok(outcome.ok, JSON.stringify(outcome));
  w.live.push(made.id);
  return made;
}

/** A binding of `ISSUER`'s whose keys were uploaded with it: `sha256:` and their digest, sealed. */
async function uploaded(w: World, as: Partial<MadeBinding> = {}): Promise<MadeBinding & { jwks: string }> {
  const keys = await uploadedKeys({ keys: [w.issuer.jwk] });
  return (await bound(w, { jwksUri: `sha256:${keys.digest}`, jwks: keys.jwks, ...as })) as MadeBinding & { jwks: string };
}

/** A binding as a sign-in names it: its row's columns, the instance it was made on, its seal. */
async function named(made: MadeBinding): Promise<SignInInput['binding']> {
  const { serviceBindings } = tablesOf(db.owner);
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made.id));
  return {
    columns: {
      id: made.id, principal: row!.principal, generation: row!.generation, profile: row!.profile, issuer: row!.issuer, origin: made.origin, jwksUri: row!.jwksUri,
      claims: row!.claims, scope: row!.scope, policy: row!.policy, revoked: row!.revokedAt !== null,
    },
    seal: Buffer.from(row!.seal!).toString('base64'),
  };
}

/** A sign-in through `made` as the app asks it: a CI run's, or a workload's session bound to `jkt` with its DPoP proof; `as` over it. */
async function signIn(w: World, made: MadeBinding, idToken: SignInInput['idToken'], as: { jkt?: string; dpop?: string | null; binding?: SignInInput['binding'] } = {}) {
  const binding = as.binding ?? (await named(made));
  const now = Date.now();
  const workload = made.policy !== null;
  const scope = workload ? sealedSessionScope(null, binding.columns, JSON.parse(made.policy!) as BindingPolicy) : binding.columns.scope;
  return w.vault.signIn!({
    principal: CI, binding,
    credential: {
      id: randomUUID(), kind: workload ? 'workload' : 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'coffre_x', label: 'deploys', scope,
      places: null, expiresAt: now + 60_000, notAfter: workload ? now + 60_000 : null, jkt: workload ? as.jkt! : null, authMac: randomBytes(32).toString('base64'),
    },
    // What the app says of the proof, which the vault takes from the token instead when it verifies one.
    appKey: APP_KEY, spent: workload ? null : randomBytes(32).toString('base64'), validUntil: workload ? null : now + 60_000,
    record: { proof: workload ? 'kubernetes' : 'oidc', issuer: ISSUER, run: { run_id: 'as the app says' } },
    idToken, dpop: as.dpop ?? null,
  });
}

/** The run's token, signed by `issuer` unless `options` says otherwise, with `made`'s uploaded keys as its row keeps them. */
const token = (issuer: TestIssuer, made: { jwks: string }, claims?: Record<string, unknown>, options?: Parameters<TestIssuer['token']>[1]) => ({
  token: issuer.token(claims, options), jwks: made.jwks,
});

/** What the vault said, a refusal's reason with it. */
function said(outcome: Awaited<ReturnType<typeof signIn>>): string {
  return outcome.ok ? 'ok' : outcome.refused === 'proof' ? `proof:${outcome.reason}` : outcome.refused;
}

async function credentials(): Promise<number> {
  const { credentials: table } = tablesOf(db.owner);
  return (await db.owner.select({ id: table.id }).from(table)).length;
}

/** What a sign-in's change recorded of its run. */
async function recordedRun(): Promise<Record<string, unknown>> {
  const { logChanges } = tablesOf(db.owner);
  const rows = await db.owner.select({ number: logChanges.number, payload: logChanges.payload }).from(logChanges);
  const signIns = rows.sort((a, b) => Number(a.number) - Number(b.number))
    .map((row) => JSON.parse(row.payload) as { op: string; signIn?: { run: Record<string, unknown> } })
    .filter((payload) => payload.op === 'credential.issue' && payload.signIn !== undefined);
  return signIns.at(-1)!.signIn!.run;
}

/** A Kubernetes workload's binding, its cluster's keys uploaded with it: `sha256:` and their digest, sealed. */
async function cluster(w: World, keys: Record<string, unknown>) {
  const uploaded = await uploadedKeys({ keys: [keys] });
  const made = await bound(w, {
    profile: 'kubernetes', issuer: CLUSTER, jwksUri: `sha256:${uploaded.digest}`, jwks: uploaded.jwks, policy: '{}',
    claims: JSON.stringify({ sub: ACCOUNT.sub, 'kubernetes.io.serviceaccount.uid': ACCOUNT.uid }),
  });
  const claims = { iss: CLUSTER, sub: ACCOUNT.sub, 'kubernetes.io': { namespace: 'deploy', serviceaccount: { name: 'api', uid: ACCOUNT.uid } } };
  return { made, jwks: uploaded.jwks, claims };
}

test("a token signed by a key its binding never trusted buys nothing: keys the app forged are not those the seal digests", async () => {
  const w = await world();
  const ci = await uploaded(w);
  assert.equal(said(await signIn(w, ci, token(w.issuer, ci))), 'ok', "the run's own token, under its binding's uploaded keys");
  // The app signs a token of its own, under the issuer's kid, with a key it holds, and hands in a set with that key.
  const { privateKey: forger, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.equal(said(await signIn(w, ci, token(w.issuer, ci, {}, { key: forger }))), 'proof:signature');
  const forged = JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'rs-1', alg: 'RS256', use: 'sig' }] });
  assert.equal(said(await signIn(w, ci, { token: w.issuer.token({}, { key: forger }), jwks: forged })), 'proof:keys');

  // A Kubernetes workload, its cluster's keys uploaded: the app's own set in their place is not what the seal digests.
  const k8s = await cluster(w, w.issuer.jwk);
  const session = await proofKey();
  const signed = async (idToken: SignInInput['idToken']) => said(await signIn(w, k8s.made, idToken, { jkt: session.jkt, dpop: await session.proof(SIGN_IN) }));
  assert.equal(await signed({ token: w.issuer.token(k8s.claims), jwks: k8s.jwks }), 'ok', "the cluster's own token, under its uploaded keys");
  assert.equal(await signed({ token: w.issuer.token(k8s.claims, { key: forger }), jwks: forged }), 'proof:keys');
  // Its sub and its service account's UID pinned: another account's token of the same cluster is no match.
  assert.equal(await signed({ token: w.issuer.token({ ...k8s.claims, 'kubernetes.io': { namespace: 'deploy', serviceaccount: { name: 'api', uid: randomUUID() } } }), jwks: k8s.jwks }), 'proof:no_match');
  assert.equal(await credentials(), 2, 'the refused wrote nothing');
});

test('a token naming a key the uploaded set lacks is refused, its kid named for the alert: never looked for, as the vault fetches nothing', async () => {
  const w = await world();
  const ci = await uploaded(w);
  for (let i = 0; i < 5; i += 1) {
    const outcome = await signIn(w, ci, token(w.issuer, ci, {}, { kid: `rotated-${i}` }));
    assert.deepEqual(outcome.ok ? null : outcome.refused === 'proof' ? [outcome.reason, outcome.kid] : outcome.refused, ['unknown_key', `rotated-${i}`]);
  }
  assert.equal(said(await signIn(w, ci, token(w.issuer, ci))), 'ok', 'the keys it has still verify');
});

test("the audience is the one sealed into the binding: an origin the app names otherwise is unsealed, a token for another, or for several, is refused (AudienceSealed)", async () => {
  const w = await world();
  const ci = await uploaded(w);
  const binding = await named(ci);
  // The app's own instance, or one it controls, named in the binding's place.
  const moved = { ...binding, columns: { ...binding.columns, origin: 'https://evil.example' } };
  assert.equal(said(await signIn(w, ci, token(w.issuer, ci, { aud: 'https://evil.example' }), { binding: moved })), 'unsealed');
  // A token a run asked for another audience: another instance's, which a compromised app there would replay here.
  assert.equal(said(await signIn(w, ci, token(w.issuer, ci, { aud: 'https://other.example' }))), 'proof:audience');
  assert.equal(said(await signIn(w, ci, token(w.issuer, ci, { aud: [ORIGIN, 'https://other.example'] }))), 'proof:audience', "for several parties, no single one's");
  assert.equal(said(await signIn(w, ci, token(w.issuer, ci, { aud: [ORIGIN] }))), 'ok', 'one audience in an array is that audience');
  assert.equal(await credentials(), 1);
});

test("a session is bound to the key its DPoP proof is signed by, and a token that names a key names that one: never a key the app substitutes (jkt)", async () => {
  const w = await world();
  // A workload whose caller picks the audience: the token names the session's key, `<origin>#jkt=<thumbprint>`.
  const named = await uploaded(w, { policy: JSON.stringify({ keyAudience: true }) });
  const run = await proofKey();
  const app = await proofKey();
  const naming = (key: { jkt: string }, form = '#') => token(w.issuer, named, { aud: `${ORIGIN}${form}jkt=${key.jkt}` });
  const proved = async (idToken: SignInInput['idToken'], key: typeof run, jkt = key.jkt, url = SIGN_IN) => said(await signIn(w, named, idToken, { jkt, dpop: await key.proof(url) }));

  assert.equal(await proved(naming(run), run), 'ok');
  assert.equal(await proved(naming(run, '?'), run), 'ok', 'either form a platform writes');
  // The run's token and proof, the session bound to the app's key instead: the key it would then hold the session with.
  assert.equal(await proved(naming(run), run, app.jkt), 'proof:dpop');
  // The run's token, with a proof of the app's own key: the token names another.
  assert.equal(await proved(naming(run), app), 'proof:audience');
  // A proof for another instance's sign-in, or none.
  assert.equal(await proved(naming(run), run, run.jkt, 'https://other.example/api/auth/workload'), 'proof:dpop');
  assert.equal(said(await signIn(w, named, naming(run), { jkt: run.jkt })), 'proof:dpop');
  // A workload of a binding of fetched keys: its token the app's, its DPoP proof still the vault's.
  const fetchedKeys = await bound(w, { policy: JSON.stringify({ keyAudience: true }) });
  assert.equal(said(await signIn(w, fetchedKeys, null, { jkt: run.jkt, dpop: await run.proof(SIGN_IN) })), 'ok');
  assert.equal(said(await signIn(w, fetchedKeys, null, { jkt: app.jkt, dpop: await run.proof(SIGN_IN) })), 'proof:dpop');
  assert.equal(said(await signIn(w, fetchedKeys, null, { jkt: run.jkt })), 'proof:dpop');
  // Nor does a CI run's sign-in take one.
  const ci = await uploaded(w);
  assert.equal(said(await signIn(w, ci, token(w.issuer, ci), { dpop: await run.proof(SIGN_IN) })), 'proof:malformed');
  assert.equal(await credentials(), 3);
});

test("a binding of keys its issuer publishes takes the app's word for its token, which the vault neither fetches keys for nor takes; one of uploaded keys takes none without its token", async () => {
  const w = await world();
  const ci = await bound(w);
  assert.equal(said(await signIn(w, ci, null)), 'ok', 'the app verified the token');
  assert.deepEqual(await recordedRun(), { run_id: 'as the app says' }, 'the run as the app recorded it');
  assert.equal(said(await signIn(w, ci, { token: w.issuer.token(), jwks: '{"keys":[]}' })), 'proof:malformed', 'a token it would not verify is none of its');
  // Uploaded keys: the vault's to verify, whatever the app sends.
  const up = await uploaded(w);
  assert.equal(said(await signIn(w, up, null)), 'proof:malformed');
  assert.equal(said(await signIn(w, up, token(w.issuer, up, { run_id: '7002' }))), 'ok');
  const run = await recordedRun();
  assert.equal(run.run_id, '7002', 'the run as its token says it, not as the app recorded it');
  assert.equal(run.sub, 'repo:acme/market:ref:refs/heads/dev');
  assert.equal(await credentials(), 2);
});

test("a proof that is no ID token is the app's to verify, its DPoP proof the vault's; a token beside it is none of its", async () => {
  const w = await world();
  const aws = await bound(w, { profile: 'aws', issuer: 'https://sts.amazonaws.com', jwksUri: 'urn:coffre:aws', policy: '{}', claims: JSON.stringify({ account: '123456789012', role_id: 'AROAEXAMPLEEXAMPLE' }) });
  const session = await proofKey();
  const dpop = async () => ({ jkt: session.jkt, dpop: await session.proof(SIGN_IN) });
  assert.equal(said(await signIn(w, aws, { token: w.issuer.token(), jwks: '{"keys":[]}' }, await dpop())), 'proof:malformed');
  assert.equal(said(await signIn(w, aws, null, { jkt: session.jkt })), 'proof:dpop', 'the session bound to a key its proof shows');
  assert.equal(said(await signIn(w, aws, null, await dpop())), 'ok', 'the app verified the signed request (0.15; the vault does in 0.16)');
});
