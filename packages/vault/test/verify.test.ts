// The vault verifies a run's ID token itself, on the binding it sealed (T149, PR 3b; D148; formal/Lifecycle.tla's
// VaultVerifiesToken, AudienceSealed): what an app turned hostile could hand it in place of the run's own proof buys
// nothing. Keys it forged, an audience it chose, a key it binds the session to, a URL that reaches the vault's own
// network; and a token naming keys no one has costs the issuer at most one fetch a minute. Both engines.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';

import { issuedGrant, sealedSessionScope, storedScope } from '@coffre/core/access';
import { forgetKeys, KEYS_COOLDOWN_MS, type WorkloadTransport } from '@coffre/core/fetch';
import { nodeTransport } from '@coffre/core/fetch/node';
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
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(async () => {
  forgetKeys();
  await emptyDatabase(db.owner);
});

function configure(): ResolvedVaultConfig {
  return {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    owners: ['root@acme.example'],
    signingKeys: [randomBytes(32)],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  };
}

/** A vault keeping 0.15's log, its issuers' keys asked of `transport` (the test issuer's unless said), and a service account that views a project. */
async function world(options: { transport?: WorkloadTransport; clock?: () => number } = {}) {
  const issuer = testIssuer();
  const vault = await openLocalVault(db.vault, configure(), {
    log: '0.15', sealThrough: sealed, issuers: { transport: options.transport ?? issuer.transport }, ...(options.clock === undefined ? {} : { clockOffset: options.clock }),
  });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  return { vault, project, issuer, live: [] as string[] };
}

type World = Awaited<ReturnType<typeof world>>;

/** A binding of CI's the Owner makes, sealed: a CI run's of `ISSUER` unless `as` says otherwise. */
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

/** A sign-in through `made` as the app asks it: a CI run's, or a workload's session bound to `jkt`; `as` over it. */
async function signIn(w: World, made: MadeBinding, proof: SignInInput['proof'], as: { jkt?: string; binding?: SignInInput['binding'] } = {}) {
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
    // What the app says of the proof, which the vault takes from the token instead.
    appKey: APP_KEY, spent: workload ? null : randomBytes(32).toString('base64'), validUntil: workload ? null : now + 60_000,
    record: { proof: workload ? 'kubernetes' : 'oidc', issuer: ISSUER, run: {} },
    proof,
  });
}

const token = (issuer: TestIssuer, claims?: Record<string, unknown>, options?: Parameters<TestIssuer['token']>[1]) => ({ token: issuer.token(claims, options), jwks: null, dpop: null });

/** What the vault said, a refusal's reason with it. */
function said(outcome: Awaited<ReturnType<typeof signIn>>): string {
  if (process.env.SAID) console.log(outcome);
  return outcome.ok ? 'ok' : outcome.refused === 'proof' ? `proof:${outcome.reason}` : outcome.refused;
}

async function credentials(): Promise<number> {
  const { credentials: table } = tablesOf(db.owner);
  return (await db.owner.select({ id: table.id }).from(table)).length;
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

test("a run's token signed by a key its binding never trusted buys nothing: keys the app forged, uploaded or fetched, are not the sealed ones", async () => {
  const w = await world();
  const ci = await bound(w);
  assert.equal(said(await signIn(w, ci, token(w.issuer))), 'ok', 'the run\'s own token');
  // The app signs a token of its own, under the issuer's kid, with a key it holds.
  const { privateKey: forger, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.equal(said(await signIn(w, ci, token(w.issuer, {}, { key: forger }))), 'proof:signature');
  // Its keys handed in beside a binding whose keys are fetched: the vault fetches them, and the forged set is no key set of the binding's.
  const forged = JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'rs-1', alg: 'RS256', use: 'sig' }] });
  assert.equal(said(await signIn(w, ci, { token: w.issuer.token({}, { key: forger }), jwks: forged, dpop: null })), 'proof:keys');

  // A workload whose cluster's keys were uploaded: the app's own set in their place is not what the seal digests.
  const k8s = await cluster(w, w.issuer.jwk);
  const session = await proofKey();
  const dpop = await session.proof(SIGN_IN);
  assert.equal(said(await signIn(w, k8s.made, { token: w.issuer.token(k8s.claims), jwks: k8s.jwks, dpop }, { jkt: session.jkt })), 'ok', 'the cluster\'s own token, under its uploaded keys');
  for (const jwks of [forged, null]) {
    const outcome = await signIn(w, k8s.made, { token: w.issuer.token(k8s.claims, { key: forger }), jwks, dpop: await session.proof(SIGN_IN) }, { jkt: session.jkt });
    assert.equal(said(outcome), 'proof:keys', `keys ${jwks === null ? 'left out' : 'forged'}`);
  }
  assert.equal(await credentials(), 2, 'the refused wrote nothing');
});

test("the audience is the one sealed into the binding: an origin the app names otherwise is unsealed, a token for another, or for several, is refused (AudienceSealed)", async () => {
  const w = await world();
  const ci = await bound(w);
  const binding = await named(ci);
  // The app's own instance, or one it controls, named in the binding's place.
  const moved = { ...binding, columns: { ...binding.columns, origin: 'https://evil.example' } };
  assert.equal(said(await signIn(w, ci, token(w.issuer, { aud: 'https://evil.example' }), { binding: moved })), 'unsealed');
  // A token a run asked for another audience: another instance's, which a compromised app there would replay here.
  assert.equal(said(await signIn(w, ci, token(w.issuer, { aud: 'https://other.example' }))), 'proof:audience');
  assert.equal(said(await signIn(w, ci, token(w.issuer, { aud: [ORIGIN, 'https://other.example'] }))), 'proof:audience', 'for several parties, no single one\'s');
  assert.equal(said(await signIn(w, ci, token(w.issuer, { aud: [ORIGIN] }))), 'ok', 'one audience in an array is that audience');
  assert.equal(await credentials(), 1);
});

test("a session is bound to the key its DPoP proof is signed by, and a token that names a key names that one: never a key the app substitutes (jkt)", async () => {
  const w = await world();
  // A GitHub workload: its caller picks the audience, so the token names the session's key, `<origin>#jkt=<thumbprint>`.
  const gh = await bound(w, { policy: JSON.stringify({ keyAudience: true }) });
  const run = await proofKey();
  const app = await proofKey();
  const naming = (key: { jkt: string }, form = '#') => token(w.issuer, { aud: `${ORIGIN}${form}jkt=${key.jkt}` });
  const proved = async (proof: SignInInput['proof'], key: typeof run, jkt = key.jkt, url = SIGN_IN) => said(await signIn(w, gh, { ...proof!, dpop: await key.proof(url) }, { jkt }));

  assert.equal(await proved(naming(run), run), 'ok');
  assert.equal(await proved(naming(run, '?'), run), 'ok', 'either form a platform writes');
  // The run's token and proof, the session bound to the app's key instead: the key it would then hold the session with.
  assert.equal(await proved(naming(run), run, app.jkt), 'proof:dpop');
  // The run's token, with a proof of the app's own key: the token names another.
  assert.equal(await proved(naming(run), app), 'proof:audience');
  // A proof for another instance's sign-in, or none.
  assert.equal(await proved(naming(run), run, run.jkt, 'https://other.example/api/auth/workload'), 'proof:dpop');
  assert.equal(said(await signIn(w, gh, naming(run), { jkt: run.jkt })), 'proof:dpop');
  // Nor does a CI run's sign-in take one.
  const ci = await bound(w);
  assert.equal(said(await signIn(w, ci, { ...token(w.issuer), dpop: await run.proof(SIGN_IN) })), 'proof:malformed');
  assert.equal(await credentials(), 2);
});

test('a token naming a key the issuer lacks costs it at most one fetch a minute, however many come: then a refusal, while the keys it has still work', async () => {
  let offset = 0;
  const w = await world({ clock: () => offset });
  const ci = await bound(w);
  assert.equal(said(await signIn(w, ci, token(w.issuer))), 'ok');
  assert.equal(w.issuer.fetches(), 1);
  const random = () => token(w.issuer, {}, { kid: randomBytes(8).toString('hex') });
  for (let i = 0; i < 20; i += 1) assert.equal(said(await signIn(w, ci, random())), 'proof:issuer_unavailable');
  assert.equal(w.issuer.fetches(), 2, 'the first unknown kid fetches the keys again, in case the issuer rotated; none of the next do');
  assert.equal(said(await signIn(w, ci, token(w.issuer))), 'ok', 'the keys fetched still verify the run\'s own');
  offset = KEYS_COOLDOWN_MS + 1_000;
  for (let i = 0; i < 5; i += 1) assert.equal(said(await signIn(w, ci, random())), 'proof:issuer_unavailable');
  assert.equal(w.issuer.fetches(), 3, 'a minute on, one fetch more');
});

test("a binding's keys at an address, over plain HTTP, or at a name that resolves into the vault's network are never fetched: on Node, refused when connecting", async () => {
  const errors: unknown[] = [];
  const node = nodeTransport({ deadlineMs: 1_000 });
  let fetches = 0;
  const transport: WorkloadTransport = {
    json: async (url) => {
      fetches += 1;
      try {
        return await node.json(url);
      } catch (error) {
        errors.push(error);
        throw error;
      }
    },
  };
  const w = await world({ transport });
  for (const jwksUri of ['https://10.0.0.7/keys', 'https://169.254.169.254/keys', 'https://[::1]/keys', 'http://issuer.example/keys', 'http://127.0.0.1:8081/keys', 'https://issuer.example:8443/keys']) {
    const made = await bound(w, { jwksUri });
    assert.equal(said(await signIn(w, made, token(w.issuer))), 'proof:issuer_unavailable', jwksUri);
  }
  assert.equal(fetches, 0, 'none of them asked of the network');
  // A name that passes for a host's, and resolves to loopback: the resolver refuses it at connect time.
  const made = await bound(w, { jwksUri: 'https://localhost./keys' });
  assert.equal(said(await signIn(w, made, token(w.issuer))), 'proof:issuer_unavailable');
  assert.equal(fetches, 1);
  assert.match(String((errors[0] as Error).cause), /not public/);
  assert.equal(await credentials(), 0);
});

test("an instance on loopback, as `pnpm dev`'s is, fetches its dev IdP's keys over plain HTTP on loopback; no other does", async () => {
  const issuer = testIssuer();
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: [issuer.jwk] }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const keys = `http://127.0.0.1:${(server.address() as AddressInfo).port}/keys`;
    const w = await world({ transport: nodeTransport({ deadlineMs: 1_000 }) });
    const dev = 'http://127.0.0.1:3000';
    const local = await bound(w, { origin: dev, jwksUri: keys });
    assert.equal(said(await signIn(w, local, token(issuer, { aud: dev }))), 'ok');
    const remote = await bound(w, { jwksUri: keys });
    assert.equal(said(await signIn(w, remote, token(issuer))), 'proof:issuer_unavailable');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("a proof that is no ID token is the app's to verify, on a binding of such a profile only: an ID token's binding takes none without its token", async () => {
  const w = await world();
  const ci = await bound(w);
  assert.equal(said(await signIn(w, ci, null)), 'proof:malformed');
  const aws = await bound(w, { profile: 'aws', issuer: 'https://sts.amazonaws.com', jwksUri: 'urn:coffre:aws', policy: '{}', claims: JSON.stringify({ account: '123456789012', role_id: 'AROAEXAMPLEEXAMPLE' }) });
  const session = await proofKey();
  assert.equal(said(await signIn(w, aws, token(w.issuer), { jkt: session.jkt })), 'proof:malformed', 'a token beside a signed request is none of its');
  assert.equal(said(await signIn(w, aws, null, { jkt: session.jkt })), 'ok', 'the app verified the signed request (0.15; the vault does in 0.16)');
});
