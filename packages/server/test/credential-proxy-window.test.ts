// The credential proxy's windows, all from one number, the deployment's `proxy.revokedWithinSeconds`, R
// (docs/design/config.md, "`proxy.revokedWithinSeconds`"): how long opened values serve, how long a request may send
// after its use was decided, and how a tunnel's checks fit inside R. Every path that forwards, signs, verifies or
// presigns with values decided now answers 503 `late` once R has passed since they were decided, as the UI's paths
// do. And the options 0.15 took for them, still read in 0.16 as the object's fields, with a warning. Through the
// plugin's own routes, with a fake coffre whose use takes as long as a test says: no database.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test, { type TestContext } from 'node:test';

import { defineDeployment, resolveDeployment, type Deployment, type DeploymentOptions } from '@coffre/core/deployment';

import { movedByPlugin, type PluginContext, type UseAsked } from '../src/plugins.ts';
import { credentialProxy, header, hmac, privateKey, proxyTimes, sigv4, type CredentialProxyOptions } from '../src/plugins/credential-proxy.ts';

const PUBLIC = 'https://coffre.example';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const SESSION = `coffre_wl_${'w'.repeat(43)}`;
const LATER = new Date(Date.now() + 86_400_000).toISOString();
const PEM = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const VALUES = { API_KEY: 'sk_live_0123456789abcdef', SIGNING_KEY: PEM, WEBHOOK_SECRET: 'whsec_0123456789', AWS_ACCESS_KEY_ID: 'AKIAEXAMPLE', AWS_SECRET_ACCESS_KEY: 'secret/0123456789' };

test('every window is R: values kept R (none without cacheValues), a request sent within R, a tunnel checked every R − d with d = min(R ÷ 2, 10 s)', () => {
  const times = (proxy: DeploymentOptions['proxy']) => proxyTimes(defineDeployment({ proxy }));
  // The default: checks every 50 s, each given 10 s, so a revoked handle's tunnel ends by 60 s.
  assert.deepEqual(times({}), { cacheMs: 60_000, sendMs: 60_000, check: { every: 50_000, deadline: 10_000 }, bound: 60_000 });
  // R = 4: every 2 s with 2 s to answer (config.md's example).
  assert.deepEqual(times({ revokedWithinSeconds: 4 }), { cacheMs: 4_000, sendMs: 4_000, check: { every: 2_000, deadline: 2_000 }, bound: 4_000 });
  // R's floor, the use's own 3 s deadline: a cold request whose use took most of it still goes out.
  assert.deepEqual(times({ revokedWithinSeconds: 3 }), { cacheMs: 3_000, sendMs: 3_000, check: { every: 1_500, deadline: 1_500 }, bound: 3_000 });
  assert.deepEqual(times({ revokedWithinSeconds: 3_600 }), { cacheMs: 3_600_000, sendMs: 3_600_000, check: { every: 3_590_000, deadline: 10_000 }, bound: 3_600_000 });
  // No values kept: every request asks the vault; R still bounds the send and the tunnels.
  assert.deepEqual(times({ cacheValues: false }), { cacheMs: 0, sendMs: 60_000, check: { every: 50_000, deadline: 10_000 }, bound: 60_000 });
});

test("0.15's options are the object's fields: editable as is, cacheSeconds 0 as cacheValues false, and one R, the smaller of the two as 0.15 ran them; one below R's 3 s floor refused", () => {
  const moved = (options: Omit<CredentialProxyOptions, 'credentials'>) => {
    const settings = movedByPlugin(credentialProxy({ credentials: {}, ...options }));
    return { old: settings.map((setting) => setting.old), deployment: resolveDeployment(undefined, settings, () => {}).proxy };
  };
  assert.deepEqual(moved({}), { old: [], deployment: { revokedWithinSeconds: 60, cacheValues: true, editable: false } });
  assert.deepEqual(moved({ editable: true }), { old: ['credentialProxy({ editable })'], deployment: { revokedWithinSeconds: 60, cacheValues: true, editable: true } });
  assert.deepEqual(moved({ cacheSeconds: 30, recheckSeconds: 120 }).deployment, { revokedWithinSeconds: 30, cacheValues: true, editable: false });
  // The other setting at its 0.15 default, 60: no bound grows on the way to 0.16.
  assert.deepEqual(moved({ cacheSeconds: 90 }).deployment, { revokedWithinSeconds: 60, cacheValues: true, editable: false });
  assert.deepEqual(moved({ recheckSeconds: 600 }).deployment, { revokedWithinSeconds: 60, cacheValues: true, editable: false });
  // No cache says nothing of R: the tunnels keep the 60 s both settings had.
  assert.deepEqual(moved({ cacheSeconds: 0 }).deployment, { revokedWithinSeconds: 60, cacheValues: false, editable: false });
  assert.deepEqual(moved({ cacheSeconds: 0, recheckSeconds: 20 }).deployment, { revokedWithinSeconds: 20, cacheValues: false, editable: false });
  // Below the floor: no R keeps it, and 3 s would let a revoked credential serve longer than it said (0.15's
  // `cacheSeconds: 1` asked the vault again 1.5 s on; R = 3 would not). Refused, naming what to write, alone or not.
  const refused = /credentialProxy\(\{ cacheSeconds: 1 \}\) is shorter than the 3 s .* Write proxy: \{ revokedWithinSeconds: 3 \} in deployment\.ts \(and cacheValues: false/;
  assert.throws(() => credentialProxy({ credentials: {}, cacheSeconds: 1 }), refused);
  assert.throws(() => credentialProxy({ credentials: {}, cacheSeconds: 1, recheckSeconds: 60 }), refused);
  assert.throws(() => credentialProxy({ credentials: {}, recheckSeconds: 0.2, cacheSeconds: 2.9 }), /credentialProxy\(\{ cacheSeconds: 2\.9, recheckSeconds: 0\.2 \}\) is shorter/);
  assert.throws(() => credentialProxy({ credentials: {}, recheckSeconds: 2 }), /credentialProxy\(\{ recheckSeconds: 2 \}\) is shorter/);
  // At the floor, and a cache of 0 beside a short recheck is still refused for the recheck.
  assert.deepEqual(moved({ cacheSeconds: 3 }).deployment, { revokedWithinSeconds: 3, cacheValues: true, editable: false });
  assert.throws(() => credentialProxy({ credentials: {}, cacheSeconds: 0, recheckSeconds: 1 }), /recheckSeconds: 1 \}\) is shorter/);
  // Checked as before.
  assert.throws(() => credentialProxy({ credentials: {}, recheckSeconds: 0 }), /recheckSeconds is above 0, an hour at most/);
  assert.throws(() => credentialProxy({ credentials: {}, cacheSeconds: 3_601 }), /cacheSeconds is between 0 and 3600/);
  // Beside the object, one would be ignored: refused.
  const both = movedByPlugin(credentialProxy({ credentials: {}, editable: true }));
  assert.throws(() => resolveDeployment({ proxy: { editable: true } }, both), /credentialProxy\(\{ editable \}\): in deployment\.ts now/);
});

test("a deployment still on 0.15's cacheSeconds: 0 is warned once, and still asks the vault on every request", async () => {
  const warned: string[] = [];
  const { plugin, sent } = proxyOf({ cacheSeconds: 0, editable: false });
  const deployment = resolveDeployment(undefined, movedByPlugin(plugin), (message) => void warned.push(message));
  assert.deepEqual(warned, ['coffre: credentialProxy({ cacheSeconds }), credentialProxy({ editable }) moved to deployment.ts in 0.16, read until 0.17, which refuses them there (docs/deploy.md, "deployment.ts")']);
  const caller = coffre(deployment);
  for (let i = 0; i < 3; i++) assert.equal((await forwarded(plugin, caller)).status, 200);
  assert.equal(caller.uses.length, 3);
  assert.equal(sent.length, 3);
});

test('with values kept, the next request within R asks nothing, and the one after R asks again', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
  const { plugin } = proxyOf();
  const caller = coffre(defineDeployment({ proxy: { revokedWithinSeconds: 4 } }));
  assert.equal((await forwarded(plugin, caller)).status, 200);
  t.mock.timers.tick(2_000);
  assert.equal((await forwarded(plugin, caller)).status, 200);
  assert.equal(caller.uses.length, 1);
  t.mock.timers.tick(2_001);
  assert.equal((await forwarded(plugin, caller)).status, 200);
  assert.equal(caller.uses.length, 2);
});

/**
 * Each path with values decided now: sent, or answered, when its use took less than R; 503 `late`, nothing sent, when
 * it took longer, as a request that paused after its values opened (a stalled isolate) would.
 */
const PATHS: { name: string; cacheValues?: boolean; ask: (plugin: ReturnType<typeof credentialProxy>, caller: Coffre) => Promise<Response> }[] = [
  { name: "a handle's request through code's credential", ask: (plugin, caller) => forwarded(plugin, caller) },
  // No values kept, and the stable URL: the vault's one call finds the environment (`useMadeFor`).
  { name: "a handle's request at the stable URL, its environment found in the use's own call", cacheValues: false, ask: (plugin, caller) => forwarded(plugin, caller) },
  { name: "a workload's request through code's credential", ask: (plugin, caller) => forwarded(plugin, caller, true) },
  { name: "a private key's signature", ask: (plugin, caller) => computed(plugin, caller, { sign: { credential: 'signing', message: 'aGVsbG8' } }) },
  { name: "an HMAC's signature", ask: (plugin, caller) => computed(plugin, caller, { sign: { credential: 'mac', message: 'aGVsbG8' } }) },
  { name: "an HMAC's check", ask: (plugin, caller) => computed(plugin, caller, { verify: { credential: 'webhook', message: 'aGVsbG8', signature: 'sha256=00' } }) },
  { name: 'a presigned URL', ask: (plugin, caller) => computed(plugin, caller, { presign: { credential: 's3', path: '/bucket/report.csv' } }) },
];

for (const path of PATHS) {
  test(`${path.name}: answered when its use was decided within R, 503 late past it, nothing sent`, async (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: 1_000_000 });
    const deployment = defineDeployment({ proxy: { revokedWithinSeconds: 4, cacheValues: path.cacheValues ?? true } });
    const { plugin, sent } = proxyOf();
    const first = coffre(deployment, t, 3_999);
    const within = await path.ask(plugin, first);
    assert.equal(within.status, 200, await within.clone().text());
    assert.equal(first.uses.length, 1);

    // A second caller, so that nothing kept for the first serves it: its use takes past R.
    const late = coffre(deployment, t, 4_001, `coffre_use_${'l'.repeat(43)}`);
    const before = sent.length;
    const answer = await path.ask(plugin, late);
    assert.equal(answer.status, 503);
    assert.equal(answer.headers.get('retry-after'), '1');
    assert.equal(((await answer.json()) as { reason: string }).reason, 'late');
    assert.equal(late.uses.length, 1);
    assert.equal(sent.length, before, 'nothing reached the upstream');
  });
}

/** The proxy: code's `api` (its upstream's egress records what it is sent), a private key and an HMAC that sign, an HMAC that checks, and an S3 credential. */
function proxyOf(options: Partial<CredentialProxyOptions> = {}) {
  const sent: string[] = [];
  const plugin = credentialProxy({
    credentials: {
      api: { upstream: 'https://api.example/v1', inject: header('x-api-key', '{API_KEY}'), egress: { fetch: async (url: URL) => (sent.push(url.href), new Response('ok')) } },
      s3: { upstream: 'https://s3.eu-west-3.amazonaws.com', inject: sigv4({ accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', region: 'eu-west-3', service: 's3' }) },
    },
    signers: { signing: privateKey('SIGNING_KEY'), mac: hmac('WEBHOOK_SECRET', { encoding: 'hex' }) },
    verifiers: { webhook: hmac('WEBHOOK_SECRET', { encoding: 'hex', prefix: 'sha256=' }) },
    ...options,
  });
  return { plugin, sent };
}

/** A request through `api`, as a handle's app sends it, or a workload's with its session. */
function forwarded(plugin: ReturnType<typeof credentialProxy>, { context, handle }: Coffre, workload = false): Promise<Response> {
  const headers: Record<string, string> = workload ? { authorization: `DPoP ${SESSION}` } : { 'x-coffre-handle': handle };
  return plugin.routes!.fetch(new Request(`${PUBLIC}/use/api/v1/charges`, { headers }), context);
}

/** A sign, verify or presign at market/dev, the handle as a bearer token. */
function computed(plugin: ReturnType<typeof credentialProxy>, { context, handle }: Coffre, body: unknown): Promise<Response> {
  const headers = { authorization: `Bearer ${handle}`, 'content-type': 'application/json' };
  return plugin.routes!.fetch(new Request(`${PUBLIC}/use/market/dev`, { method: 'POST', headers, body: JSON.stringify(body) }), context);
}

type Coffre = ReturnType<typeof coffre>;

/**
 * coffre, as the plugin sees it, with `deployment`: `handle`, or a workload's session, stands for market/dev, which
 * holds every value; each use counted, and taking `takes` ms of the mocked clock to decide.
 */
function coffre(deployment: Deployment, t?: TestContext, takes = 0, handle = HANDLE) {
  const uses: UseAsked[] = [];
  const decided = async (asked: Pick<UseAsked, 'keys'>) => {
    uses.push(asked as UseAsked);
    if (takes > 0) t!.mock.timers.tick(takes);
    const values = Object.fromEntries(Object.entries(VALUES).filter(([key]) => (asked.keys as readonly string[]).includes(key)));
    return { values, plain: [], keys: Object.keys(values), environment: { path: 'market/dev', personal: false }, expiresAt: LATER };
  };
  const workload = { path: 'market/dev', place: 'market/dev', places: ['market/dev'], nonce: null, constraints: null, hdr: [], credentialId: handle, principal: 'service:api' };
  const context = {
    publicUrl: PUBLIC,
    deployment,
    binding: false,
    workload: async (request: Request) => (request.headers.get('authorization')?.startsWith('DPoP ') ? workload : null),
    recheck: async () => true,
    handle: async () => ({ expiresAt: LATER, paths: ['market/dev'] }),
    use: async (_who: unknown, asked: UseAsked) => decided(asked),
    // The stable URL's one call, which the proxy asks only where it keeps no values.
    ...(deployment.proxy.cacheValues ? {} : { useMadeFor: async (_handle: string, asked: Pick<UseAsked, 'keys'>) => decided(asked) }),
  } as unknown as PluginContext;
  return { context, uses, handle };
}
