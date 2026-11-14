// `coffre run` end to end on the 0.16 proxy: the CLI's own `placeholders`
// (packages/cli/src/main.ts), run as a person runs it, against the app
// behind a listener of this test's. It asks whether the instance has the
// proxy, makes one handle with the person's token, asks the plan with the
// handle, runs the command with the plan's variables, and revokes the
// handle once the command ends. What the plan holds is proxy-plan.test.ts's;
// here, that the CLI and the server agree on it. The CLI is spawned from its
// source, as its own tests run it: no package of the server's imports it.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { generateToken } from '@coffre/core/identity';
import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, instance, principal, project, role, rows, secret, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { basic, credentialProxy } from '../src/plugins/credential-proxy.ts';
import { openApp, PUBLIC_URL } from './app-fixture.ts';

const ADA = 'user:ada@acme.example';
const SID = 'AC0123456789';
const TOKEN = 'twilio-auth-token-0123';
const WEBHOOK = 'whsec_0123456789';

const proxy = credentialProxy({ credentials: { twilio: { upstream: 'https://api.twilio.example/2010-04-01', inject: basic('{TWILIO_SID}', '{TWILIO_TOKEN}') } }, generate: { 'market/local': 'all' } });
const app = await openApp({ plugins: [proxy] });
const { world } = app;
after(() => app.close());

/** The app on a port of its own, as a deployment serves it: each request handed to coffre as it came. */
async function listening(): Promise<{ origin: string; close: () => Promise<void> }> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) if (typeof value === 'string') headers.set(name, value);
    const answered = await app.request(req.url!, { method: req.method!, headers, ...(chunks.length === 0 ? {} : { body: Buffer.concat(chunks) }) });
    res.writeHead(answered.status, Object.fromEntries(answered.headers)).end(Buffer.from(await answered.arrayBuffer()));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as { port: number };
  return { origin: `http://127.0.0.1:${port}`, close: () => new Promise((resolve) => (server.close(() => resolve()), server.closeAllConnections())) };
}

test("a person's `coffre run` gets the plan's placeholders and values, and its handle ends with the command", async (t) => {
  await emptyDatabase(world.owner);
  const market = project('market');
  const dev = environment(market, 'dev');
  const pat = generateToken('personal');
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', market),
    ...rows('environments', dev),
    ...rows('principals', principal(ADA)),
    ...rows('grants', grant(ADA, 'developer', { project: market })),
    ...rows('secrets', value(world, secret(dev, 'TWILIO_SID'), SID, { plain: true }), value(world, secret(dev, 'TWILIO_TOKEN'), TOKEN), value(world, secret(dev, 'WEBHOOK_SECRET'), WEBHOOK), value(world, secret(dev, 'U_PASS'), 'u-pass-0123456789', { sensitive: true })),
    ...rows('credentials', credential(pat, ADA, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) })),
  );
  const served = await listening();
  t.after(served.close);
  // Signed in with the personal token, as `coffre login <url> --token` leaves it.
  const home = mkdtempSync(join(tmpdir(), 'coffre-plan-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  mkdirSync(join(home, '.coffre'), { recursive: true, mode: 0o700 });
  const session = { mode: 'signin', kind: 'token', token: pat, expiresAt: null, obtainedAt: new Date().toISOString() };
  writeFileSync(join(home, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: served.origin, instances: { [served.origin]: session } }), { mode: 0o600 });

  const printed = ['TWILIO_SID', 'TWILIO_TOKEN', 'WEBHOOK_SECRET', 'U_PASS', 'COFFRE_HANDLE', 'COFFRE_CREDENTIALS'];
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), COFFRE_STATE_DIR: home, HOME: home };
  const main = new URL('../../cli/src/main.ts', import.meta.url).pathname;
  const print = `console.log(JSON.stringify(Object.fromEntries(${JSON.stringify(printed)}.map((key) => [key, process.env[key] ?? null]))))`;
  const calls = app.calls.length;
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'run', 'market/dev', '--', process.execPath, '-e', print], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 20_000 });
  let [stdout, stderr] = ['', ''];
  child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
  child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
  const [code] = await once(child, 'close');
  assert.equal(code, 0, stderr);

  const got = JSON.parse(stdout) as Record<string, string | null>;
  const handle = got.COFFRE_HANDLE!;
  assert.match(handle, /^coffre_use_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(got, {
    TWILIO_SID: SID,
    TWILIO_TOKEN: handle,
    WEBHOOK_SECRET: WEBHOOK,
    U_PASS: null,
    COFFRE_HANDLE: handle,
    COFFRE_CREDENTIALS: JSON.stringify({ twilio: `${PUBLIC_URL}/use/market/dev/twilio` }),
  });
  assert.match(stderr, /placeholders for market\/dev: twilio through/);
  assert.match(stderr, /values as they are, which you may read: TWILIO_SID, WEBHOOK_SECRET$/m);
  assert.match(stderr, /left out, neither proxied nor yours to read: U_PASS/);
  assert.equal(stdout.includes(TOKEN) || stderr.includes(TOKEN), false);
  // The handle made, the plan's peek and its use, and the handle revoked: nothing else of the vault's.
  assert.deepEqual(app.calls.slice(calls), ['change', 'peek', 'use', 'change']);
  const [made] = await rowsOf<{ revoked: boolean }>(world.owner, sql`SELECT revoked_at IS NOT NULL AS revoked FROM credentials WHERE kind = 'handle'`);
  assert.deepEqual(made, { revoked: true }, 'ended with its command');
});

test("`coffre run` in an environment the deployment generates for makes the person's own value once, in their personal config, and the next run reads it", async (t) => {
  await emptyDatabase(world.owner);
  const market = project('market');
  const local = environment(market, 'local');
  const pat = generateToken('personal');
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('roles', role(true, 'owner', ['secret.read']), role(true, 'member', []), role(false, 'developer', ['secret.read', 'secret.use', 'secret.write'])),
    ...rows('projects', market),
    ...rows('environments', local),
    ...rows('principals', principal(ADA)),
    ...rows('grants', grant(ADA, 'developer', { project: market })),
    ...rows('secrets', { ...value(world, secret(local, 'SEAL_KEY'), 'shared-seal-key-0123456789', { sensitive: true }), recipe: 'bytes:32:hex' }, value(world, secret(local, 'TYPED'), 'typed-0123456789', { sensitive: true })),
    ...rows('credentials', credential(pat, ADA, { kind: 'personal', scope: JSON.stringify([{ projectId: market.id, environmentId: null, role: 'developer' }]) })),
  );
  const served = await listening();
  t.after(served.close);
  const home = mkdtempSync(join(tmpdir(), 'coffre-plan-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  mkdirSync(join(home, '.coffre'), { recursive: true, mode: 0o700 });
  const session = { mode: 'signin', kind: 'token', token: pat, expiresAt: null, obtainedAt: new Date().toISOString() };
  writeFileSync(join(home, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: served.origin, instances: { [served.origin]: session } }), { mode: 0o600 });
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), COFFRE_STATE_DIR: home, HOME: home };
  const main = new URL('../../cli/src/main.ts', import.meta.url).pathname;
  const print = 'console.log(JSON.stringify({ SEAL_KEY: process.env.SEAL_KEY ?? null, TYPED: process.env.TYPED ?? null }))';
  const run = async () => {
    const calls = app.calls.length;
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'run', 'market/local', '--', process.execPath, '-e', print], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 20_000 });
    let [stdout, stderr] = ['', ''];
    child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
    child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
    const [code] = await once(child, 'close');
    assert.equal(code, 0, stderr);
    return { got: JSON.parse(stdout) as Record<string, string | null>, stderr, calls: app.calls.slice(calls) };
  };

  // The handle, the plan (a peek: nothing in it is the app's to be handed yet), the one write of the person's own value, the
  // plan again, which reads it at once, and the handle ended.
  const first = await run();
  assert.match(first.got.SEAL_KEY!, /^[0-9a-f]{64}$/);
  assert.equal(first.got.TYPED, null, 'typed by hand: no recipe to make one by');
  assert.deepEqual(first.calls, ['change', 'peek', 'change', 'peek', 'use', 'change']);
  const configs = await rowsOf<{ owner: string }>(world.owner, sql`SELECT owner FROM environments WHERE owner IS NOT NULL`);
  assert.deepEqual(configs, [{ owner: ADA }]);
  // Made once: the next run, within the vault's memory too, reads it and writes nothing.
  const second = await run();
  assert.deepEqual([second.got.SEAL_KEY, second.calls], [first.got.SEAL_KEY, ['change', 'peek', 'use', 'change']]);
});
