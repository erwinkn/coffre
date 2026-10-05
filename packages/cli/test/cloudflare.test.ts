import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { type ChildProcess, spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse } from 'jsonc-parser';

import { localCallback } from '../src/browser.ts';
import { callbackOf, CloudflareApi, cloudflareToken, deploymentWrangler, deployWorker, originOf, stopWranglers } from '../src/cloudflare.ts';
import { deploymentKind, editWorker, placeholder, readWorker } from '../src/deployment.ts';
import { appManifest, appName, convert, createGitHubApp, manifestAddress, manifestPage } from '../src/github-app.ts';
import { templateDir } from '../src/init.ts';
import { Steps } from '../src/steps.ts';
import { Cancelled } from '../src/tty.ts';
import { addressOf, addressProblem, adminsProblem, domainOf, isOurs, nameFrom, nameProblem, ourConfig, recordsOf } from '../src/workers.ts';
import { cancelTerminals, fakeCloudflare, fakeGitHub, fakeOpener, fakeTerminal, fakeWrangler, manifestForm, settle, submitManifest } from './fakes.ts';

// Whatever a failed test leaves waiting, a prompt, a wrangler, a listener, goes: this file's process always ends.
after(() => {
  cancelTerminals();
  stopWranglers();
});

/** For a test that runs a process or listens: it fails, rather than waits for ever. */
const LIMIT = { timeout: 30_000 };

const TOKEN = `cf-oauth-${'t'.repeat(40)}`;

function scratch(): string {
  return mkdtempSync(join(tmpdir(), 'coffre-cloudflare-'));
}

/** Keys typed, one tick each, as a person would. */
async function type(keys: NodeJS.WritableStream, text: string): Promise<void> {
  keys.write(text);
  await new Promise((resolve) => setImmediate(resolve));
}

async function until<T>(read: () => T | undefined | Promise<T | undefined>, timeoutMs = 10_000): Promise<T> {
  const start = Date.now();
  for (;;) {
    const value = await read();
    if (value !== undefined) return value;
    if (Date.now() - start > timeoutMs) throw new Error('timed out');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

// --- what a paste may make setup fetch ---------------------------------------------------

test('a pasted callback is fetched only on this machine: localhost or 127.0.0.1, the port and path expected, with its parameters', () => {
  const ok = 'http://localhost:8976/oauth/callback?code=abc&state=xyz';
  assert.equal(String(localCallback(ok, 8976, '/oauth/callback', ['code', 'state'])), ok);
  assert.ok(localCallback('  http://127.0.0.1:8976/oauth/callback?code=a&state=b\n', 8976, '/oauth/callback', ['code', 'state']) instanceof URL);
  for (const [pasted, why] of [
    ['http://evil.example:8976/oauth/callback?code=a&state=b', /not a localhost address/],
    ['http://localhost.evil.example:8976/oauth/callback?code=a&state=b', /not a localhost address/],
    ['http://localhost:8976@evil.example/oauth/callback?code=a&state=b', /not a localhost address/],
    ['https://localhost:8976/oauth/callback?code=a&state=b', /not a localhost address/],
    ['http://127.0.0.2:8976/oauth/callback?code=a&state=b', /not a localhost address/],
    ['http://localhost:8977/oauth/callback?code=a&state=b', /not this step's address/],
    ['http://localhost:8976/elsewhere?code=a&state=b', /not this step's address/],
    ['http://localhost:8976/oauth/callback?code=a', /has no state/],
    ['localhost:8976/oauth/callback', /not a localhost address|not an address/],
    ['not a url', /not an address/],
  ] as const) {
    const result = localCallback(pasted, 8976, '/oauth/callback', ['code', 'state']);
    assert.equal(typeof result, 'string', pasted);
    assert.match(result as string, why, pasted);
  }
});

test("wrangler's callback is where its link says, if on this machine; otherwise wrangler's own", () => {
  const link = (redirect: string) => `https://dash.cloudflare.com/oauth2/auth?redirect_uri=${encodeURIComponent(redirect)}&state=s`;
  assert.equal(callbackOf(link('http://localhost:9123/oauth/callback')).href, 'http://localhost:9123/oauth/callback');
  assert.equal(callbackOf(link('https://evil.example/oauth/callback')).href, 'http://localhost:8976/oauth/callback');
  assert.equal(callbackOf('https://dash.cloudflare.com/oauth2/auth').href, 'http://localhost:8976/oauth/callback');
});

// --- the deployment's files ----------------------------------------------------------------

test("a directory's kind: empty, a deployment of either kind, or something else", () => {
  const dir = scratch();
  try {
    assert.equal(deploymentKind(join(dir, 'absent')), 'empty');
    assert.equal(deploymentKind(dir), 'empty');
    cpSync(templateDir('workers'), join(dir, 'workers'), { recursive: true, filter: (path) => !path.includes('node_modules') });
    cpSync(templateDir('node'), join(dir, 'node'), { recursive: true, filter: (path) => !path.includes('node_modules') });
    assert.equal(deploymentKind(join(dir, 'workers')), 'workers');
    assert.equal(deploymentKind(join(dir, 'node')), 'node');
    assert.equal(deploymentKind(dir), 'other');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('wrangler.jsonc is read for what setup needs, and edited in place, its comments and layout kept', () => {
  const dir = scratch();
  try {
    cpSync(templateDir('workers'), dir, { recursive: true, filter: (path) => !path.includes('node_modules') });
    const before = readWorker(dir, 'app/wrangler.jsonc');
    assert.deepEqual(
      { name: before.name, accountId: before.accountId, hyperdrive: before.hyperdrive, route: before.route },
      { name: 'coffre', accountId: null, hyperdrive: null, route: null },
    );
    assert.ok(placeholder(before.vars.PUBLIC_URL) && placeholder(before.vars.GITHUB_CLIENT_ID));
    assert.ok(placeholder(readWorker(dir, 'vault/wrangler.jsonc').vars.ROOT_ADMINS));

    editWorker(dir, 'app/wrangler.jsonc', [
      { path: ['account_id'], value: 'acc-1', after: 'name' },
      { path: ['vars', 'PUBLIC_URL'], value: 'https://secrets.acme.test' },
      { path: ['hyperdrive', 0, 'id'], value: 'hd-1' },
      { path: ['routes'], value: [{ pattern: 'secrets.acme.test', custom_domain: true }], after: 'workers_dev' },
    ]);
    const text = readFileSync(join(dir, 'app/wrangler.jsonc'), 'utf8');
    assert.match(text, /"name": "coffre",\n {2}"account_id": "acc-1",\n/);
    assert.match(text, /"workers_dev": false,\n {2}"routes": \[\{ "pattern": "secrets\.acme\.test", "custom_domain": true \}\],\n/);
    assert.match(text, /"hyperdrive": \[\{ "binding": "HYPERDRIVE", "id": "hd-1" \}\],/);
    assert.match(text, /\/\/ Where people reach coffre: an origin, no path\./, 'comments stay');
    const after = readWorker(dir, 'app/wrangler.jsonc');
    assert.deepEqual(
      { accountId: after.accountId, hyperdrive: after.hyperdrive, route: after.route, url: after.vars.PUBLIC_URL },
      { accountId: 'acc-1', hyperdrive: 'hd-1', route: 'secrets.acme.test', url: 'https://secrets.acme.test' },
    );
    // The rest, as it was.
    const parsed = parse(text) as { services: unknown; triggers: unknown };
    assert.deepEqual(parsed.services, [{ binding: 'VAULT', service: 'coffre-vault' }]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the address and the root admins: what will do, and why not', () => {
  assert.equal(addressOf(' HTTPS://Secrets.Acme.test/login?x=1 '), 'secrets.acme.test');
  assert.equal(addressProblem('secrets.acme.test'), null);
  assert.equal(addressProblem('acme.test'), null);
  // Under none of the account's domains will do too: it is served through one (hostname.ts).
  assert.equal(addressProblem('secrets.other.test'), null);
  assert.match(addressProblem('secrets')!, /an address such as/);
  assert.match(addressProblem('secrets.acme.test:8443')!, /an address such as/);
  assert.equal(domainOf('secrets.example.org'), 'example.org');
  assert.equal(adminsProblem('a@acme.test, b@acme.test'), null);
  assert.match(adminsProblem('a@acme.test, nobody')!, /not an email: nobody/);
});

// --- whose a Worker and a Hyperdrive config are ---------------------------------------------

test('what a directory records of its deployment: the Hyperdrive ids it binds, and a vault ID setup made, not the template\'s', () => {
  const dir = scratch();
  try {
    cpSync(templateDir('workers'), dir, { recursive: true, filter: (path) => !path.includes('node_modules') });
    const read = () => recordsOf({ app: readWorker(dir, 'app/wrangler.jsonc'), vault: readWorker(dir, 'vault/wrangler.jsonc') });
    assert.deepEqual(read(), { hyperdrive: { app: null, vault: null }, vaultKeyId: null }, 'a fresh deployment records nothing, vault-1 included');
    editWorker(dir, 'app/wrangler.jsonc', [{ path: ['hyperdrive', 0, 'id'], value: 'hd-app' }]);
    editWorker(dir, 'vault/wrangler.jsonc', [{ path: ['vars', 'VAULT_KEY_ID'], value: 'vault-2026-10-03-abcdef' }]);
    assert.deepEqual(read(), { hyperdrive: { app: 'hd-app', vault: null }, vaultKeyId: 'vault-2026-10-03-abcdef' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a Worker is this deployment's only when it binds what this directory records; another deployment's otherwise", () => {
  const records = { hyperdrive: { app: 'hd-app', vault: 'hd-vault' }, vaultKeyId: 'vault-2026-10-03-abcdef' };
  const nothing = { hyperdrive: { app: null, vault: null }, vaultKeyId: null };
  const app = [{ type: 'hyperdrive', name: 'HYPERDRIVE', id: 'hd-app' }];
  assert.equal(isOurs('app', app, records), true);
  assert.equal(isOurs('app', [{ type: 'hyperdrive', name: 'HYPERDRIVE', id: 'hd-elsewhere' }], records), false);
  assert.equal(isOurs('app', app, nothing), false, 'a fresh directory owns no Worker that exists');
  const vault = [{ type: 'plain_text', name: 'VAULT_KEY_ID', text: 'vault-2026-10-03-abcdef' }];
  assert.equal(isOurs('vault', vault, { ...records, hyperdrive: { app: null, vault: null } }), true, 'by its vault ID');
  assert.equal(isOurs('vault', [{ type: 'plain_text', name: 'VAULT_KEY_ID', text: 'vault-1' }], nothing), false);
});

test("a Hyperdrive config is this deployment's by the id it records, or by name only on this run's database", () => {
  const administrator = new URL('postgresql://owner:pw@db.acme.test:5432/coffre');
  const config = (id: string, name: string, host: string, database: string) => ({ id, name, origin: { host, port: 5432, database, user: 'coffre_runtime' } });
  const live = config('hd-live', 'coffre', 'db.live.test', 'coffre');
  const leftover = config('hd-left', 'coffre-try', 'db.acme.test', 'coffre');
  assert.equal(ourConfig([live], 'coffre', null, administrator), undefined, 'another database: never touched');
  assert.equal(ourConfig([live], 'coffre', 'hd-live', administrator), live, 'recorded here: ours, wherever it points');
  assert.equal(ourConfig([live, leftover], 'coffre-try', null, administrator), leftover, "made by a run that stopped before recording it");
  assert.equal(ourConfig([config('hd-x', 'coffre', 'db.acme.test', 'other')], 'coffre', null, administrator), undefined, 'same host, another database');
});

test("a deployment's name: from its address, as a Worker's name can be", () => {
  assert.equal(nameFrom('coffre-try.erwinkn.com'), 'coffre-try');
  assert.equal(nameFrom('try.erwinkn.com'), 'coffre-try');
  assert.equal(nameFrom('secrets.acme.com'), 'coffre-secrets');
  assert.equal(nameFrom(`${'x'.repeat(70)}.acme.com`).length, 57);
  assert.equal(nameProblem(nameFrom(`${'x'.repeat(49)}-y.acme.com`)), null, 'never ends on a dash once cut');
  assert.equal(nameProblem('coffre-try'), null);
  for (const bad of ['Coffre', '-x', 'x-', 'a_b', 'x'.repeat(58)]) assert.match(nameProblem(bad)!, /lower-case letters, digits and dashes/, bad);
});

// --- Cloudflare's API ------------------------------------------------------------------------

test("Cloudflare's API: the token as a bearer, a database password only in a body, never in an error, and caching off", LIMIT, async () => {
  const cloudflare = await fakeCloudflare(TOKEN);
  try {
    const api = new CloudflareApi(TOKEN, cloudflare.url);
    assert.deepEqual((await api.accounts()).map(({ name }) => name), ['Acme', 'Home']);
    // An account with more domains than a page holds: every one of them.
    cloudflare.state.zones['acc-acme'] = Array.from({ length: 120 }, (_, i) => ({ id: `zone-${i}`, name: `acme-${i}.test` }));
    assert.equal((await api.zones('acc-acme')).length, 120);
    assert.equal(await api.email(), 'ops@acme.test');
    assert.deepEqual(await api.secretNames('acc-acme', 'coffre'), null, 'a Worker not deployed yet');
    assert.equal(await api.bindings('acc-acme', 'coffre'), null);
    cloudflare.state.scripts.set('acc-acme/coffre', { secrets: new Set(['APP_KEY']), bindings: [{ type: 'hyperdrive', name: 'HYPERDRIVE', id: 'hd-1' }] });
    assert.deepEqual(await api.bindings('acc-acme', 'coffre'), [{ type: 'hyperdrive', name: 'HYPERDRIVE', id: 'hd-1' }]);
    assert.deepEqual(await api.secretNames('acc-acme', 'coffre'), ['APP_KEY']);
    const origin = originOf('postgresql://coffre_runtime.br4nch:p%40ss-word@db.acme.test:6432/coffre?sslmode=verify-full');
    assert.deepEqual(origin, { host: 'db.acme.test', port: 6432, database: 'coffre', user: 'coffre_runtime.br4nch', password: 'p@ss-word' });
    const id = await api.createHyperdrive('acc-acme', 'coffre', origin);
    const made = cloudflare.state.configs.get('acc-acme')![0]!;
    assert.equal(made.id, id);
    assert.deepEqual(made.origin, { scheme: 'postgres', ...origin });
    assert.deepEqual(made.caching, { disabled: true });
    const listed = await api.hyperdriveConfigs('acc-acme');
    assert.ok(!JSON.stringify(listed).includes('p@ss-word'));
    await api.disableCaching('acc-acme', id);

    const refused = new CloudflareApi('not-the-token', cloudflare.url);
    await assert.rejects(refused.createHyperdrive('acc-acme', 'coffre', origin), (error: Error) => {
      assert.match(error.message, /^Cloudflare answered 401 to POST \/accounts\/acc-acme\/hyperdrive\/configs: Authentication error \(10000\)$/);
      assert.ok(!error.message.includes('p@ss-word') && !error.message.includes('not-the-token'));
      return true;
    });
    for (const request of cloudflare.state.requests) assert.ok(!request.path.includes('p@ss-word'), 'a password in a URL');
  } finally {
    cloudflare.close();
  }
});

// --- wrangler ---------------------------------------------------------------------------------

test("wrangler deploys with the secrets on its stdin, as its secrets file: never in its arguments, and none when there are none", LIMIT, async () => {
  const dir = scratch();
  const cloudflare = await fakeCloudflare(TOKEN);
  const env = process.env.CLOUDFLARE_API_BASE_URL;
  process.env.CLOUDFLARE_API_BASE_URL = cloudflare.url;
  try {
    cpSync(templateDir('workers'), dir, { recursive: true, filter: (path) => !path.includes('node_modules') });
    fakeWrangler(dir, join(dir, '.state'), TOKEN);
    writeFileSync(join(dir, '.state', 'token'), TOKEN);
    const wrangler = deploymentWrangler(dir);
    const key = 'K'.repeat(43) + '=';
    await deployWorker(wrangler, 'vault/wrangler.jsonc', 'acc-acme', { VAULT_KEY: key });
    await deployWorker(wrangler, 'app/wrangler.jsonc', 'acc-acme', {});
    const calls = readFileSync(join(dir, '.state', 'calls.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    assert.deepEqual(calls[0].args, ['deploy', '-c', 'vault/wrangler.jsonc', '--secrets-file', '/dev/stdin']);
    assert.deepEqual(JSON.parse(calls[0].stdin), { VAULT_KEY: key });
    assert.equal(calls[0].account, 'acc-acme');
    assert.deepEqual(calls[1].args, ['deploy', '-c', 'app/wrangler.jsonc']);
    assert.deepEqual(await new CloudflareApi(TOKEN, cloudflare.url).secretNames('acc-acme', 'coffre-vault'), ['VAULT_KEY']);
    writeFileSync(join(dir, '.state', 'fail-coffre'), '');
    await assert.rejects(deployWorker(wrangler, 'app/wrangler.jsonc', 'acc-acme', { APP_KEY: key }), (error: Error) => {
      assert.match(error.message, /wrangler could not deploy app\/wrangler\.jsonc: .*A request to the Cloudflare API failed/);
      assert.ok(!error.message.includes(key));
      return true;
    });
  } finally {
    process.env.CLOUDFLARE_API_BASE_URL = env;
    if (env === undefined) delete process.env.CLOUDFLARE_API_BASE_URL;
    cloudflare.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A Workers deployment with the fake wrangler, and an opener that only notes what it opens; all gone after the test. */
function signInSetup(t: { after: (fn: () => Promise<void>) => void }) {
  const dir = scratch();
  const state = join(dir, '.state');
  const opener = join(dir, '.bin');
  const path = process.env.PATH;
  const remove = () => {
    process.env.PATH = path;
    rmSync(dir, { recursive: true, force: true });
  };
  try {
    cpSync(templateDir('workers'), dir, { recursive: true, filter: (each) => !each.includes('node_modules') });
    fakeWrangler(dir, state, TOKEN);
    fakeOpener(opener);
    process.env.PATH = `${opener}:${path}`;
  } catch (error) {
    remove();
    throw error;
  }
  const terminal = fakeTerminal();
  const steps = new Steps(terminal.out, ['Sign in to Cloudflare'], () => terminal.keys, String);
  const printed: [string, string][] = [];
  const signing = steps.run(0, async (step) => (await cloudflareToken(deploymentWrangler(dir), step, (label, address) => printed.push([label, address])), 'Signed in'));
  // Settled one way or another by the end, by the test or by the Ctrl-C after it: never an unhandled rejection.
  signing.catch(() => {});
  // However the test ends: the sign-in cancelled and its wrangler stopped, and only then the directory gone.
  t.after(async () => {
    await settle(terminal.keys, signing, steps);
    remove();
  });
  const login = () =>
    until(() => (existsSync(join(state, 'login')) ? (JSON.parse(readFileSync(join(state, 'login'), 'utf8')) as { port: number; state: string }) : undefined));
  return { dir, state, opener, terminal, printed, signing, login };
}

/** Whether a process is still there. */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

test("Cloudflare sign-in: wrangler's login, finished by its callback pasted back, which setup fetches here; a foreign address is refused", LIMIT, async (t) => {
  const { state, opener, terminal, printed, signing, login } = signInSetup(t);
  const { port, state: nonce } = await login();
  await until(() => (terminal.drawn().includes('paste that address here') && printed.length > 0 ? true : undefined));
  assert.equal(printed[0]![0], 'If no browser opened, sign in to Cloudflare at');
  assert.match(printed[0]![1], /^https:\/\/dash\.cloudflare\.com\/oauth2\/auth\?/);
  // The opener runs on its own: what it was asked to open shows up when it does.
  const opened = await until(() => (existsSync(join(opener, 'opened')) ? readFileSync(join(opener, 'opened'), 'utf8') || undefined : undefined));
  assert.match(opened, /^https:\/\/dash\.cloudflare\.com\/oauth2\/auth\?/);

  await type(terminal.keys, `http://evil.example:${port}/oauth/callback?code=c0de&state=${nonce}\r`);
  await until(() => (terminal.drawn().includes('not a localhost address') ? true : undefined));
  await type(terminal.keys, `http://localhost:${port}/oauth/callback?code=c0de&state=${nonce}\r`);
  await signing;
  assert.ok(!terminal.drawn().includes('c0de'), 'the pasted address is never drawn');
  const calls = readFileSync(join(state, 'calls.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line).args.join(' '));
  assert.deepEqual(calls, ['auth token --json', 'login --browser=false', 'auth token --json']);
});

test('wrangler prints its link before it listens: an address pasted at once is tried again until it answers', LIMIT, async (t) => {
  const setup = signInSetup(t);
  writeFileSync(join(setup.state, 'listen-late'), '');
  const { port, state: nonce } = await setup.login();
  await until(() => (setup.terminal.drawn().includes('paste that address here') ? true : undefined));
  await type(setup.terminal.keys, `http://localhost:${port}/oauth/callback?code=c0de&state=${nonce}\r`);
  await setup.signing;
  assert.ok(!setup.terminal.drawn().includes('not answering'), 'it answered in time, and nobody was asked again');
});

test('wrangler not listening yet, two seconds on: the prompt says so, and takes the address again', LIMIT, async (t) => {
  const setup = signInSetup(t);
  writeFileSync(join(setup.state, 'listen-late'), '3000');
  const { port, state: nonce } = await setup.login();
  await until(() => (setup.terminal.drawn().includes('paste that address here') ? true : undefined));
  const address = `http://localhost:${port}/oauth/callback?code=c0de&state=${nonce}\r`;
  await type(setup.terminal.keys, address);
  await until(() => (setup.terminal.drawn().includes('wrangler is not answering at that address yet: paste it again in a moment') ? true : undefined));
  // Once it answers, the same address, again: the sign-in goes on.
  await new Promise((resolve) => setTimeout(resolve, 1_500));
  await type(setup.terminal.keys, address);
  await setup.signing;
});

test('Ctrl-C at the sign-in prompt cancels, and takes wrangler, still listening, with it', LIMIT, async (t) => {
  const { terminal, signing, login } = signInSetup(t);
  const { port } = await login();
  await until(() => (terminal.drawn().includes('paste that address here') ? true : undefined));
  const cancelled = assert.rejects(signing, Cancelled);
  await type(terminal.keys, '\x03');
  await cancelled;
  await assert.rejects(fetch(`http://localhost:${port}/oauth/callback`), 'nothing listens there any more');
});

test('wrangler stopped from outside, as at setup\'s exit: its login, still listening, goes', LIMIT, async (t) => {
  const { state, login } = signInSetup(t);
  const { port } = await login();
  const pid = Number(readFileSync(join(state, 'pid-login'), 'utf8'));
  assert.ok(alive(pid));
  stopWranglers();
  await until(() => (alive(pid) ? undefined : true));
  await assert.rejects(fetch(`http://localhost:${port}/oauth/callback`));
});

test('setup ended by a signal, as when its terminal closes: wrangler, in a session of its own, goes with it', LIMIT, async () => {
  const dir = scratch();
  let standIn: ChildProcess | undefined;
  try {
    cpSync(templateDir('workers'), dir, { recursive: true, filter: (each) => !each.includes('node_modules') });
    fakeWrangler(dir, join(dir, '.state'), TOKEN);
    // A process standing for setup: it starts wrangler's login, then waits, until a SIGHUP ends it.
    const cli = fileURLToPath(new URL('../src/cloudflare.ts', import.meta.url));
    standIn = spawn(
      process.execPath,
      ['--conditions=coffre:source', '--input-type=module', '-e', `import { deploymentWrangler } from ${JSON.stringify(cli)}; deploymentWrangler(${JSON.stringify(dir)})(['login', '--browser=false']); setInterval(() => {}, 1000);`],
      { stdio: 'ignore' },
    );
    const pid = await until(() => (existsSync(join(dir, '.state', 'pid-login')) ? Number(readFileSync(join(dir, '.state', 'pid-login'), 'utf8')) : undefined));
    await until(() => (existsSync(join(dir, '.state', 'login')) ? true : undefined));
    const exited = new Promise((resolve) => standIn!.on('exit', (exitCode) => resolve(exitCode)));
    standIn.kill('SIGHUP');
    assert.equal(await exited, 129);
    await until(() => (alive(pid) ? undefined : true));
  } finally {
    // A stand-in still up after a failure ends as setup would, its wrangler with it; then the directory.
    if (standIn !== undefined && standIn.exitCode === null && standIn.signalCode === null) {
      const gone = new Promise((resolve) => standIn!.once('exit', resolve));
      standIn.kill('SIGHUP');
      await Promise.race([gone, new Promise((resolve) => setTimeout(resolve, 5_000).unref())]);
      standIn.kill('SIGKILL');
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a deploy cancelled stops all of it: sh, cat and wrangler, its secrets with them', LIMIT, async () => {
  const dir = scratch();
  const stop = new AbortController();
  let deploying: Promise<unknown> = Promise.resolve();
  try {
    cpSync(templateDir('workers'), dir, { recursive: true, filter: (each) => !each.includes('node_modules') });
    fakeWrangler(dir, join(dir, '.state'), TOKEN);
    writeFileSync(join(dir, '.state', 'token'), TOKEN);
    writeFileSync(join(dir, '.state', 'slow'), '');
    deploying = deploymentWrangler(dir)(['deploy', '-c', 'vault/wrangler.jsonc', '--secrets-file', '/dev/stdin'], {
      input: JSON.stringify({ VAULT_KEY: 'K'.repeat(43) + '=' }),
      signal: stop.signal,
    });
    const pid = await until(() => (existsSync(join(dir, '.state', 'pid-deploy')) ? Number(readFileSync(join(dir, '.state', 'pid-deploy'), 'utf8')) : undefined));
    stop.abort();
    await deploying;
    await until(() => (alive(pid) ? undefined : true));
  } finally {
    // Cancelled, and awaited, before its directory goes, whatever happened above.
    stop.abort();
    await Promise.race([deploying.catch(() => {}), new Promise((resolve) => setTimeout(resolve, 5_000).unref())]);
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- GitHub ------------------------------------------------------------------------------------

test("the GitHub App's manifest: named for the address, private, coffre's callback, emails only, no webhook", () => {
  assert.equal(appName('secrets.erwinkn.com'), 'coffre-secrets-erwinkn-com');
  assert.equal(appName('a-very-long-subdomain.of.an-even-longer.example.com').length, 34);
  assert.ok(!appName('abcdefghijklmnopqrstuvwxyz.ab-c.example').endsWith('-'));
  assert.deepEqual(appManifest('https://secrets.acme.test', 'http://127.0.0.1:5000/created'), {
    name: 'coffre-secrets-acme-test',
    url: 'https://secrets.acme.test',
    redirect_url: 'http://127.0.0.1:5000/created',
    callback_urls: ['https://secrets.acme.test/auth/callback/github'],
    public: false,
    default_permissions: { emails: 'read' },
    hook_attributes: { url: 'https://secrets.acme.test', active: false },
  });
});

test('the page and the data: address post the same manifest, to GitHub and nowhere else', () => {
  const github = { web: 'https://github.com', api: 'https://api.github.com' };
  const manifest = appManifest('https://secrets.acme.test', 'http://127.0.0.1:5000/created');
  for (const html of [manifestPage(github, manifest, 'st4te'), decodeURIComponent(manifestAddress(github, manifest, 'st4te').slice('data:text/html,'.length))]) {
    const form = manifestForm(html);
    assert.equal(form.action, 'https://github.com/settings/apps/new?state=st4te');
    assert.deepEqual(JSON.parse(form.manifest), manifest);
    assert.equal([...html.matchAll(/https?:\/\/[^\s"'<]+/g)].filter(([url]) => !url.startsWith('https://github.com/') && !url.includes('acme.test') && !url.startsWith('http://127.0.0.1:5000/')).length, 0);
  }
  const address = manifestAddress(github, manifest, 'st4te');
  assert.match(address, /^data:text\/html,<form%20method=post%20action="https:\/\/github\.com\/settings\/apps\/new\?state=st4te">/);
  assert.match(address, /"callback_urls":\["https:\/\/secrets\.acme\.test\/auth\/callback\/github"\]/, 'readable as it is');
  assert.ok(!/\s/.test(address), 'one word, to paste whole');
  assert.ok(address.length < 700, `short enough to copy: ${address.length}`);
});

test("a manifest's code converts once, into the client ID and secret; the private key is dropped", LIMIT, async () => {
  const fake = await fakeGitHub();
  try {
    const page = manifestPage(fake.github, appManifest('https://secrets.acme.test', 'http://127.0.0.1:1/created'), 's');
    const code = new URL(await submitManifest(page)).searchParams.get('code')!;
    const app = await convert(fake.github, code);
    assert.deepEqual(Object.keys(app).sort(), ['clientId', 'clientSecret', 'slug', 'url']);
    assert.equal(app.slug, 'coffre-secrets-acme-test');
    await assert.rejects(convert(fake.github, code), /GitHub answered 404: Not Found/);
  } finally {
    fake.close();
  }
});

for (const road of ['the browser here', 'the address pasted back'] as const) {
  test(`the GitHub App, made through ${road}; an address from another run is refused`, LIMIT, async () => {
    const fake = await fakeGitHub();
    const dir = scratch();
    const path = process.env.PATH;
    const terminal = fakeTerminal();
    const steps = new Steps(terminal.out, ["Make coffre's GitHub App"], () => terminal.keys, String);
    let making: Promise<void> = Promise.resolve();
    try {
      fakeOpener(dir);
      process.env.PATH = `${dir}:${path}`;
      const printed: [string, string][] = [];
      const asides: string[] = [];
      let app: { clientId: string; clientSecret: string } | null = null;
      making = steps.run(0, async (step) => {
        const say = { aside: (text: string) => asides.push(text), link: (label: string, address: string) => printed.push([label, address]) };
        app = await createGitHubApp(step, say, fake.github, 'https://secrets.acme.test');
        return 'Made';
      });
      const here = await until(() => (existsSync(join(dir, 'opened')) ? readFileSync(join(dir, 'opened'), 'utf8').trim() || undefined : undefined));
      assert.match(here, /^http:\/\/127\.0\.0\.1:\d+\/$/);
      assert.deepEqual(asides, ["coffre's GitHub App may read the email addresses of whoever signs in with it, and nothing else."], 'said before the browser opens');
      assert.deepEqual(printed[0], ['If no browser opened, create it at', here]);
      assert.match(printed[1]![1], /^data:text\/html,/);
      await until(() => (terminal.drawn().includes('paste that address here') ? true : undefined));
      if (road === 'the browser here') {
        const back = await submitManifest(await (await fetch(here)).text());
        const done = await fetch(back);
        assert.equal(done.status, 200);
        assert.match(await done.text(), /coffre's GitHub App is made/);
      } else {
        // A browser elsewhere: the data: address, then GitHub's way back, which fails there, pasted here.
        const data = printed[1]![1];
        const back = new URL(await submitManifest(decodeURIComponent(data.slice('data:text/html,'.length))));
        const other = new URL(back.href);
        other.searchParams.set('state', 'another-run');
        await type(terminal.keys, `${other.href}\r`);
        await until(() => (terminal.drawn().includes('from another run of setup') ? true : undefined));
        back.hostname = 'localhost';
        await type(terminal.keys, `${back.href}\r`);
      }
      await making;
      assert.equal(fake.state.manifests.length, 1);
      assert.match(app!.clientId, /^Iv23li/);
      assert.ok(!terminal.drawn().includes(app!.clientSecret), 'the secret is never drawn');
      assert.ok(!terminal.drawn().includes('code='), 'nor the code');
      await assert.rejects(fetch(here), 'the page is gone once the app is made');
    } finally {
      // Cancelled first, its page closed with it; then the rest.
      await settle(terminal.keys, making, steps);
      process.env.PATH = path;
      fake.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
