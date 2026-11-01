// `coffre verify`: the keys held to check material made as the vault makes
// it; what the CLI sends while it checks them, which is never a key; the
// session `coffre login` made, used and left signed in; and the choice of
// check, on a terminal and off one. The real instance's side is the server's
// tests, and conformance, which runs this CLI against a deployment.
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { appLogKeyId, KEY_CHECK_CONTEXT, KEY_CHECK_VALUE, LocalKekProvider } from '@coffre/core/kek';

import { signInError } from '../src/instance.ts';
import { Failure, Skip } from '../src/verify/checks.ts';
import { appKeyVerdict, vaultKeyVerdict, type KeyMaterial } from '../src/verify/keys.ts';
import { inTerminal, ptySkip, visible } from './pty.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

const CURRENT = 'vault-2026-10-03-bbbbbb';
const PREVIOUS = 'vault-2025-01-10-aaaaaa';
const keys = { current: randomBytes(32), previous: randomBytes(32), app: randomBytes(32) };

/** A key's check, as the vault writes it in a `key.check` entry and the instance gives it. */
async function checkOf(key: Buffer, vaultId: string, seq: number): Promise<KeyMaterial['vault']['checks'][number]> {
  const wrapped = await new LocalKekProvider(key, vaultId).wrap(Buffer.from(KEY_CHECK_VALUE), KEY_CHECK_CONTEXT);
  return { seq, vaultId, provider: 'local', version: wrapped.kekVersion, wrapped: wrapped.bytes.toString('base64') };
}

/** What an instance rotated once gives: the app key's id, the current vault key, and both keys' checks, newest first. */
const material: KeyMaterial = {
  app: { keyId: appLogKeyId(keys.app) },
  vault: {
    current: { vaultId: CURRENT, provider: 'local' },
    checks: [await checkOf(keys.current, CURRENT, 41), await checkOf(keys.previous, PREVIOUS, 2)],
  },
};

const b64 = (key: Buffer) => key.toString('base64');

/** What a verdict threw: its kind, and its line. */
async function refusal(verdict: () => unknown): Promise<string> {
  try {
    await verdict();
  } catch (error) {
    if (error instanceof Failure) return `✗ ${error.message}`;
    if (error instanceof Skip) return `– ${error.message}`;
    throw error;
  }
  assert.fail('the key passed');
}

test('the vault key: the current one passes, with its vault ID; a previous one is named as such; another fails', async () => {
  assert.equal(await vaultKeyVerdict(b64(keys.current), material.vault), `the current one, vault ID ${CURRENT}`);
  assert.equal(await vaultKeyVerdict(b64(keys.current), material.vault, CURRENT), `the current one, vault ID ${CURRENT}, as given`);
  assert.equal(
    await refusal(() => vaultKeyVerdict(b64(keys.current), material.vault, PREVIOUS)),
    `✗ the key is right, but its vault ID is ${CURRENT}, not ${PREVIOUS}: keep the right one with it`,
  );
  assert.equal(
    await refusal(() => vaultKeyVerdict(b64(keys.previous), material.vault)),
    `✗ this is a previous vault key (vault ID ${PREVIOUS}), not the current one: the vault wraps under vault ID ${CURRENT}`,
  );
  assert.equal(
    await refusal(() => vaultKeyVerdict(b64(randomBytes(32)), material.vault)),
    `✗ not this instance's vault key: it opens none of the checks of its 2 vault keys, current or replaced. The vault wraps under vault ID ${CURRENT}`,
  );
  // The app key is no vault key, though of the same shape.
  assert.match(await refusal(() => vaultKeyVerdict(b64(keys.app), material.vault)), /^✗ not this instance's vault key/);
});

test('a vault that moved to a key service: the local key it replaced is named as previous', async () => {
  const moved: KeyMaterial['vault'] = {
    current: { vaultId: 'arn:aws:kms:eu-west-1:111122223333:key/coffre', provider: 'aws-kms' },
    checks: [{ seq: 50, vaultId: 'arn:aws:kms:eu-west-1:111122223333:key/coffre', provider: 'aws-kms', version: '1', wrapped: b64(randomBytes(184)) }, material.vault.checks[0]!],
  };
  assert.match(await refusal(() => vaultKeyVerdict(b64(keys.current), moved)), /^✗ this is a previous vault key \(vault ID vault-2026-10-03-bbbbbb\), not the current one: the vault wraps under arn:\S+, in aws-kms$/);
});

test('the app key: the one the app signs with passes; another fails; neither key is in what is said', async () => {
  assert.equal(appKeyVerdict(b64(keys.app), material.app), 'the one the app signs with now');
  assert.equal(await refusal(() => appKeyVerdict(b64(keys.current), material.app)), "✗ not this instance's app key: the app signs with another");
  // One the app replaced, kept to verify the log: said, and still not the one to escrow as current.
  const replaced = { ...material.app, previous: [appLogKeyId(keys.current)] };
  assert.equal(await refusal(() => appKeyVerdict(b64(keys.current), replaced)), `✗ this is a previous app key (${appLogKeyId(keys.current)}), not the current one: the app signs with ${material.app.keyId}`);
});

test('a malformed key is said to be one, without being shown; an empty answer skips the key', async () => {
  const text = b64(keys.current);
  for (const malformed of [text.slice(1), keys.current.toString('hex'), 'hunter2', `${text}${text}`]) {
    for (const said of [await refusal(() => vaultKeyVerdict(malformed, material.vault)), await refusal(() => appKeyVerdict(malformed, material.app))]) {
      assert.match(said, /^✗ not an? (vault|app) key: one is 32 bytes in base64, 44 characters, and these \d+ characters are not$/);
      assert.ok(!said.includes(malformed));
    }
  }
  assert.equal(await refusal(() => vaultKeyVerdict('', material.vault)), '– not given: not checked');
  assert.equal(await refusal(() => appKeyVerdict('', material.app)), '– not given: not checked');
});

// --- the command, against an instance that records what it is sent ---------------

type Seen = { method: string; url: string; headers: IncomingMessage['headers']; body: string };

const SESSION = `coffre_cli_${'s'.repeat(43)}`;

/** An instance that answers `answer` for a call with the session, 401 for one without, and keeps every request. */
async function fakeInstance(t: test.TestContext, answer: (method: string, path: string) => unknown) {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8').on('data', (chunk: string) => (body += chunk));
    req.on('end', () => {
      seen.push({ method: req.method!, url: req.url!, headers: req.headers, body });
      const signedIn = req.headers.authorization === `Bearer ${SESSION}`;
      const value = signedIn ? answer(req.method!, req.url!.replace(/\?.*/, '')) : undefined;
      res.writeHead(value === undefined ? (signedIn ? 404 : 401) : 200, { 'content-type': 'application/json' }).end(JSON.stringify(value ?? { error: 'no' }));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  const address = server.address();
  assert.ok(address !== null && typeof address !== 'string');
  return { origin: `http://127.0.0.1:${address.port}`, seen };
}

/** A home where `coffre login` signed in to `origin`. */
function signedInHome(t: test.TestContext, origin: string): { home: string; store: () => string } {
  const home = mkdtempSync(join(tmpdir(), 'coffre-verify-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  mkdirSync(join(home, '.coffre'), { mode: 0o700 });
  const file = join(home, '.coffre', 'credentials.json');
  const session = { mode: 'signin', token: SESSION, principal: { type: 'user', id: 'root@acme.example' }, expiresAt: '2099-01-01T00:00:00Z', obtainedAt: '2026-10-03T00:00:00Z' };
  writeFileSync(file, JSON.stringify({ version: 2, current: origin, instances: { [origin]: session } }));
  chmodSync(file, 0o600);
  return { home, store: () => readFileSync(file, 'utf8') };
}

/** `coffre <args>` off a terminal, `input` on its stdin. */
async function coffre(args: string[], home: string, input = '', env: NodeJS.ProcessEnv = {}, cwd?: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, ...args], { cwd, env: { ...clean, HOME: home, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  child.stdin.end(input);
  const [code] = (await once(child, 'close')) as [number | null];
  return { code, stdout, stderr };
}

/** Every form a key could be sent in. */
const forms = (key: Buffer) => [key.toString('base64'), key.toString('base64url'), key.toString('hex'), encodeURIComponent(key.toString('base64'))];

test('coffre verify keys reads what the keys are checked against, and sends nothing else: no key, in any form', async (t) => {
  const instance = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/audit/keys' ? material : undefined));
  const { home } = signedInHome(t, instance.origin);

  // On stdin, as a script pipes them: the vault key's line, then the app key's.
  const right = await coffre(['verify', 'keys'], home, `${b64(keys.current)}\n${b64(keys.app)}\n`);
  assert.equal(right.code, 0, right.stderr);
  assert.match(right.stdout, /✓ vault key +the current one, vault ID vault-2026-10-03-bbbbbb \(from stdin\)/);
  assert.match(right.stdout, /✓ app key +the one the app signs with now \(from stdin\)/);
  assert.match(right.stdout, new RegExp(`Both keys are ${instance.origin}'s\\.`));

  const previous = await coffre(['verify', 'keys'], home, `${b64(keys.previous)}\n${b64(randomBytes(32))}\n`);
  assert.equal(previous.code, 1);
  assert.match(previous.stdout, /✗ vault key +this is a previous vault key \(vault ID vault-2025-01-10-aaaaaa\), not the current one: .* \(from stdin\)/);
  assert.match(previous.stdout, /✗ app key +not this instance's app key: the app signs with another \(from stdin\)/);
  assert.match(previous.stdout, /Neither key is /);

  // One key alone, a blank line for the other: that one skipped, not failed.
  const one = await coffre(['verify', 'keys'], home, `\n${b64(keys.app)}\n`);
  assert.equal(one.code, 0);
  assert.match(one.stdout, /– vault key +not given: not checked/);
  assert.match(one.stdout, /The app key is /);
  const none = await coffre(['verify', 'keys'], home, '\n\n');
  assert.equal(none.code, 1);
  assert.match(none.stdout, /No key given: nothing checked/);

  assert.deepEqual(new Set(instance.seen.map(({ method, url }) => `${method} ${url}`)), new Set(['GET /api/audit/keys']));
  const sent = JSON.stringify(instance.seen);
  for (const key of Object.values(keys)) for (const form of forms(key)) assert.ok(!sent.includes(form), 'a key was sent');
  for (const run of [right, previous, one]) for (const key of Object.values(keys)) assert.ok(!(run.stdout + run.stderr).includes(b64(key)), 'a key was printed');
});

test('coffre verify keys is refused before any key is asked for, for someone who may not read the checks', async (t) => {
  const instance = await fakeInstance(t, () => undefined);
  const { home } = signedInHome(t, instance.origin);
  const run = await coffre(['verify', 'keys'], home, `${b64(keys.current)}\n`);
  assert.equal(run.code, 1);
  assert.match(run.stderr, /^coffre: not found/);
  assert.equal(run.stdout, '');
});

for (const role of ['user', 'owner'] as const) {
  test(`coffre verify instance, as a ${role}, uses the session coffre login made, and leaves it signed in`, async (t) => {
    const me = { principal: { type: 'user', id: 'root@acme.example' }, registered: true, tampered: false, instanceRole: role === 'user' ? 'member' : role, runsInstance: role !== 'user', canReadAudit: true, environments: [] };
    const instance = await fakeInstance(t, (method, path) =>
      method === 'GET' && path === '/api/me' ? me : method === 'GET' && path === '/api/audit/verification' ? { ok: true, entries: 12, through: 11, checkpoint: null } : undefined,
    );
    const { home, store } = signedInHome(t, instance.origin);
    const before = store();
    const run = await coffre(['verify', 'instance', instance.origin, '--yes'], home);
    // A stand-in for an instance fails the anonymous checks; what matters here is what is done with the session.
    assert.equal(run.code, 1);
    if (role === 'user') {
      assert.match(run.stdout, /✗ owner +root@acme\.example is not an admin or owner of all of http:\/\/127\.0\.0\.1:\d+: nothing was made/);
      assert.doesNotMatch(run.stdout, /setup|clean-up/);
    } else {
      assert.match(run.stdout, /✓ owner +root@acme\.example, an owner, with this CLI's session/);
      assert.match(run.stdout, /✓ owner verification +the whole chain verifies, as you: 12 entries, through entry 11/);
      assert.match(run.stdout, /✓ clean-up +nothing issued; your session stays/);
    }
    const signed = instance.seen.filter(({ headers }) => headers.authorization !== undefined);
    assert.ok(signed.length > 0);
    assert.ok(signed.every(({ headers }) => headers.authorization === `Bearer ${SESSION}`), 'another credential');
    // No second sign-in, and the session never ended: nothing at /api/auth but the anonymous look at how to sign in.
    assert.deepEqual([...new Set(instance.seen.filter(({ url }) => url.startsWith('/api/auth')).map(({ method, url }) => `${method} ${url}`))], ['GET /api/auth']);
    assert.ok(!instance.seen.some(({ method, url }) => method === 'DELETE' && url.startsWith('/api/sessions')));
    assert.equal(store(), before);
    assert.ok(!(run.stdout + run.stderr).includes(SESSION));
  });
}

// --- which instance verify instance writes to (T181) ---------------------------------

/** A home with a session on each of `origins`, the first the default. */
function homeWithSessions(t: test.TestContext, origins: string[]): { home: string; store: () => string } {
  const { home, store } = signedInHome(t, origins[0]!);
  const file = join(home, '.coffre', 'credentials.json');
  const kept = JSON.parse(readFileSync(file, 'utf8')) as { instances: Record<string, unknown> };
  for (const origin of origins) kept.instances[origin] = kept.instances[origins[0]!];
  writeFileSync(file, JSON.stringify({ version: 2, current: origins[0], instances: kept.instances }));
  return { home, store };
}

/** A Workers deployment's directory, whose app names `url` as PUBLIC_URL; a `coffre.json` too when `file` is given. */
function deployment(t: test.TestContext, url: string, file?: string): string {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'coffre-deployment-')));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const worker of ['app', 'vault']) {
    mkdirSync(join(dir, worker, 'src'), { recursive: true });
    writeFileSync(join(dir, worker, 'wrangler.jsonc'), `{ // the deployment's own\n  "name": "${worker}", "vars": { "PUBLIC_URL": ${JSON.stringify(url)} }\n}\n`);
  }
  if (file !== undefined) writeFileSync(join(dir, 'coffre.json'), JSON.stringify({ url: file }));
  return dir;
}

const OWNER = { principal: { type: 'user', id: 'root@acme.example' }, registered: true, tampered: false, instanceRole: 'member', runsInstance: false, canReadAudit: true, environments: [] };

test("coffre verify instance in a deployment's directory never takes the default session's instance for the deployment's own", async (t) => {
  const other = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/me' ? OWNER : undefined));
  // The default session is for `other`; the deployment names another instance, that this home has no session for.
  const { home, store } = signedInHome(t, other.origin);
  const before = store();
  const dir = deployment(t, 'https://coffre.deployed.test');
  for (const args of [['verify', 'instance'], ['verify', 'instance', '--yes'], ['verify', 'instance']]) {
    const run = await coffre(args, home, '', {}, dir);
    assert.equal(run.code, 1);
    assert.equal(run.stdout, '');
    assert.match(run.stderr, /^coffre: not signed in: run `coffre login https:\/\/coffre\.deployed\.test` first \(.*app\/wrangler\.jsonc names it, as PUBLIC_URL\)/);
    assert.equal(other.seen.length, 0, 'a request went to the default instance');
  }
  // A token login that fails just before it does not change that: no fallback to the saved session.
  const failed = await coffre(['login', other.origin, '--token'], home, 'coffre_pat_wrong\n', {}, dir);
  assert.notEqual(failed.code, 0);
  other.seen.length = 0;
  const after = await coffre(['verify', 'instance', '--yes'], home, '', {}, dir);
  assert.equal(after.code, 1);
  assert.equal(other.seen.length, 0);
  assert.equal(store(), before);
});

test('coffre verify instance with nothing naming an instance refuses, however many sessions are saved, and sends nothing', async (t) => {
  const instance = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/me' ? OWNER : undefined));
  const { home, store } = signedInHome(t, instance.origin);
  const before = store();
  const dir = mkdtempSync(join(tmpdir(), 'coffre-nowhere-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const args of [['verify', 'instance'], ['verify', 'instance', '--yes']]) {
    const run = await coffre(args, home, '', {}, dir);
    assert.equal(run.code, 2);
    assert.equal(run.stdout, '');
    assert.match(run.stderr, /^coffre: verify instance creates a project, an environment, a service account, grants and a secret on the instance it checks/);
    assert.ok(run.stderr.includes(`The default session, ${instance.origin}, is not used unasked.`), run.stderr);
  }
  assert.equal(instance.seen.length, 0);
  assert.equal(store(), before);
});

test("a deployment's PUBLIC_URL and a coffre.json that disagree are refused, not picked between", async (t) => {
  const instance = await fakeInstance(t, () => undefined);
  const { home } = signedInHome(t, instance.origin);
  const dir = deployment(t, instance.origin, 'https://coffre.elsewhere.test');
  const run = await coffre(['verify', 'instance', '--yes'], home, '', {}, dir);
  assert.equal(run.code, 2);
  assert.match(run.stderr, /names it \(https:\/\/coffre\.elsewhere\.test\), but .*app\/wrangler\.jsonc names it, as PUBLIC_URL \(http:\/\/127\.0\.0\.1:\d+\): name the one you mean/);
  assert.equal(instance.seen.length, 0);
});

test("a deployment's config that cannot be read is an error, not a reason to go on with a coffre.json's instance", async (t) => {
  const instance = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/me' ? OWNER : undefined));
  const { home } = signedInHome(t, instance.origin);
  const dir = deployment(t, 'https://coffre.deployed.test', instance.origin);
  const file = join(dir, 'app', 'wrangler.jsonc');
  for (const broken of ['{ "name": "app", "vars": { "PUBLIC_URL": ', '{ "name": "app", "vars": { "PUBLIC_URL": "https://coffre.deployed.test/path" } }']) {
    writeFileSync(file, broken);
    const run = await coffre(['verify', 'instance', '--yes'], home, '', {}, dir);
    assert.equal(run.code, 1);
    assert.equal(run.stdout, '');
    assert.ok(run.stderr.startsWith(`coffre: cannot use ${file}: `), run.stderr);
    assert.equal(instance.seen.length, 0);
  }
});

test("coffre verify instance in a deployment's directory goes to the deployment's instance, with its session, once confirmed with --yes", async (t) => {
  const deployed = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/me' ? OWNER : undefined));
  const other = await fakeInstance(t, () => undefined);
  const { home } = homeWithSessions(t, [other.origin, deployed.origin]);
  const run = await coffre(['verify', 'instance', '--yes'], home, '', {}, deployment(t, deployed.origin));
  assert.match(run.stdout, new RegExp(`^Writes to ${deployed.origin.replace(/[.]/g, '\\.')} \\(.*app/wrangler\\.jsonc names it, as PUBLIC_URL\\)\nSigned in as root@acme\\.example`));
  assert.match(run.stdout, /--yes: going on\./);
  assert.ok(deployed.seen.length > 0);
  assert.equal(other.seen.length, 0, 'a request went to the default instance');
});

test('coffre verify instance <url> without a terminal or --yes says who and where, then refuses, having sent nothing', async (t) => {
  const instance = await fakeInstance(t, () => undefined);
  const { home, store } = signedInHome(t, instance.origin);
  const before = store();
  for (const args of [['verify', 'instance', instance.origin], ['--url', instance.origin, 'verify', 'instance']]) {
    const run = await coffre(args, home);
    assert.equal(run.code, 2);
    assert.match(run.stdout, new RegExp(`^Writes to ${instance.origin.replace(/[.]/g, '\\.')} \\(named on the command line\\)\nSigned in as root@acme\\.example, with this CLI's session\n`));
    assert.match(run.stderr, /^coffre: not on a terminal to ask: nothing was sent to http:\/\/127\.0\.0\.1:\d+\. Run it again with --yes to write there\n$/);
    assert.equal(instance.seen.length, 0);
  }
  assert.equal(store(), before);
});

test('coffre verify instance, on a terminal, asks before it writes: no, or Enter, sends nothing; y goes on', { skip: ptySkip }, async (t) => {
  const instance = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/me' ? OWNER : undefined));
  const { home } = signedInHome(t, instance.origin);
  for (const key of ['n', '\r']) {
    const { output, code } = await inTerminal(['verify', 'instance', instance.origin], { ...cleanEnv(), HOME: home }, async (terminal) => {
      await terminal.waitFor('y/N');
      terminal.send(key);
      await terminal.waitFor('not confirmed');
    });
    assert.equal(code, 1);
    assert.match(visible(output), /Write to http:\/\/127\.0\.0\.1:\d+\? y\/N/);
    assert.equal(instance.seen.length, 0);
  }
  const { output, code } = await inTerminal(['verify', 'instance', instance.origin], { ...cleanEnv(), HOME: home }, async (terminal) => {
    await terminal.waitFor('y/N');
    terminal.send('y');
    await terminal.waitFor('is not an admin or owner');
  });
  assert.equal(code, 1);
  assert.match(visible(output), /Checking http:\/\/127\.0\.0\.1:\d+, as no one, then as you/);
  assert.ok(instance.seen.length > 0);
});

test('coffre verify instance without a session says to sign in first, and checks nothing', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-verify-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const elsewhere = await coffre(['verify', 'instance', 'https://coffre.acme.example'], home);
  assert.equal(elsewhere.code, 1);
  assert.equal(elsewhere.stderr, `coffre: ${signInError('not signed in: run `coffre login https://coffre.acme.example` first')}\n`);
  // Named a sign-in instance by --auth-mode, it is not hedged about Access.
  const named = await coffre(['--auth-mode', 'signin', 'verify', 'instance', 'https://coffre.acme.example'], home);
  assert.equal(named.stderr, `coffre: ${signInError('not signed in: run `coffre login https://coffre.acme.example` first', 'signin')}\n`);
  const access = await coffre(['--auth-mode', 'cloudflare', 'verify', 'instance', 'https://coffre.acme.example'], home);
  assert.equal(access.stderr, 'coffre: not signed in: run `coffre login https://coffre.acme.example` first\n', 'Access signs in with cloudflared: no code to explain');
  // Without a name, nothing is chosen for it, signed in anywhere or not.
  const noUrl = await coffre(['--auth-mode', 'signin', 'verify', 'instance'], home);
  assert.equal(noUrl.code, 2);
  assert.match(noUrl.stderr, /^coffre: verify instance creates a project/);
  assert.equal(elsewhere.stdout + named.stdout + access.stdout + noUrl.stdout, '');
});

test("coffre verify log holds the reads listed to the uses sealed, a stretch a request, after the chain: OK, or BROKEN with each problem (T166)", async (t) => {
  const chain = { ok: true, entries: 12, through: 11, checkpoint: null, remaining: 0 };
  const cases: [Record<string, unknown>, number, RegExp][] = [
    [{ start: { kept: true, ok: true, problems: [], through: '40', listed: '90', next: '40' }, 40: { kept: true, ok: true, problems: [], through: '90', listed: '90', next: null } }, 0, /reads OK: every read sealed through entry 90 listed as the log sealed it/],
    [{ start: { kept: true, ok: false, problems: ['read 7 is sealed but not listed'], through: '40', listed: '90', next: '40' } }, 2, /reads BROKEN, found by the vault's check \(verified through entry 40\):\n {2}read 7 is sealed but not listed/],
    // An instance before 0.15: no such route, and nothing more said.
    [{}, 0, /^$/],
  ];
  for (const [stretches, code, said] of cases) {
    let seen: { url: string }[] = [];
    const instance = await fakeInstance(t, (method, path) => {
      if (method !== 'GET') return undefined;
      if (path === '/api/audit/verification') return chain;
      if (path !== '/api/audit/reads') return undefined;
      return stretches[new URL(seen.at(-1)!.url, 'http://x').searchParams.get('from')!];
    });
    seen = instance.seen;
    const { home } = signedInHome(t, instance.origin);
    const run = await coffre(['verify', 'log'], home);
    assert.equal(run.code, code, run.stderr);
    assert.match(code === 0 ? run.stdout.split('\n').slice(2).join('\n') : run.stderr, said);
    assert.match(run.stdout, /^audit log OK: verified from the first entry through entry 11, 12 entries/);
  }
});

test('coffre verify alone, without a terminal, lists the checks and exits 2', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-verify-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const run = await coffre(['verify'], home);
  assert.equal(run.code, 2);
  assert.equal(run.stdout, '');
  assert.match(run.stderr, /^usage: coffre verify instance \| keys \| log \| backup <dump>\n\n {2}instance {2}.+\n {2}keys {6}.+\n {2}log {7}.+\n {2}backup {4}.+\n/);
});

test('coffre verify alone, on a terminal, asks which check, and runs the one chosen', { skip: ptySkip }, async (t) => {
  const instance = await fakeInstance(t, (method, path) =>
    method === 'GET' && path === '/api/audit/verification' ? { ok: true, entries: 12, through: 11, checkpoint: null } : undefined,
  );
  const { home } = signedInHome(t, instance.origin);
  const { output, code } = await inTerminal(['verify'], { ...cleanEnv(), HOME: home }, async (terminal) => {
    await terminal.waitFor('Which check?');
    await terminal.waitFor('log');
    terminal.send('\x1b[B');
    terminal.send('\x1b[B');
    terminal.send('\r');
    await terminal.waitFor('audit log OK');
  });
  assert.equal(code, 0);
  const shown = visible(output);
  assert.match(shown, /✓ Which check\? {2}log {7}the whole audit log, as you, an owner/);
  assert.match(shown, /audit log OK: verified from the first entry through entry 11, 12 entries/);
});

test('coffre verify keys, on a terminal, asks for each key without showing it', { skip: ptySkip }, async (t) => {
  const instance = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/audit/keys' ? material : undefined));
  const { home } = signedInHome(t, instance.origin);
  const { output, code } = await inTerminal(['verify', 'keys'], { ...cleanEnv(), HOME: home }, async (terminal) => {
    await terminal.waitFor('Vault key?');
    terminal.send(`${b64(keys.previous)}\r`);
    await terminal.waitFor('App key?');
    terminal.send(`${b64(keys.app)}\r`);
    await terminal.waitFor('is not');
  });
  assert.equal(code, 1);
  const shown = visible(output);
  assert.match(shown, /•{44} {2}44 characters/);
  assert.match(shown, /✗ vault key +this is a previous vault key \(vault ID vault-2025-01-10-aaaaaa\), not the current one/);
  assert.match(shown, /✓ app key +the one the app signs with now\r?\n/);
  for (const key of Object.values(keys)) for (const form of forms(key)) assert.ok(!output.includes(form), 'a key was shown');
});

/** This process's environment without its COFFRE_ variables, which would pick another instance or credential. */
function cleanEnv(): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));
}
