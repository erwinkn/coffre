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
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { appLogKeyId, KEY_CHECK_CONTEXT, KEY_CHECK_VALUE, LocalKekProvider } from '@coffre/core/kek';

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
async function coffre(args: string[], home: string, input = '', env: NodeJS.ProcessEnv = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, ...args], { env: { ...clean, HOME: home, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
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

for (const role of ['user', 'root-admin'] as const) {
  test(`coffre verify instance, as a ${role}, uses the session coffre login made, and leaves it signed in`, async (t) => {
    const me = { principal: { type: 'user', id: 'root@acme.example' }, registered: true, tampered: false, instanceRole: role, isRootAdmin: role !== 'user', runsInstance: role !== 'user', canReadAudit: true, environments: [] };
    const instance = await fakeInstance(t, (method, path) =>
      method === 'GET' && path === '/api/me' ? me : method === 'GET' && path === '/api/audit/verification' ? { ok: true, entries: 12, through: 11, checkpoint: null } : undefined,
    );
    const { home, store } = signedInHome(t, instance.origin);
    const before = store();
    const run = await coffre(['verify', 'instance'], home);
    // A stand-in for an instance fails the anonymous checks; what matters here is what is done with the session.
    assert.equal(run.code, 1);
    if (role === 'user') {
      assert.match(run.stdout, /✗ owner +root@acme\.example is not an admin or owner of all of http:\/\/127\.0\.0\.1:\d+, nor a root admin: nothing was made/);
      assert.doesNotMatch(run.stdout, /setup|clean-up/);
    } else {
      assert.match(run.stdout, /✓ owner +root@acme\.example, a root admin, with this CLI's session/);
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

test('coffre verify instance without a session says to sign in first, and checks nothing', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-verify-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const nowhere = await coffre(['verify', 'instance'], home);
  assert.equal(nowhere.code, 1);
  assert.equal(nowhere.stderr, 'coffre: not signed in anywhere yet: run `coffre login <url>` first\n');
  const elsewhere = await coffre(['verify', 'instance', 'https://coffre.acme.example'], home);
  assert.equal(elsewhere.code, 1);
  assert.equal(elsewhere.stderr, 'coffre: not signed in to https://coffre.acme.example: run `coffre login https://coffre.acme.example` first\n');
  assert.equal(nowhere.stdout + elsewhere.stdout, '');
});

test('coffre verify alone, without a terminal, lists the checks and exits 2', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-verify-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const run = await coffre(['verify'], home);
  assert.equal(run.code, 2);
  assert.equal(run.stdout, '');
  assert.match(run.stderr, /^usage: coffre verify instance \| keys \| log\n\n {2}instance {2}.+\n {2}keys {6}.+\n {2}log {7}.+\n/);
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
  assert.match(shown, /audit log OK: verified through entry 11, 12 entries/);
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
