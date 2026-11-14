// `coffre verify`: a key held to the checks the vault answers in `about`,
// made as it makes them; what the CLI sends while it checks one, which is
// never a key; the
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

import { derivedSigningKey, keyCheckOf } from '@coffre/core/kek';

import { LOG_GONE } from '../src/backup-help.ts';
import { browsersOnly, signInError } from '../src/instance.ts';
import { Failure, Skip } from '../src/verify/checks.ts';
import { keyVerdict, type KeyMaterial } from '../src/verify/keys.ts';
import { tokenReveal } from '../src/verify/token.ts';
import { inTerminal, ptySkip, visible } from './pty.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

const CURRENT = 'vault-2026-10-03-bbbbbb';
const PREVIOUS = 'vault-2025-01-10-aaaaaa';
const keys = { current: randomBytes(32), previous: randomBytes(32), signing: randomBytes(32) };

/** What an instance rotated once answers, as `about` makes it: both local vault keys, and the checks of the signing keys they stand for, the current first. */
const material: KeyMaterial = {
  kek: { provider: 'local', id: CURRENT },
  previous: [{ provider: 'local', id: PREVIOUS }],
  checks: [keyCheckOf(derivedSigningKey(keys.current)), keyCheckOf(derivedSigningKey(keys.previous))],
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

test('a local vault key: the current one passes, its vault ID shown, or compared when given; a previous one is named as such; another fails', async () => {
  assert.equal(keyVerdict(b64(keys.current), material), `the vault key the vault signs with now; it wraps under vault ID ${CURRENT}`);
  assert.equal(keyVerdict(b64(keys.current), material, CURRENT), `the vault key the vault signs with now; it wraps under vault ID ${CURRENT}, as given`);
  assert.equal(
    await refusal(() => keyVerdict(b64(keys.current), material, PREVIOUS)),
    `✗ the vault key is right, but the vault wraps under ${CURRENT}, not ${PREVIOUS}: keep the right ID with it`,
  );
  assert.match(await refusal(() => keyVerdict(b64(keys.previous), material)), new RegExp(`^✗ a vault key the vault only verifies with, not the one it signs with now: a previous one, .* The vault wraps under vault ID ${CURRENT}$`));
  for (const other of [randomBytes(32), derivedSigningKey(randomBytes(32))]) {
    assert.equal(
      await refusal(() => keyVerdict(b64(other), material)),
      `✗ not this instance's: no key the vault signs or verifies with, taken as a vault key or as a signing key. The vault wraps under vault ID ${CURRENT}`,
    );
  }
});

test("a key service and its signingKey: the signingKey passes as the signing key; the local key it replaced is a previous one; the service's ID is shown, not proven", async () => {
  const moved: KeyMaterial = {
    kek: { provider: 'aws-kms', id: 'arn:aws:kms:eu-west-1:111122223333:key/coffre' },
    previous: [{ provider: 'local', id: CURRENT }],
    checks: [keyCheckOf(keys.signing), material.checks[0]!],
  };
  assert.equal(keyVerdict(b64(keys.signing), moved), 'the signing key the vault signs with now; it wraps under arn:aws:kms:eu-west-1:111122223333:key/coffre, in aws-kms');
  assert.match(await refusal(() => keyVerdict(b64(keys.current), moved)), /^✗ a vault key the vault only verifies with, not the one it signs with now: .* The vault wraps under arn:\S+, in aws-kms$/);
  // The local key's own signing key, pasted as such, is the same key: named a signing key.
  assert.match(await refusal(() => keyVerdict(b64(derivedSigningKey(keys.current)), moved)), /^✗ a signing key the vault only verifies with/);
});

test('a signingKey that is also a previous vault key passes as the signing key the vault signs with now', () => {
  // A local vault key K, kept as the vault key it replaced, given to a key service as its signingKey: its check is first as the signing key, later as the vault key.
  const reused: KeyMaterial = {
    kek: { provider: 'aws-kms', id: 'arn:aws:kms:eu-west-1:111122223333:key/coffre' },
    previous: [{ provider: 'local', id: CURRENT }],
    checks: [keyCheckOf(keys.current), keyCheckOf(derivedSigningKey(keys.current))],
  };
  assert.equal(keyVerdict(b64(keys.current), reused), 'the signing key the vault signs with now; it wraps under arn:aws:kms:eu-west-1:111122223333:key/coffre, in aws-kms');
});

test('a malformed key is said to be one, without being shown; an empty answer skips the key', async () => {
  const text = b64(keys.current);
  for (const malformed of [text.slice(1), keys.current.toString('hex'), 'hunter2', `${text}${text}`]) {
    const said = await refusal(() => keyVerdict(malformed, material));
    assert.match(said, /^✗ not a key: one is 32 bytes in base64, 44 characters, and these \d+ characters are not$/);
    assert.ok(!said.includes(malformed));
  }
  assert.equal(await refusal(() => keyVerdict('', material)), '– not given: not checked');
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

test('coffre verify keys reads what the key is checked against, and sends nothing else: no key, in any form', async (t) => {
  const instance = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/audit/keys' ? material : undefined));
  const { home } = signedInHome(t, instance.origin);

  // On stdin, as a script pipes it: the key's line.
  const right = await coffre(['verify', 'keys'], home, `${b64(keys.current)}\n`);
  assert.equal(right.code, 0, right.stderr);
  assert.match(right.stdout, /✓ key +the vault key the vault signs with now; it wraps under vault ID vault-2026-10-03-bbbbbb \(from stdin\)/);
  assert.match(right.stdout, new RegExp(`The key is ${instance.origin}'s\\.`));

  // 0.14's two lines, the app key's second: the vault key checked, and the app key's line said to be unread.
  const previous = await coffre(['verify', 'keys'], home, `${b64(keys.previous)}\n${b64(keys.signing)}\n`);
  assert.equal(previous.code, 1);
  assert.match(previous.stdout, /✗ key +a vault key the vault only verifies with, not the one it signs with now: .* \(from stdin\)/);
  assert.match(previous.stdout, /stdin's other lines are not read: the app key has nothing to be checked against/);
  assert.match(previous.stdout, /The key is not the one /);

  const none = await coffre(['verify', 'keys'], home, '\n');
  assert.equal(none.code, 1);
  assert.match(none.stdout, /– key +not given: not checked/);
  assert.match(none.stdout, /No key given: nothing checked/);

  assert.deepEqual(new Set(instance.seen.map(({ method, url }) => `${method} ${url}`)), new Set(['GET /api/audit/keys']));
  const sent = JSON.stringify(instance.seen);
  for (const key of Object.values(keys)) for (const form of forms(key)) assert.ok(!sent.includes(form), 'a key was sent');
  for (const run of [right, previous]) for (const key of Object.values(keys)) assert.ok(!(run.stdout + run.stderr).includes(b64(key)), 'a key was printed');
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
    // The newest page of the log: an entry signed since the head, and one it numbers, proven.
    const audit = { entries: [{ seq: 1, proof: 'unproven' }, { seq: 0, proof: 'proven' }], more: false, next: null, head: { size: 1, signedAt: '2026-11-14T00:00:00Z' }, holes: [] };
    const instance = await fakeInstance(t, (method, path) =>
      method === 'GET' && path === '/api/me' ? me : method === 'GET' && path === '/api/audit' ? audit : undefined,
    );
    const { home, store } = signedInHome(t, instance.origin);
    const before = store();
    const run = await coffre(['verify', 'instance'], home);
    // A stand-in for an instance fails the anonymous checks; what matters here is what is done with the session.
    assert.equal(run.code, 1);
    if (role === 'user') {
      assert.match(run.stdout, /✗ owner +root@acme\.example is not an admin or owner of all of http:\/\/127\.0\.0\.1:\d+: nothing was made/);
      assert.doesNotMatch(run.stdout, /setup|clean-up/);
    } else {
      assert.match(run.stdout, /✓ owner +root@acme\.example, an owner, with this CLI's session/);
      // 0.16.0 walks no whole log, as the owner or the token: one page of it, held to the head the vault signed.
      assert.doesNotMatch(run.stdout, /verification/);
      assert.match(run.stdout, /✓ owner log proofs +1 entry of the newest page proven against the vault's head of 1, signed at 2026-11-14T00:00:00Z; 1 past it, none missing/);
      assert.deepEqual(instance.seen.filter(({ url }) => url.startsWith('/api/audit')).map(({ url }) => url), ['/api/audit?detail=1&limit=200']);
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

test('coffre verify instance asks again for a page racing a pruning, and judges the fresh one', async (t) => {
  const me = { principal: { type: 'user', id: 'root@acme.example' }, registered: true, tampered: false, instanceRole: 'owner', runsInstance: true, canReadAudit: true, environments: [] };
  const head = { size: 2, signedAt: '2026-11-14T00:00:00Z' };
  const entries = [{ seq: 1, proof: 'proven' }, { seq: 0, proof: 'proven' }];
  // The first page's head still counts aging uses a pruning removed since; the next head does not.
  const pages = [{ entries, more: false, next: null, head, holes: [{ above: 0, below: null, kept: 0, aging: 3 }] }, { entries, more: false, next: null, head, holes: [] }];
  let read = 0;
  const instance = await fakeInstance(t, (method, path) =>
    method === 'GET' && path === '/api/me' ? me : method === 'GET' && path === '/api/audit' ? pages[Math.min(read++, 1)] : undefined,
  );
  const { home } = signedInHome(t, instance.origin);
  const run = await coffre(['verify', 'instance'], home);
  assert.match(run.stdout, /✓ owner log proofs +2 entries of the newest page proven against the vault's head of 2, signed at 2026-11-14T00:00:00Z; 0 past it, none missing/);
  assert.equal(instance.seen.filter(({ url }) => url.startsWith('/api/audit')).length, 2);
});

test('coffre verify instance without a session says to sign in first, and checks nothing', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-verify-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const nowhere = await coffre(['verify', 'instance'], home);
  assert.equal(nowhere.code, 1);
  assert.equal(nowhere.stderr, `coffre: ${signInError('not signed in anywhere yet: run `coffre login <url>` first')}\n`);
  const elsewhere = await coffre(['verify', 'instance', 'https://coffre.acme.example'], home);
  assert.equal(elsewhere.code, 1);
  assert.equal(elsewhere.stderr, `coffre: ${signInError('not signed in: run `coffre login https://coffre.acme.example` first')}\n`);
  const named = await coffre(['--auth-mode', 'signin', 'verify', 'instance', 'https://coffre.acme.example'], home);
  assert.equal(named.stderr, `coffre: ${signInError('not signed in: run `coffre login https://coffre.acme.example` first')}\n`);
  // Behind Cloudflare Access, 0.16.0 takes no CLI's credential: said in a sentence, nothing checked.
  const access = await coffre(['--auth-mode', 'cloudflare', 'verify', 'instance', 'https://coffre.acme.example'], home);
  assert.equal(access.stderr, `coffre: ${browsersOnly('https://coffre.acme.example')}\n`);
  const noUrl = await coffre(['--auth-mode', 'signin', 'verify', 'instance'], home);
  assert.equal(noUrl.stderr, `coffre: ${signInError('not signed in anywhere yet: run `coffre login <url>` first')}\n`);
  assert.equal(nowhere.stdout + elsewhere.stdout + named.stdout + access.stdout + noUrl.stdout, '');
});

test('coffre verify alone, without a terminal, lists the checks and exits 2', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-verify-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const run = await coffre(['verify'], home);
  assert.equal(run.code, 2);
  assert.equal(run.stdout, '');
  assert.match(run.stderr, /^usage: coffre verify instance \| keys \| backup <dump>\n\n {2}instance {2}.+\n {2}keys {6}.+\n {2}backup {4}.+\n/);
});

test("coffre verify log, 0.14's walk of the whole log, says in a line what watches the log in 0.16.0, and asks nothing", async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'coffre-verify-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const run = await coffre(['verify', 'log'], home);
  assert.equal(run.code, 1);
  assert.equal(run.stdout, '');
  assert.equal(run.stderr, `coffre: ${LOG_GONE}\n`);
  assert.match(LOG_GONE, /^coffre verify log is not in 0\.16\.0: the vault signs the audit log/);
});

test('coffre verify alone, on a terminal, asks which check, and runs the one chosen', { skip: ptySkip }, async (t) => {
  // An instance that lets no one read the keys' material: the keys' check, chosen, says so and asks for no key.
  const instance = await fakeInstance(t, () => undefined);
  const { home } = signedInHome(t, instance.origin);
  const { output, code } = await inTerminal(['verify'], { ...cleanEnv(), HOME: home }, async (terminal) => {
    await terminal.waitFor('Which check?');
    await terminal.waitFor('keys');
    terminal.send('\x1b[B');
    terminal.send('\r');
    await terminal.waitFor('not found');
  });
  assert.equal(code, 1);
  const shown = visible(output);
  assert.match(shown, /✓ Which check\? {2}keys {6}the vault key or signing key you keep, against the instance/);
  assert.doesNotMatch(shown, /\blog\b/, 'the whole log is no check to choose');
});

test('coffre verify keys, on a terminal, asks for the key without showing it', { skip: ptySkip }, async (t) => {
  const instance = await fakeInstance(t, (method, path) => (method === 'GET' && path === '/api/audit/keys' ? material : undefined));
  const { home } = signedInHome(t, instance.origin);
  const { output, code } = await inTerminal(['verify', 'keys'], { ...cleanEnv(), HOME: home }, async (terminal) => {
    await terminal.waitFor('Vault key, or signing key?');
    terminal.send(`${b64(keys.previous)}\r`);
    await terminal.waitFor('is not');
  });
  assert.equal(code, 1);
  const shown = visible(output);
  assert.match(shown, /•{44} {2}44 characters/);
  assert.match(shown, /✗ key +a vault key the vault only verifies with, not the one it signs with now/);
  for (const key of Object.values(keys)) for (const form of forms(key)) assert.ok(!output.includes(form), 'a key was shown');
});

/** This process's environment without its COFFRE_ variables, which would pick another instance or credential. */
function cleanEnv(): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));
}

// --- the token's reveal, found in the log once the signer publishes it -----------

const CANARY = { project: 'conformance', environment: 'live', key: 'CANARY', value: 'coffre-canary-1' };

/** A coffre whose reveal is request `r-1`, and whose log lists `pages`, one a read, the last again after. */
function revealing(pages: unknown[][]): { send: typeof fetch; reads: () => number } {
  let reads = 0;
  const send = (async (input: Request) => {
    const { pathname } = new URL(input.url);
    if (pathname === '/api/reveals') return Response.json({ operationId: 'r-1', values: { CANARY: CANARY.value } });
    assert.equal(pathname, '/api/audit');
    return Response.json({ entries: pages[Math.min(reads++, pages.length - 1)], more: false, next: null, head: null, holes: null });
  }) as typeof fetch;
  return { send, reads: () => reads };
}

const read = (operationId: string) => ({ seq: 7, action: 'secret.read', decision: 'allow', key: 'CANARY', operationId, requestId: operationId });

test("the token's reveal is looked for again until the signer has published it, and found by its operation", async () => {
  const coffre = revealing([[], [read('r-0')], [read('r-0'), read('r-1')]]);
  const said = await tokenReveal('http://coffre.test', 'coffre_svc_x', coffre.send, CANARY, { member: 'token:live' }, { seconds: 5, every: 0.01 });
  assert.equal(said, 'one secret.read of CANARY, entry 7, under request r-1');
  assert.equal(coffre.reads(), 3);
});

test("a reveal the log never lists fails at the wait's end, and a read that stalls ends with it", async () => {
  const never = revealing([[read('r-0')]]);
  await assert.rejects(
    tokenReveal('http://coffre.test', 'coffre_svc_x', never.send, CANARY, { member: 'token:live' }, { seconds: 0.2, every: 0.01 }),
    (error: unknown) => error instanceof Failure && error.message === 'the reveal is logged 0 times, not once, in 0.2 s',
  );
  assert.ok(never.reads() > 1);
  // A read that never answers: the wait's deadline aborts it, and the reveal is judged on what was read before.
  const stalled = (async (input: Request, init?: RequestInit) => {
    if (new URL(input.url).pathname === '/api/reveals') return Response.json({ operationId: 'r-1', values: { CANARY: CANARY.value } });
    const signal = init?.signal ?? input.signal;
    return new Promise<Response>((_, reject) => signal.addEventListener('abort', () => reject(signal.reason)));
  }) as typeof fetch;
  const started = Date.now();
  await assert.rejects(
    tokenReveal('http://coffre.test', 'coffre_svc_x', stalled, CANARY, { member: 'token:live' }, { seconds: 0.2, every: 0.01 }),
    (error: unknown) => error instanceof Failure && /^the reveal is logged 0 times/.test(error.message),
  );
  assert.ok(Date.now() - started < 2000);
});
