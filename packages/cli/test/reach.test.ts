// An instance the CLI cannot reach: every command says why, from what
// Node's fetch keeps in its cause, and what to try. fetch is stubbed in
// the CLI's own process, failing as Node's does when a name does not resolve.
// And what import says of lines it cannot parse, before it reaches anything.
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const ORIGIN = 'https://secrets.acme.example';
const WHY = "getaddrinfo ENOTFOUND secrets.acme.example; the name does not resolve here: check the address, or flush this machine's DNS cache";

/** The CLI, in a home of its own, signed in to ORIGIN as a person or not at all, its fetch failing as Node's does for a name that does not resolve. */
async function cli(t: test.TestContext, args: string[], signedIn = true) {
  const home = mkdtempSync(join(tmpdir(), 'coffre-reach-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  if (signedIn) {
    mkdirSync(join(home, '.coffre'), { mode: 0o700 });
    const ada = { mode: 'signin', token: 'coffre_cli_ada', principal: { type: 'user', id: 'ada@acme.example' }, expiresAt: '2099-01-01T00:00:00Z', obtainedAt: '2026-10-01T00:00:00Z' };
    writeFileSync(join(home, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: ORIGIN, instances: { [ORIGIN]: ada } }), { mode: 0o600 });
  }
  const stub = join(home, 'unresolved.mjs');
  writeFileSync(
    stub,
    `globalThis.fetch = async () => {
  const cause = Object.assign(new Error('getaddrinfo ENOTFOUND secrets.acme.example'), { code: 'ENOTFOUND', syscall: 'getaddrinfo', hostname: 'secrets.acme.example' });
  throw new TypeError('fetch failed', { cause });
};\n`,
  );
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_')));
  const child = spawn(process.execPath, ['--conditions=coffre:source', `--import=${stub}`, main, ...args], { env: { ...env, HOME: home, NO_COLOR: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let [stdout, stderr] = ['', ''];
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  const [status] = (await once(child, 'close')) as [number | null];
  return { status, stdout, stderr };
}

test('login says why it could not reach the instance, and what to try', async (t) => {
  const { status, stderr } = await cli(t, ['login', ORIGIN, '--no-browser'], false);
  assert.equal(status, 1);
  assert.equal(stderr, `coffre: could not reach ${ORIGIN}: ${WHY}\n`);
});

test('a command, through the API, says why it could not reach the instance', async (t) => {
  const { status, stderr } = await cli(t, ['whoami']);
  assert.equal(status, 1);
  assert.equal(stderr, `coffre: could not reach ${ORIGIN}: ${WHY}\n`);
});

test('logout says why it could not end the session, and that nothing changed', async (t) => {
  const { status, stderr } = await cli(t, ['logout', ORIGIN]);
  assert.equal(status, 1);
  assert.equal(stderr, `coffre: could not reach ${ORIGIN} to end the session: ${WHY}; nothing was changed\n`);
});

test('verify instance says why once, at health, and skips what would only say it again', async (t) => {
  const { status, stdout } = await cli(t, ['verify', 'instance', ORIGIN]);
  assert.equal(status, 1);
  const lines = stdout.split('\n').map((line) => line.trim().replace(/ {2,}/g, '  '));
  assert.ok(lines.includes(`✗ health  could not reach ${ORIGIN}: ${WHY}`), stdout);
  for (const check of ['headers', 'anonymous api', 'forged cross-site', 'sign-in info', 'anonymous answers']) {
    assert.ok(lines.includes(`– ${check}  no instance: an earlier check failed`), stdout);
  }
  assert.ok(lines.includes(`✗ owner  could not reach ${ORIGIN}: ${WHY}`), stdout);
  assert.ok(!stdout.includes('fetch failed') && !stdout.includes('    at '), 'no stack, nor fetch\'s own two words');
});

test("import names a line it cannot parse by its number, its reason and its key, never its text: a value never reaches stderr", async (t) => {
  const secret = 'sk-live-51Habc123xyz';
  const dir = mkdtempSync(join(tmpdir(), 'coffre-import-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, '.env');
  writeFileSync(file, [`${secret}==`, secret, `TOKEN="${secret}`, `DATABASE_URL="postgres://u:${secret}@db" extra`].join('\n'));
  const { status, stdout, stderr } = await cli(t, ['import', 'market/prod', '--file', file]);
  assert.equal(status, 0, stderr);
  assert.equal(
    stderr,
    [
      '  line 1: key must match ^[A-Za-z_][A-Za-z0-9_]*$',
      '  line 2: no "=" on this line',
      '  line 3: unterminated double quote (multi-line values are not supported) (TOKEN)',
      '  line 4: unexpected text after the closing quote (DATABASE_URL)',
      '',
    ].join('\n'),
  );
  assert.ok(!(stdout + stderr).includes('51Habc123'));
});
