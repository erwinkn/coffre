import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { everyRoute } from '@coffre/client/routes';

import { ENTRIES, PARITY } from '../src/commands.ts';
import { commandLine, SESSION_OPTIONS } from '../src/flags.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const COMMANDS = [...new Set(ENTRIES.map(({ command }) => command))];

type Run = { code: number | null; stdout: string; stderr: string };

/** `coffre <args>`, signed in nowhere unless `home` says otherwise, with none of this process's COFFRE_ variables. */
async function coffre(args: string[], home?: string): Promise<Run> {
  const own = home ?? mkdtempSync(join(tmpdir(), 'coffre-parity-'));
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));
  try {
    const child = spawn(process.execPath, ['--conditions=coffre:source', main, ...args], { env: { ...env, HOME: own, NO_COLOR: '1' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let [stdout, stderr] = ['', ''];
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
    const [code] = (await once(child, 'close')) as [number | null];
    return { code, stdout, stderr };
  } finally {
    if (home === undefined) rmSync(own, { recursive: true, force: true });
  }
}

/** Each of `items`, a few at a time. */
async function each<T, R>(items: readonly T[], run: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: 6 }, async () => {
    while (next < items.length) {
      const at = next++;
      results[at] = await run(items[at]!);
    }
  }));
  return results;
}

test('every route of the API is a command of the CLI, or a browser\'s, with why', () => {
  const routes = everyRoute('https://coffre.test').map(({ key }) => key).sort();
  assert.deepEqual(Object.keys(PARITY).sort(), routes, 'PARITY lists each route once, and only routes');
  for (const [route, reach] of Object.entries(PARITY)) {
    if ('browser' in reach) {
      assert.ok(reach.browser.length > 20, `${route} says why only a browser calls it`);
      continue;
    }
    assert.ok(reach.commands.length > 0, `${route} names a command`);
    for (const command of reach.commands) assert.ok((COMMANDS as string[]).includes(command), `${route}: \`coffre ${command}\` is no command of coffre help`);
  }
  // What only a browser does, as coffre help does not offer it.
  const browser = Object.entries(PARITY).filter(([, reach]) => 'browser' in reach).map(([route]) => route);
  assert.deepEqual(browser, ['GET /device-logins/:code', 'POST /device-logins/:code', 'GET /oauth/authorizations', 'POST /oauth/authorizations', 'GET /approvals/:id', 'POST /approvals/:id']);
});

test("a command's own flag named like a session flag reaches it: grant --service is grant's", () => {
  for (const { command, usage } of ENTRIES) {
    for (const name of Object.keys(SESSION_OPTIONS)) {
      if (!usage.join(' ').includes(`[--${name}]`)) continue;
      const words = command.split(' ');
      assert.deepEqual(commandLine([...words, 'x', `--${name}`]).rest.slice(words.length - 1), ['x', `--${name}`], `coffre ${command} --${name}`);
    }
  }
});

test('every command says how it is used, with --help, -h or help <command>, exit 0, and is run by the CLI', async () => {
  const asks = COMMANDS.flatMap((command) => [[...command.split(' '), '--help'], [...command.split(' '), '-h'], ['help', ...command.split(' ')]]);
  const runs = await each(asks, (args) => coffre(args));
  asks.forEach((args, i) => {
    const run = runs[i]!;
    const command = args.filter((arg) => arg !== 'help' && !arg.startsWith('-')).join(' ');
    assert.equal(run.code, 0, `coffre ${args.join(' ')}: ${run.stderr}`);
    assert.ok(run.stdout.includes(`coffre ${command}`), `coffre ${args.join(' ')} shows its usage:\n${run.stdout}`);
  });
  // `coffre trust` alone says how, as coffre help says it does.
  const trust = await coffre(['trust']);
  assert.equal(trust.code, 0, trust.stderr);
  assert.match(trust.stdout, /^usage: coffre trust <service>/);
});

test('a flag a command does not take is refused in a line and the usage, never a stack trace', async () => {
  const runs = await each(COMMANDS, (command) => coffre([...command.split(' '), '--bogus']));
  COMMANDS.forEach((command, i) => {
    const run = runs[i]!;
    assert.notEqual(run.code, 0, `coffre ${command} --bogus was taken`);
    assert.doesNotMatch(run.stderr, /^\s+at /m, `coffre ${command} --bogus printed a stack trace:\n${run.stderr}`);
  });
  const init = runs[COMMANDS.indexOf('init')]!;
  assert.equal(init.code, 2);
  assert.match(init.stderr, /^coffre: unknown option '--bogus'\nusage:\n {4}coffre init --workers/);
});

test('coffre help names service accounts as people do, service:<name>, and offers OIDC before bearer tokens', async () => {
  const { stdout } = await coffre(['help']);
  assert.doesNotMatch(stdout, /(?<![\w-])token:[A-Za-z0-9]/);
  const section = stdout.slice(stdout.indexOf('  Service accounts, for CI and other machines'));
  assert.ok(section.indexOf('coffre trust') < section.indexOf('coffre tokens issue'), 'OIDC first, then bearer tokens');
  assert.match(stdout, /coffre admit <principal> \[--service\].*\n.*a service account,\n.*service:<name> or --service/);
  const trust = await coffre(['trust']);
  assert.match(trust.stdout, /A service account, service:<name>, signs in by OIDC this way/);
});

test('--version prints the version; help and --help the commands', async () => {
  const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  for (const flag of ['--version', '-v']) assert.deepEqual(await coffre([flag]), { code: 0, stdout: `${version}\n`, stderr: '' });
  for (const args of [[], ['--help'], ['help']]) {
    const run = await coffre(args);
    assert.equal(run.code, 0);
    assert.match(run.stdout, /^coffre - secrets, with an audit log\n/);
  }
  const named = await coffre(['help', 'tokens']);
  assert.match(named.stdout, /^usage:\n {4}coffre tokens <service>.*\n {4}coffre tokens issue/);
  const none = await coffre(['nope']);
  assert.equal(none.code, 1);
  assert.match(none.stderr, /^coffre: no command nope\n/);
});

test('a saved session the instance does not know is said plainly, with the login that mends it', async (t) => {
  const server = createServer((_, response) => response.writeHead(401, { 'content-type': 'application/json' }).end('{"error":"unauthenticated","message":"that credential is unknown, expired or revoked"}'));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const home = mkdtempSync(join(tmpdir(), 'coffre-parity-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  mkdirSync(join(home, '.coffre'), { mode: 0o700 });
  const session = { mode: 'signin', token: 'coffre_cli_saved', expiresAt: '2099-01-01T00:00:00Z', obtainedAt: '2026-10-01T00:00:00Z' };
  writeFileSync(join(home, '.coffre', 'credentials.json'), JSON.stringify({ version: 2, current: origin, instances: { [origin]: session } }));
  chmodSync(join(home, '.coffre', 'credentials.json'), 0o600);
  const run = await coffre(['whoami'], home);
  assert.equal(run.code, 1);
  assert.equal(run.stderr, `coffre: ${origin} does not know the session saved here: it was signed out, or the instance was reset since. Sign in again: \`coffre login ${origin}\`\n`);
});
