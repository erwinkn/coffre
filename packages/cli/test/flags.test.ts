import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { commandLine, readSession } from '../src/flags.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

test('the session flags come before the command, and the command keeps its own', () => {
  assert.deepEqual(commandLine(['--url', 'https://coffre.example.com', '--service=api-deploy', 'export', 'app/prod', '--format', 'github']), {
    session: { url: 'https://coffre.example.com', service: 'api-deploy' },
    command: 'export',
    rest: ['app/prod', '--format', 'github'],
  });
  assert.deepEqual(commandLine(['get', 'app/prod/KEY']), { session: {}, command: 'get', rest: ['app/prod/KEY'] });
  // Not a session flag: the command, which the usage answers.
  assert.equal(commandLine(['--help']).command, '--help');
  assert.equal(commandLine(['--token-file', 't', 'get']).command, '--token-file');
  assert.throws(() => commandLine(['--url']), /argument missing/);
});

test('a session flag after the command is refused, saying where it goes; a command’s own flag of that name is not', () => {
  assert.throws(
    () => commandLine(['get', 'app/prod/KEY', '--url', 'https://coffre.example.com']),
    /--url is a session flag, which goes before the command: coffre --url <url> get …/,
  );
  assert.throws(() => commandLine(['export', 'app/prod', '--service=deploy']), /coffre --service <name> export/);
  assert.deepEqual(commandLine(['grant', 'app', 'deploy', '--role', 'viewer', '--service']).rest, ['app', 'deploy', '--role', 'viewer', '--service']);
  assert.deepEqual(commandLine(['login', 'https://coffre.example.com', '--service', 'deploy']).rest, ['https://coffre.example.com', '--service', 'deploy']);
  for (const command of ['admit', 'revoke', 'offboard']) assert.deepEqual(commandLine([command, 'deploy', '--service']).rest, ['deploy', '--service']);
  // Setup and migrate refuse it themselves, saying more when it looks like a connection string.
  assert.deepEqual(commandLine(['setup', '--url=postgresql://o:p@h/d']).rest, ['--url=postgresql://o:p@h/d']);
  // After `--`, the arguments are the child's.
  assert.deepEqual(commandLine(['run', 'app/prod', '--', 'deploy', '--url', 'x']).rest, ['app/prod', '--', 'deploy', '--url', 'x']);
});

test('a session flag a command has no use for is refused, not ignored', () => {
  assert.throws(() => commandLine(['--url', 'u', 'setup']), /--url does nothing for coffre setup/);
  assert.throws(() => commandLine(['--url', 'u', '--service', 's', 'login']), /--service does nothing for coffre login/);
  assert.deepEqual(commandLine(['--url', 'u', '--auth-mode', 'cloudflare', 'login']).session, { url: 'u', 'auth-mode': 'cloudflare' });
});

test('an empty session flag is refused, never taken for one left out', () => {
  // What an unset variable expands to: left out, it would mean the saved session's instance, or its person.
  assert.throws(() => readSession({ url: '' }), /^Error: --url is empty: an unset variable, perhaps$/);
  assert.throws(() => readSession({ url: 'https://coffre.example.com', service: '  ' }), /--service is empty/);
  assert.throws(() => readSession({ 'auth-mode': '' }), /--auth-mode is empty/);
  assert.deepEqual(readSession({ url: ' https://coffre.example.com ', service: 'deploy' }), {
    url: 'https://coffre.example.com',
    service: 'deploy',
    authMode: undefined,
  });
});

/** The CLI, with none of this process's COFFRE_ variables, and `input` on stdin. */
function coffre(args: string[], env: Record<string, string> = {}, input = '') {
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('COFFRE_')));
  const home = mkdtempSync(join(tmpdir(), 'coffre-flags-home-'));
  try {
    return spawnSync(process.execPath, ['--conditions=coffre:source', main, ...args], { env: { ...inherited, HOME: home, ...env }, input, encoding: 'utf8', timeout: 10_000 });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

test('with an empty --url or --service, the CLI stops before sending anything, saved session or not', () => {
  for (const session of [['--url', ''], ['--url', 'http://127.0.0.1:9', '--service', '']]) {
    const run = coffre([...session, 'whoami']);
    assert.equal(run.status, 1);
    assert.match(run.stderr, /^coffre: --(url|service) is empty: an unset variable, perhaps\n$/);
  }
});

test('an instance named twice, as an argument and as --url, is refused', () => {
  const login = coffre(['--url', 'http://127.0.0.1:9', 'login', 'http://127.0.0.1:8']);
  assert.equal(login.status, 1);
  assert.match(login.stderr, /name the instance once: coffre login <url>, or coffre --url <url> login/);
  const verify = coffre(['--url', 'http://127.0.0.1:9', 'verify', 'instance', 'http://127.0.0.1:8']);
  assert.equal(verify.status, 2);
  assert.match(verify.stderr, /name the instance once/);
});

test('verify instance refuses --service, in a line', () => {
  const run = coffre(['--service', 'deploy', 'verify', 'instance', 'http://127.0.0.1:9']);
  assert.equal(run.status, 2);
  assert.match(run.stderr, /^coffre: verify instance checks as no one, then with a bearer token .* --service is for other commands\n$/);
});

test('a secret is never an argument: set refuses a value, login refuses two ways in', () => {
  const set = coffre(['--url', 'http://127.0.0.1:9', 'set', 'app/prod/KEY', 'hunter2']);
  assert.equal(set.status, 1);
  assert.equal(set.stderr, 'coffre: coffre set asks for the value: paste it, or pipe it in, never as an argument\n');
  const both = coffre(['login', 'http://127.0.0.1:9', '--token', '--service', 'deploy']);
  assert.equal(both.status, 1);
  assert.match(both.stderr, /--token and --service are two ways to sign in: give one/);
  const id = coffre(['login', 'http://127.0.0.1:9', '--id-token']);
  assert.match(id.stderr, /--id-token goes with --service <name>/);
  // An unset variable piped in would blank the secret: refused, before anything is sent.
  const empty = coffre(['--url', 'http://127.0.0.1:9', 'set', 'app/prod/KEY'], {}, '');
  assert.equal(empty.status, 1);
  assert.equal(empty.stderr, 'coffre: no value: none came on stdin, and there is no terminal to ask on\n');
  // A machine sign-in says its own mode.
  const mode = coffre(['--auth-mode', 'cloudflare', 'login', 'http://127.0.0.1:9', '--token'], {}, 'coffre_svc_x\n');
  assert.equal(mode.status, 1);
  assert.equal(mode.stderr, "coffre: --auth-mode is for a person's sign-in: --token says which\n");
  // Nothing on stdin and no terminal: said, before anything is sent.
  const none = coffre(['login', 'http://127.0.0.1:9', '--token']);
  assert.equal(none.status, 1);
  assert.equal(none.stderr, 'coffre: no bearer token: none came on stdin, and there is no terminal to ask on\n');
});
