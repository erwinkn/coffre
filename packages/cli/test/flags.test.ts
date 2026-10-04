import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { commandLine, readSession, removedVariables, secretFile } from '../src/flags.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

test('the session flags come before the command, and the command keeps its own', () => {
  assert.deepEqual(commandLine(['--url', 'https://coffre.example.com', '--token-file=-', 'export', 'app/prod', '--format', 'github']), {
    session: { url: 'https://coffre.example.com', 'token-file': '-' },
    command: 'export',
    rest: ['app/prod', '--format', 'github'],
  });
  assert.deepEqual(commandLine(['get', 'app/prod/KEY']), { session: {}, command: 'get', rest: ['app/prod/KEY'] });
  // Not a session flag: the command, which the usage answers.
  assert.equal(commandLine(['--help']).command, '--help');
  assert.throws(() => commandLine(['--url']), /argument missing/);
});

test('a session flag after the command is refused, saying where it goes; a command’s own flag of that name is not', () => {
  assert.throws(
    () => commandLine(['get', 'app/prod/KEY', '--url', 'https://coffre.example.com']),
    /--url is a session flag, which goes before the command: coffre --url <url> get …/,
  );
  assert.throws(() => commandLine(['export', 'app/prod', '--token-file=t']), /coffre --token-file <path\|-> export/);
  assert.deepEqual(commandLine(['grant', 'app', 'deploy', '--role', 'viewer', '--service']).rest, ['app', 'deploy', '--role', 'viewer', '--service']);
  // Setup and migrate refuse it themselves, saying more when it looks like a connection string.
  assert.deepEqual(commandLine(['setup', '--url=postgresql://o:p@h/d']).rest, ['--url=postgresql://o:p@h/d']);
  // After `--`, the arguments are the child's.
  assert.deepEqual(commandLine(['run', 'app/prod', '--', 'deploy', '--url', 'x']).rest, ['app/prod', '--', 'deploy', '--url', 'x']);
});

test('a session flag a command has no use for is refused, not ignored', () => {
  assert.throws(() => commandLine(['--token-file', 't', 'setup']), /--token-file does nothing for coffre setup/);
  assert.throws(() => commandLine(['--url', 'u', '--service', 's', 'login']), /--service does nothing for coffre login/);
  assert.deepEqual(commandLine(['--url', 'u', '--auth-mode', 'cloudflare', 'login']).session, { url: 'u', 'auth-mode': 'cloudflare' });
});

test('a variable an earlier CLI read stops the command, in one line naming what replaced it', () => {
  assert.equal(removedVariables({ HOME: '/home/a' }, ['get']), null);
  assert.equal(removedVariables({ COFFRE_TOKEN: 'coffre_svc_x' }, ['get']), 'COFFRE_TOKEN is no longer read: unset it, and pass --token-file <path|->');
  assert.equal(
    removedVariables({ COFFRE_API_URL: 'https://coffre.example.com', COFFRE_ID_TOKEN: 'a', COFFRE_ID_TOKEN_FILE: '/t' }, ['export', 'app/prod']),
    'COFFRE_API_URL, COFFRE_ID_TOKEN and COFFRE_ID_TOKEN_FILE are no longer read: unset them, and pass --url <url> and --id-token-file <path|->',
  );
  // A command's own input matters only to that command; an empty variable never did anything.
  assert.equal(removedVariables({ COFFRE_APP_KEY: 'k', COFFRE_TOKEN: ' ' }, ['get']), null);
  assert.equal(removedVariables({ COFFRE_APP_KEY: 'k' }, ['verify', 'instance']), null);
  assert.match(removedVariables({ COFFRE_APP_KEY: 'k' }, ['verify', 'keys']) ?? '', /COFFRE_APP_KEY is no longer read: unset it, and pass coffre verify keys --app-key-file <path\|->/);
  assert.match(removedVariables({ COFFRE_MIGRATE_DATABASE_URL: 'postgresql://o@h/d' }, ['migrate', '--yes']) ?? '', /coffre migrate --database-url-file/);
  // A command that talks to no instance never read the session's.
  assert.equal(removedVariables({ COFFRE_TOKEN: 'coffre_svc_x', COFFRE_API_URL: 'https://coffre.example.com' }, ['init', '--node']), null);
  assert.equal(removedVariables({ COFFRE_SETUP_DATABASE_URL: 'postgresql://o@h/d', COFFRE_TOKEN: 'x' }, ['setup']), 'COFFRE_SETUP_DATABASE_URL is no longer read: unset it, and pass coffre setup --database-url-file <path|->');
});

test('a secret comes from its file, trimmed, and an empty or missing file is said as it is', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-flags-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'token'), 'coffre_svc_x\n');
  writeFileSync(join(dir, 'empty'), '\n');
  assert.equal(secretFile('--token-file', join(dir, 'token')), 'coffre_svc_x');
  assert.throws(() => secretFile('--token-file', join(dir, 'empty')), /^Error: --token-file: its file is empty$/);
  assert.throws(() => secretFile('--token-file', join(dir, 'nope')), /^Error: --token-file: its file could not be read \(ENOENT\)$/);
  // A secret given where its path goes is not shown back.
  assert.throws(
    () => secretFile('--token-file', 'coffre_svc_given-by-mistake'),
    (error: Error) => !error.message.includes('coffre_svc_given-by-mistake'),
  );
});

test('an empty session flag is refused, never taken for one left out', () => {
  // What an unset variable expands to: left out, it would mean the saved session's instance, or its person.
  assert.throws(() => readSession({ url: '' }), /^Error: --url is empty: an unset variable, perhaps$/);
  assert.throws(() => readSession({ url: 'https://coffre.example.com', service: '  ' }), /--service is empty/);
  assert.throws(() => readSession({ 'auth-mode': '' }), /--auth-mode is empty/);
  assert.throws(() => readSession({ 'token-file': '' }), /--token-file is empty/);
  assert.deepEqual(readSession({ url: ' https://coffre.example.com ', service: 'deploy' }), {
    url: 'https://coffre.example.com',
    token: undefined,
    service: 'deploy',
    idToken: undefined,
    accessClientId: undefined,
    accessClientSecret: undefined,
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

test('the CLI refuses a removed variable before anything else, in one line, where it was read', () => {
  const run = coffre(['whoami'], { COFFRE_TOKEN: 'coffre_svc_x' });
  assert.equal(run.status, 1);
  assert.equal(run.stderr, 'coffre: COFFRE_TOKEN is no longer read: unset it, and pass --token-file <path|->\n');
  assert.equal(coffre(['roles'], { COFFRE_TOKEN: 'coffre_svc_x' }).status, 0);
});

test('with an empty --url or --service, the CLI stops before sending anything, saved session or not', () => {
  for (const session of [['--url', '', '--token-file', '-'], ['--url', 'http://127.0.0.1:9', '--service', '']]) {
    const run = coffre([...session, 'whoami'], {}, 'coffre_svc_x\n');
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

test('verify instance refuses the flags of a CI run, in a line', () => {
  const run = coffre(['--service', 'deploy', 'verify', 'instance', 'http://127.0.0.1:9']);
  assert.equal(run.status, 2);
  assert.match(run.stderr, /^coffre: verify instance checks as no one, then with a service token in --token-file, or as you .* are for other commands\n$/);
});

test('stdin goes to one reader: a token from - leaves none for set, import or run', () => {
  const url = ['--url', 'http://127.0.0.1:9', '--token-file', '-'];
  for (const [args, said] of [
    [['set', 'app/prod/KEY'], /coffre set reads the value on stdin, which --token-file has read: give --token-file a path/],
    [['import', 'app/prod'], /coffre import reads the file on stdin, which --token-file has read/],
    [['run', 'app/prod', '--', 'true'], /coffre run hands stdin to true, and --token-file has read it: give --token-file a path/],
  ] as const) {
    const run = coffre([...url, ...args], {}, 'coffre_svc_x\n');
    assert.equal(run.status, 1, run.stderr);
    assert.match(run.stderr, said);
  }
  const both = coffre([...url, 'verify', 'instance', '--canary', 'app/prod/CANARY', '--canary-value-file', '-'], {}, 'coffre_svc_x\n');
  assert.equal(both.status, 2);
  assert.match(both.stderr, /--token-file and --canary-value-file both read stdin: give one of them a path/);
});
