import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { postgresClient } from '@coffre/db/connect';
import { KNOWN_MIGRATIONS } from '@coffre/db/schema-version';

import { cappedLimit, hyperdriveLimit, limitReason, tooFewConnections } from '../src/connections.ts';
import { asJson, hyperdriveCommand, loginFor, loginUrl, scramVerifier, setupScreen, setupValues, summary, workerNames, type SetupResult } from '../src/setup.ts';
import { templateDir } from '../src/init.ts';
import { asSuperuser, CLUSTER, connects, database, emptyCluster, needsCluster, SMALL_CLUSTER } from './cluster.ts';
import { fakeOpener, fakeWrangler } from './fakes.ts';
import { inTerminal, ptySkip, screens, typingUrl, visible } from './pty.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

type Run = { status: number | null; stdout: string; stderr: string };

/**
 * `coffre setup` as an operator runs it, in an empty directory with no home,
 * or in a Workers deployment's, as its two wrangler.jsonc files make it, each
 * naming the template's Worker (`vault`, the vault's file as given): the URL
 * piped in.
 */
function setup(args: string[], how: { stdin?: string; workers?: boolean; vault?: string }): Run {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-setup-'));
  const files = how.workers === true ? ['app', 'vault'] : [];
  for (const component of files) {
    mkdirSync(join(dir, component));
    const named = `{ "name": "${component === 'app' ? 'coffre' : 'coffre-vault'}" }\n`;
    writeFileSync(join(dir, component, 'wrangler.jsonc'), component === 'vault' ? (how.vault ?? named) : named);
  }
  try {
    const result = spawnSync(process.execPath, ['--conditions=coffre:source', main, 'setup', ...args], {
      cwd: dir,
      env: { PATH: process.env.PATH, HOME: dir },
      input: how.stdin ?? '',
      encoding: 'utf8',
    });
    assert.deepEqual(readdirSync(dir).sort(), files, 'it writes no file');
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}


function json(run: Run) {
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stderr, /--json prints .* to stdout/);
  return JSON.parse(run.stdout) as {
    app: { APP_KEY?: string; DATABASE_URL?: string };
    vault: { VAULT_KEY_ID?: string; VAULT_KEY?: string; DATABASE_URL?: string; HOT_DATABASE_URL?: string };
    backup: { DATABASE_URL?: string };
    logins: Record<string, { login: string; password: string }>;
  };
}

/** Neither the connection string nor its password, anywhere the operator or a log would see. */
function assertNoAdministrator(run: Run, url: string): void {
  const password = decodeURIComponent(new URL(url).password);
  for (const [stream, text] of [['stdout', run.stdout], ['stderr', run.stderr]] as const) {
    assert.ok(!text.includes(url), `the connection string is on ${stream}`);
    assert.ok(!text.includes(password), `the administrator's password is on ${stream}`);
  }
}

// --- without a database ---------------------------------------------------------------

test('a login on PlanetScale names its branch, as the administrator does; elsewhere it is the role', () => {
  assert.equal(loginFor('coffre_runtime', 'postgres.x7k2m9q4w1'), 'coffre_runtime.x7k2m9q4w1');
  assert.equal(loginFor('coffre_vault_runtime', 'postgres'), 'coffre_vault_runtime');
  const administrator = new URL('postgresql://postgres.x7k2m9q4w1:s3cret@eu.pg.psdb.cloud:5432/coffre?sslmode=verify-full&sslrootcert=system');
  const url = loginUrl(administrator, loginFor('coffre_runtime', 'postgres.x7k2m9q4w1'), 'fresh-password');
  assert.equal(url, 'postgresql://coffre_runtime.x7k2m9q4w1:fresh-password@eu.pg.psdb.cloud:5432/coffre?sslmode=verify-full&sslrootcert=system');
});

test('a SCRAM verifier is what Postgres stores, never the password: it checks RFC 7677\'s exchange', () => {
  const verifier = scramVerifier('pencil', Buffer.from('W22ZaJ0SNY7soEsUEjb6gQ==', 'base64'));
  assert.ok(!verifier.includes('pencil'));
  const [, iterations, salt, storedKey, serverKey] = /^SCRAM-SHA-256\$(\d+):([^$]+)\$([^:]+):(.+)$/.exec(verifier)!;
  assert.deepEqual([iterations, salt], ['4096', 'W22ZaJ0SNY7soEsUEjb6gQ==']);
  // The RFC's exchange, as a server holding only the verifier checks it: the client's proof, and its own signature.
  const nonce = 'rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0';
  const authMessage = `n=user,r=rOprNGfwEbeRWgbNEkqO,r=${nonce},s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=${nonce}`;
  const hmac = (key: string, text: string) => createHmac('sha256', Buffer.from(key, 'base64')).update(text).digest();
  const proof = Buffer.from('dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=', 'base64');
  const clientKey = Buffer.from(proof.map((byte, i) => byte ^ hmac(storedKey!, authMessage)[i]!));
  assert.equal(createHash('sha256').update(clientKey).digest('base64'), storedKey);
  assert.equal(hmac(serverKey!, authMessage).toString('base64'), '6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=');
  assert.notEqual(scramVerifier('pencil'), scramVerifier('pencil'), 'a fresh salt each time');
});

test('the connection string is refused on the command line, without quoting it', () => {
  const url = 'postgresql://postgres:hunter2-secret@db.example.com:5432/coffre';
  for (const args of [[url], [`--url=${url}`], ['--database-url-file', url]]) {
    const run = setup(args, {});
    assert.equal(run.status, 1);
    assert.match(run.stderr, /never from the command line/);
    assert.match(run.stderr, /change that password, which is in your shell history now/);
    assertNoAdministrator(run, url);
    assert.equal(run.stdout, '');
  }
  const typo = setup(['--rest-passwords'], {});
  assert.equal(typo.status, 1);
  assert.doesNotMatch(typo.stderr, /shell history/);
});

test('a connection string that is not one is refused, without quoting it', () => {
  for (const given of ['mysql://root:hunter2-secret@db.example.com/coffre', 'postgresql://hunter2-secret', 'hunter2-secret']) {
    const run = setup(['--json'], { stdin: `${given}\n` });
    assert.equal(run.status, 1);
    assert.ok(!run.stderr.includes('hunter2-secret'), run.stderr);
  }
});

test('without a terminal, and without --json, it refuses before reading anything or touching the database', () => {
  const run = setup([], { stdin: 'postgresql://postgres:hunter2-secret@127.0.0.1:9/coffre\n' });
  assert.equal(run.status, 1);
  assert.equal(run.stdout, '');
  assert.match(run.stderr, /coffre setup shows the values it makes on a screen of their own/);
  assert.doesNotMatch(run.stderr, /ECONNREFUSED|Connect/);
});

const made: SetupResult = {
  keys: { APP_KEY: 'A'.repeat(43) + '=', VAULT_KEY_ID: 'vault-2026-10-02-abcdef', VAULT_KEY: 'K'.repeat(43) + '=' },
  app: { role: 'coffre_runtime', login: 'coffre_runtime', password: 'created', url: 'postgresql://coffre_runtime:p1@db.example.com:5432/coffre?sslmode=verify-full' },
  vault: { role: 'coffre_vault_runtime', login: 'coffre_vault_runtime', password: 'created', url: 'postgresql://coffre_vault_runtime:p2@db.example.com:5432/coffre?sslmode=verify-full' },
  hot: { role: 'coffre_vault_hot', login: 'coffre_vault_hot', password: 'created', url: 'postgresql://coffre_vault_hot:p4@db.example.com:5432/coffre?sslmode=verify-full' },
  backup: { role: 'coffre_backup_login', login: 'coffre_backup_login', password: 'created', url: 'postgresql://coffre_backup_login:p3@db.example.com:5432/coffre?sslmode=verify-full' },
  version: '0.1.3',
  // PlanetScale's smallest cluster, by the count third parties give: 6 connections for each config.
  connections: { max: 25, reserved: 3 },
};

test('--json carries the same values as the screen, under the names the examples give them', () => {
  const { app, vault, backup } = setupValues(made);
  const onScreen = Object.fromEntries([...app, ...vault, ...backup].map(({ label, value }) => [label, value]));
  const printed = asJson(made);
  assert.deepEqual(onScreen, {
    'App key': printed.app.APP_KEY,
    'App database URL': printed.app.DATABASE_URL,
    'Vault ID': printed.vault.VAULT_KEY_ID,
    'Vault key': printed.vault.VAULT_KEY,
    'Vault database URL': printed.vault.DATABASE_URL,
    'Hot path database URL': printed.vault.HOT_DATABASE_URL,
    'Backup database URL': printed.backup.DATABASE_URL,
  });
  assert.deepEqual(setupScreen(made).sections.map(({ title, values }) => [title, values.map(({ label }) => label)]), [
    ['App', ['App key', 'App database URL']],
    ['Vault', ['Vault ID', 'Vault key', 'Vault database URL', 'Hot path database URL']],
    ['Backup', ['Backup database URL']],
  ]);
  assert.deepEqual(setupScreen(made).guide.map(({ title }) => title), ['On Cloudflare Workers', 'On Node', 'Backups']);
});

test("only the backup login new, as when a deployment set up before it reruns setup: its URL alone, and where it goes, with nothing to do to the app or the vault", () => {
  const kept = (login: SetupResult['app']) => ({ ...login, password: 'kept' as const, url: null });
  const later: SetupResult = { ...made, keys: null, app: kept(made.app), vault: kept(made.vault), hot: kept(made.hot) };
  const screen = setupScreen(later);
  assert.deepEqual(screen.sections.map(({ title, values }) => [title, values.map(({ label }) => label)]), [['Backup', ['Backup database URL']]]);
  assert.deepEqual(screen.guide.map(({ title }) => title), ['Backups']);
  assert.deepEqual(asJson(later), {
    app: {},
    vault: {},
    backup: { DATABASE_URL: made.backup.url },
    logins: {
      coffre_runtime: { login: 'coffre_runtime', password: 'kept' },
      coffre_vault_runtime: { login: 'coffre_vault_runtime', password: 'kept' },
      coffre_vault_hot: { login: 'coffre_vault_hot', password: 'kept' },
      coffre_backup_login: { login: 'coffre_backup_login', password: 'created' },
    },
  });
  const text = summary(later, { write: () => true, isTTY: false, columns: 200 } as never);
  assert.match(text, /✓ The backup database URL was shown once\.\n\s+It isn't stored anywhere\./);
  assert.match(text, /Backups\s+the backup database URL in your backup job's secrets, for coffre backup: docs\/restore\.md\./);
  assert.doesNotMatch(text, /Workers|Node/, 'the app and the vault go on as they were');
});

test("the configs the screen makes are named after the deployment's Workers: an account holds a name once", () => {
  // A second deployment on the account, its Workers renamed in its files: the template's names are the first's.
  const dir = mkdtempSync(join(tmpdir(), 'coffre-names-'));
  try {
    cpSync(templateDir('workers'), dir, { recursive: true });
    for (const [path, from, to] of [
      ['app/wrangler.jsonc', '"name": "coffre"', '"name": "coffre-staging"'],
      ['vault/wrangler.jsonc', '"name": "coffre-vault"', '"name": "coffre-staging-vault"'],
    ] as const) {
      const text = readFileSync(join(dir, path), 'utf8');
      assert.ok(text.includes(from), `${path} names its Worker as the template does`);
      writeFileSync(join(dir, path), text.replace(from, to));
    }
    const names = workerNames(dir);
    assert.deepEqual(names, { app: 'coffre-staging', vault: 'coffre-staging-vault' });
    const commands = setupScreen(made, names).guide.flatMap(({ lines }) => lines.flatMap((line) => (typeof line === 'string' ? [] : [line.command])));
    assert.deepEqual(commands.slice(0, 3), [
      hyperdriveCommand('create coffre-staging --caching-disabled', 6),
      hyperdriveCommand('create coffre-staging-vault --caching-disabled', 6),
      hyperdriveCommand('create coffre-staging-vault-hot --caching-disabled', 6),
    ]);
    // A file setup cannot read stops it, saying which: the template's names in its place could be another deployment's.
    writeFileSync(join(dir, 'vault/wrangler.jsonc'), readFileSync(join(dir, 'vault/wrangler.jsonc'), 'utf8').replace(/\}\s*$/, ''));
    assert.throws(() => workerNames(dir), /^Error: vault\/wrangler\.jsonc is not valid: /);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a Workers file setup cannot read stops it before it asks for anything", () => {
  const run = setup(['--json'], { stdin: 'postgresql://admin:secret@db.example:5432/coffre\n', workers: true, vault: '{ "name": "coffre-vault"\n' });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /vault\/wrangler\.jsonc is not valid: /);
  assert.doesNotMatch(run.stderr, /Connect|db\.example/, 'it reads no URL and connects to nothing');
});

test('where the values go: new Hyperdrive configs, or after a reset, the ones to update, never with a password in the command', () => {
  const commands = (result: SetupResult) =>
    setupScreen(result).guide.flatMap(({ lines }) => lines.flatMap((line) => (typeof line === 'string' ? [] : [line.command])));
  assert.deepEqual(commands(made).slice(0, 3), [
    hyperdriveCommand('create coffre --caching-disabled', 6),
    hyperdriveCommand('create coffre-vault --caching-disabled', 6),
    hyperdriveCommand('create coffre-vault-hot --caching-disabled', 6),
  ]);
  const reset = {
    ...made,
    keys: null,
    app: { ...made.app, password: 'reset' as const },
    vault: { ...made.vault, password: 'reset' as const },
    hot: { ...made.hot, password: 'reset' as const },
    backup: { ...made.backup, password: 'reset' as const },
  };
  assert.deepEqual(commands(reset), [
    hyperdriveCommand("update <the app's config id>", 6),
    hyperdriveCommand("update <the vault's config id>", 6),
    hyperdriveCommand("update <the hot path's config id>", 6),
  ]);
  for (const command of commands(reset)) assert.match(command, / --origin-connection-limit=6 /);
  // Setup can't see what each config allows now: the screen says the updates set it, why that matters, and when to keep one lower.
  const lines = (result: SetupResult) => setupScreen(result).guide[0]!.lines.filter((line): line is string => typeof line === 'string');
  const check = "Setup can't see the limit each config has now, and the update commands set it to 6. Below that, a call waiting on a lock stops the others on its Hyperdrive shard: leave --origin-connection-limit out only for a config you keep lower because its database serves more than coffre (pnpm exec wrangler hyperdrive get <id> shows its limit).";
  // Said before the commands, so that one kept lower on purpose is not raised by copying them as they are.
  const guide = setupScreen(reset).guide[0]!.lines;
  assert.ok(guide.includes(check) && guide.indexOf(check) < guide.findIndex((line) => typeof line !== 'string'));
  assert.ok(!lines(made).some((line) => line.startsWith("Setup can't see")), 'new configs have no limit yet');
  // A database too small for the three configs: no command that would leave Cloudflare's default in place, but why not.
  const small = { ...made, connections: { max: 15, reserved: 3 } };
  assert.ok(!commands(small).some((command) => command.includes('hyperdrive')));
  assert.deepEqual(lines(small).slice(0, 1), [`No Hyperdrive config for each database URL: ${tooFewConnections(small.connections)}.`]);
  for (const command of [...commands(made), ...commands(reset)]) assert.ok(!/p1|p2|p4|postgresql:/.test(command), command);
  assert.deepEqual(setupScreen(reset).sections.flatMap(({ values }) => values.map(({ label }) => label)), ['App database URL', 'Vault database URL', 'Hot path database URL', 'Backup database URL']);
  // Only the hot path's login new, as after an upgrade: its config to make, and the two kept configs' limits lowered to a third,
  // with no password in the commands, since a share of two may have set them above it.
  const kept = (login: SetupResult['app']) => ({ ...login, password: 'kept' as const, url: null });
  const upgraded = { ...made, keys: null, app: kept(made.app), vault: kept(made.vault), backup: kept(made.backup) };
  assert.deepEqual(commands(upgraded), [
    hyperdriveCommand('create coffre-vault-hot --caching-disabled', 6),
    "pnpm exec wrangler hyperdrive update <the app's config id> --origin-connection-limit=6",
    "pnpm exec wrangler hyperdrive update <the vault's config id> --origin-connection-limit=6",
  ]);
  assert.ok(lines(upgraded).includes("The app's and the vault's configs keep their passwords, and their limits, which setup can't see: one a share of two configs set may be above 6. Lower each to 6, unless it is there or below already:"));
  // Where each goes: the hot path's into vault.env too, under a name of its own, and its config's id beside the vault's.
  const node = setupScreen(made).guide[1]!.lines;
  assert.ok(node.includes('vault.env takes the vault database URL, as DATABASE_URL.') && node.includes('vault.env takes the hot path database URL, as HOT_DATABASE_URL.'));
  assert.ok(lines(made).includes("Their ids go under hyperdrive: the app's in app/wrangler.jsonc, at HYPERDRIVE; the vault's and the hot path's in vault/wrangler.jsonc, at VAULT_HYPERDRIVE and HOT_HYPERDRIVE."));
});

test("what comes next, after a run that made only the hot path's login, as one after an upgrade does", () => {
  const kept = (login: SetupResult['app']) => ({ ...login, password: 'kept' as const, url: null });
  const text = (result: SetupResult) => summary(result, { write: () => true, isTTY: false, columns: 400 } as never);
  const upgraded = text({ ...made, keys: null, app: kept(made.app), vault: kept(made.vault), backup: kept(made.backup) });
  assert.match(upgraded, /✓ The hot path database URL was shown once\./);
  assert.match(upgraded, /Workers\s+a Hyperdrive config for the hot path database URL, with caching off; then pnpm run deploy\./);
  assert.match(upgraded, /Node\s+HOT_DATABASE_URL in vault\.env updated, then the vault restarted\./);
  // With --reset-passwords, the others' configs updated beside it.
  const reset = text({ ...made, keys: null, app: { ...made.app, password: 'reset' }, vault: { ...made.vault, password: 'reset' }, backup: kept(made.backup) });
  assert.match(reset, /Workers\s+a Hyperdrive config for the hot path database URL, with caching off; the app's and the vault's configs updated with their new database URLs; then pnpm run deploy\./);
  assert.match(reset, /Node\s+DATABASE_URL in \.env, DATABASE_URL in vault\.env and HOT_DATABASE_URL in vault\.env updated, then both processes restarted\./);
  assert.match(text(made), /Node\s+\.env and vault\.env, then pnpm vault and pnpm start\./);
});

test("each Hyperdrive config's connection limit is an even share of the database's connections, so that a burst of requests waits in Hyperdrive rather than being refused", () => {
  // PlanetScale's smallest cluster: max_connections 25, 3 kept for superusers.
  // Left at Cloudflare's default, 60 each, the configs opened more than its
  // 22, and a page's parallel reads failed with 53300 (T78). Three configs
  // now, the app's, the vault's and the hot path's, share it.
  const small = { max: 25, reserved: 3 };
  assert.equal(hyperdriveLimit(small), 6);
  assert.equal(limitReason(small, 6), 'max_connections 25, 3 reserved, 3 kept for the administrator and migrations: 6 each');
  // Postgres's default: no more than Free allows, which a query that holds a connection only while it runs never needs.
  const standard = { max: 100, reserved: 3 };
  assert.equal(hyperdriveLimit(standard), 20);
  assert.equal(limitReason(standard, 20), 'max_connections 100, 3 reserved, 3 kept for the administrator and migrations: 31 each, capped at 20');
  // The fewest Hyperdrive takes is 5 per config: below it, setup refuses rather than write a smaller limit.
  assert.equal(hyperdriveLimit({ max: 21, reserved: 3 }), 5);
  assert.equal(hyperdriveLimit({ max: 20, reserved: 3 }), null);
  assert.match(tooFewConnections({ max: 15, reserved: 3 }), /max_connections is 15, 3 of them reserved.*at least 5 for each of coffre's three configs.*raise max_connections to 21 or more/);
  // The guide on setup's screen says what the commands' limit is for, and how it came to it.
  assert.ok(setupScreen(made).guide[0]!.lines.includes(
    "Each command sets its config's connection limit to 6, so that all three configs fit under the database's max_connections, with some left for migrations (max_connections 25, 3 reserved, 3 kept for the administrator and migrations: 6 each).",
  ));
});

test('a limit is only ever lowered: one set lower on purpose is kept, and one not known is set', () => {
  assert.equal(cappedLimit(60, 20), 20, "Cloudflare's default on Paid, lowered");
  assert.equal(cappedLimit(21, 20), 20);
  assert.equal(cappedLimit(20, 20), null, 'at the limit: left alone');
  assert.equal(cappedLimit(5, 20), null, 'set lower on purpose: kept');
  assert.equal(cappedLimit(undefined, 20), 20, 'unset: Cloudflare would apply its default');
  assert.equal(cappedLimit(null, 20), 20, 'not known, as on the manual path');
});

test('a Hyperdrive command reads the URL without echo, and hands wrangler it without its parameters', { skip: spawnSync('bash', ['-c', 'true']).status !== 0 && 'needs bash' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-hyperdrive-'));
  try {
    writeFileSync(join(dir, 'pnpm'), `#!/bin/sh\nprintf '%s\\n' "$@" > "${dir}/argv"\n`);
    chmodSync(join(dir, 'pnpm'), 0o755);
    const url = 'postgresql://coffre_runtime.x7k2:s3cret@eu.pg.psdb.cloud:5432/coffre?sslmode=verify-full&sslrootcert=system';
    const run = spawnSync('bash', ['-c', `${hyperdriveCommand('create coffre --caching-disabled', 6)}; echo "left:[$COFFRE_DB_URL]"`], {
      input: `${url}\n`,
      env: { PATH: `${dir}:${process.env.PATH}` },
      encoding: 'utf8',
    });
    assert.equal(run.stdout, 'left:[]\n', 'nothing echoed, and the variable gone');
    assert.deepEqual(readFileSync(join(dir, 'argv'), 'utf8').trim().split('\n'), [
      'exec', 'wrangler', 'hyperdrive', 'create', 'coffre', '--caching-disabled', '--origin-connection-limit=6',
      '--connection-string=postgresql://coffre_runtime.x7k2:s3cret@eu.pg.psdb.cloud:5432/coffre',
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * A Workers deployment as a fresh clone has it: its files and lockfile, no
 * node_modules. Its pnpm installs the fake wrangler, as pnpm would the real
 * one, and keeps its arguments; or, `refusing`, fails as pnpm does. Its
 * database is the disposable cluster's: setup reads what it lets in before
 * it asks about Cloudflare, and gets no further with it here.
 */
function freshClone(refusing?: string) {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-clone-'));
  const deployment = join(dir, 'secrets');
  cpSync(templateDir('workers'), deployment, { recursive: true, filter: (path) => !path.includes('node_modules') });
  writeFileSync(join(deployment, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\n");
  // What the install brings: the deployment's own wrangler, kept aside until then.
  const state = join(dir, 'wrangler');
  fakeWrangler(join(dir, 'packages'), state, `cf-oauth-${'t'.repeat(40)}`);
  const bin = join(dir, 'bin');
  fakeOpener(bin);
  writeFileSync(
    join(bin, 'pnpm'),
    refusing === undefined
      ? `#!/bin/sh\nprintf '%s\\n' "$@" > '${dir}/pnpm-argv'\ncp -R '${dir}/packages/node_modules' .\nmkdir -p node_modules/.pnpm\ncp pnpm-lock.yaml node_modules/.pnpm/lock.yaml\n`
      : `#!/bin/sh\necho '${refusing}' >&2\nexit 1\n`,
  );
  chmodSync(join(bin, 'pnpm'), 0o755);
  const env = { PATH: `${bin}:${process.env.PATH}`, HOME: dir };
  const url = `${CLUSTER}/postgres`;
  return { dir, deployment, state, env, url, remove: () => rmSync(dir, { recursive: true, force: true }) };
}

test("a fresh clone of a Workers deployment: setup installs it as its lockfile says, then signs in with its own wrangler", { skip: ptySkip || needsCluster.skip }, async () => {
  const clone = freshClone();
  try {
    const { output } = await inTerminal(
      ['setup'],
      clone.env,
      typingUrl(clone.url, async (terminal) => {
        await terminal.waitFor('Set Cloudflare up too?');
        terminal.send('\r');
        // wrangler's login, waiting for its address: the deployment's wrangler ran.
        await terminal.waitFor('paste that address here');
        terminal.send('\x03');
      }),
      { columns: 160, rows: 48 },
      clone.deployment,
    );
    const text = visible(screens(output).main);
    assert.match(text, /✓ Installed its packages, as pnpm-lock\.yaml says[\s\S]*Sign in to Cloudflare/);
    assert.doesNotMatch(text, /ENOENT/);
    assert.deepEqual(readFileSync(join(clone.dir, 'pnpm-argv'), 'utf8').trim().split('\n'), [
      'install',
      '--config.update-notifier=false',
      '--config.confirm-modules-purge=false',
      '--frozen-lockfile',
    ]);
    const calls = readFileSync(join(clone.state, 'calls.jsonl'), 'utf8').trim().split('\n').map((line) => (JSON.parse(line) as { args: string[] }).args.join(' '));
    assert.equal(calls[0], 'auth token --json', 'the deployment\'s wrangler, installed, ran');
  } finally {
    clone.remove();
  }
});

test('when its install fails, setup says why in a sentence, and runs nothing of the deployment', { skip: ptySkip || needsCluster.skip }, async () => {
  const clone = freshClone(' ERR_PNPM_OUTDATED_LOCKFILE  Cannot install with "frozen-lockfile" because pnpm-lock.yaml is not up to date with package.json');
  try {
    const { output, code } = await inTerminal(
      ['setup'],
      clone.env,
      typingUrl(clone.url, async (terminal) => {
        await terminal.waitFor('Set Cloudflare up too?');
        terminal.send('\r');
      }),
      { columns: 160, rows: 48 },
      clone.deployment,
    );
    const text = visible(screens(output).main);
    assert.equal(code, 1, text);
    assert.match(text, /✗ Install its packages\s+pnpm-lock\.yaml doesn't match package\.json, so pnpm won't install from it: run pnpm install here, and commit the lockfile it writes/);
    assert.doesNotMatch(text, /Sign in to Cloudflare|ENOENT/);
    assert.ok(!existsSync(join(clone.state, 'calls.jsonl')), 'no wrangler ran');
  } finally {
    clone.remove();
  }
});

// --- against a disposable cluster -------------------------------------------------------

/** coffre_backup_login's memberships in coffre_backup, one per grantor. */
function membership(name: string) {
  return asSuperuser(name, async (client) =>
    [...await client.unsafe<{ admin: boolean; inherit: boolean; set: boolean }[]>(
      `SELECT admin_option AS admin, inherit_option AS inherit, set_option AS set FROM pg_auth_members
        WHERE roleid = 'coffre_backup'::regrole AND member = 'coffre_backup_login'::regrole`,
    )],
  );
}

/** coffre_vault_hot's membership in coffre_vault, and its settings, which 0022 gives it. */
function hotRole(name: string) {
  return asSuperuser(name, async (client) => ({
    member: [...await client.unsafe<{ admin: boolean; inherit: boolean; set: boolean }[]>(
      `SELECT admin_option AS admin, inherit_option AS inherit, set_option AS set FROM pg_auth_members
        WHERE roleid = 'coffre_vault'::regrole AND member = 'coffre_vault_hot'::regrole`,
    )],
    settings: [...(await client.unsafe<{ setconfig: string[] }[]>(
      "SELECT setconfig FROM pg_db_role_setting WHERE setrole = 'coffre_vault_hot'::regrole AND setdatabase = 0",
    ))[0]?.setconfig ?? []].filter((setting) => !setting.startsWith('jit=')).sort(),
  }));
}

/** The log's entries, by action, as `url`'s login sees them. */
async function logEntries(url: string): Promise<string[]> {
  const client = postgresClient(url, { max: 1 });
  try {
    return (await client.unsafe<{ action: string }[]>('SELECT action FROM audit_log ORDER BY seq')).map(({ action }) => action);
  } finally {
    await client.end();
  }
}

beforeEach(async () => {
  if (CLUSTER !== undefined) await emptyCluster();
});

for (const as of ['superuser', 'owner'] as const) {
  test(`as ${as === 'owner' ? 'an owner' : 'a superuser'}: makes the logins, migrates, checks the boundary, and shows every value once`, needsCluster, async () => {
    const url = await database(`setup_${as}`, as);
    const first = setup(['--json'], { stdin: `${url}\n` });
    const shown = json(first);
    assertNoAdministrator(first, url);
    assert.match(first.stderr, /✓ Created coffre_runtime, coffre_vault_runtime, coffre_vault_hot and coffre_backup_login\n/);
    const count = KNOWN_MIGRATIONS.postgres.length;
    assert.match(first.stderr, new RegExp(`✓ Migrated the database to coffre \\S+'s schema: ${count} migration${count === 1 ? '' : 's'} applied\n`));
    assert.match(first.stderr, /\n\s+coffre_backup_login is a member of coffre_backup, which reads every row and writes none\n/);
    assert.match(
      first.stderr,
      /coffre_runtime\s+can read the log; cannot write members, delete log entries or create tables\n\s+coffre_vault_runtime\s+can read the log and write members; cannot delete log entries or create tables\n\s+coffre_vault_hot\s+can read the log and write members; cannot delete log entries or create tables\n\s+coffre_backup_login\s+can read the log; cannot write members, delete log entries or create tables\n/,
    );
    assert.deepEqual(shown.logins, {
      coffre_runtime: { login: 'coffre_runtime', password: 'created' },
      coffre_vault_runtime: { login: 'coffre_vault_runtime', password: 'created' },
      coffre_vault_hot: { login: 'coffre_vault_hot', password: 'created' },
      coffre_backup_login: { login: 'coffre_backup_login', password: 'created' },
    });
    // The hot path's login, made before the migrations, which took it as a host's: the vault's, with the hot path's settings.
    assert.equal(new URL(shown.vault.HOT_DATABASE_URL!).username, 'coffre_vault_hot');
    assert.ok(await connects(shown.vault.HOT_DATABASE_URL!));
    assert.deepEqual(await hotRole(`setup_${as}`), { member: [{ admin: false, inherit: true, set: false }], settings: ['lock_timeout=1s', 'plan_cache_mode=force_generic_plan', 'statement_timeout=2s'] });
    assert.equal(new URL(shown.backup.DATABASE_URL!).username, 'coffre_backup_login');
    assert.ok(await connects(shown.backup.DATABASE_URL!));
    assert.deepEqual(await membership(`setup_${as}`), [{ admin: false, inherit: true, set: false }], 'a member of coffre_backup, as --backup-login grants it');
    assert.match(shown.vault.VAULT_KEY_ID!, /^vault-\d{4}-\d{2}-\d{2}-[a-z2-7]{6}$/);
    for (const key of [shown.vault.VAULT_KEY!, shown.app.APP_KEY!]) assert.equal(Buffer.from(key, 'base64').length, 32);
    assert.equal(new URL(shown.app.DATABASE_URL!).username, 'coffre_runtime');
    assert.equal(new URL(shown.vault.DATABASE_URL!).username, 'coffre_vault_runtime');
    assert.ok(await connects(shown.app.DATABASE_URL!));
    assert.ok(await connects(shown.vault.DATABASE_URL!));
    const stored = await asSuperuser(`setup_${as}`, async (client) => ({
      verifiers: (await client.unsafe<{ rolpassword: string }[]>(
        "SELECT rolpassword FROM pg_authid WHERE rolname IN ('coffre_runtime', 'coffre_vault_runtime', 'coffre_vault_hot', 'coffre_backup_login') ORDER BY rolname",
      )).map((row) => row.rolpassword),
      migrations: (await client.unsafe('SELECT hash FROM drizzle.__drizzle_migrations')).count,
    }));
    assert.equal(stored.verifiers.length, 4);
    for (const verifier of stored.verifiers) assert.match(verifier, /^SCRAM-SHA-256\$4096:/);
    assert.ok(stored.migrations! > 0);

    // Again, piped in, without --reset-passwords: nothing changes, and nothing is shown.
    const again = setup(['--json'], { stdin: `${url}\n` });
    assert.deepEqual(json(again), {
      app: {},
      vault: {},
      backup: {},
      logins: {
        coffre_runtime: { login: 'coffre_runtime', password: 'kept' },
        coffre_vault_runtime: { login: 'coffre_vault_runtime', password: 'kept' },
        coffre_vault_hot: { login: 'coffre_vault_hot', password: 'kept' },
        coffre_backup_login: { login: 'coffre_backup_login', password: 'kept' },
      },
    });
    assert.match(again.stderr, /✓ Kept coffre_runtime, coffre_vault_runtime, coffre_vault_hot and coffre_backup_login, with their passwords/);
    assert.match(again.stderr, /✓ The database is up to date/);
    assert.match(again.stderr, /coffre_runtime, coffre_vault_runtime, coffre_vault_hot and coffre_backup_login: from the catalog, with no new password to log in with/);
    assertNoAdministrator(again, url);
    assert.deepEqual(
      await asSuperuser(`setup_${as}`, async (client) => ({
        verifiers: (await client.unsafe<{ rolpassword: string }[]>(
          "SELECT rolpassword FROM pg_authid WHERE rolname IN ('coffre_runtime', 'coffre_vault_runtime', 'coffre_vault_hot', 'coffre_backup_login') ORDER BY rolname",
        )).map((row) => row.rolpassword),
        migrations: (await client.unsafe('SELECT hash FROM drizzle.__drizzle_migrations')).count,
      })),
      stored,
    );
    assert.deepEqual(await membership(`setup_${as}`), [{ admin: false, inherit: true, set: false }], 'granted again, not twice');
    assert.ok(await connects(shown.app.DATABASE_URL!), 'the first passwords still work');

    // With --reset-passwords: new ones, and the old stop working. The database is still unused, so new keys come with them.
    const reset = json(setup(['--reset-passwords', '--json'], { stdin: `${url}\n` }));
    assert.equal(reset.logins.coffre_runtime!.password, 'reset');
    assert.equal(reset.logins.coffre_backup_login!.password, 'reset');
    assert.ok(await connects(reset.app.DATABASE_URL!));
    assert.ok(await connects(reset.vault.DATABASE_URL!));
    assert.equal(reset.logins.coffre_vault_hot!.password, 'reset');
    assert.ok(await connects(reset.vault.HOT_DATABASE_URL!));
    assert.equal(await connects(shown.vault.HOT_DATABASE_URL!), false);
    assert.ok(await connects(reset.backup.DATABASE_URL!));
    assert.equal(await connects(shown.app.DATABASE_URL!), false);
    assert.equal(await connects(shown.backup.DATABASE_URL!), false);
    assert.ok(reset.vault.VAULT_KEY !== undefined && reset.vault.VAULT_KEY !== shown.vault.VAULT_KEY);
  });
}

test("a Workers deployment whose database can't hold the three Hyperdrive configs: setup refuses before anything else, and every login keeps its password", { skip: SMALL_CLUSTER === undefined && 'needs the small cluster: scripts/test-setup.sh' }, async () => {
  // 15 connections, 3 of them for superusers: 3 for each config, short of Hyperdrive's 5.
  await emptyCluster(SMALL_CLUSTER);
  await asSuperuser('postgres', (client) => client.unsafe('CREATE DATABASE setup_small'), SMALL_CLUSTER);
  const url = `${SMALL_CLUSTER}/setup_small`;
  const verifiers = () =>
    asSuperuser('postgres', async (client) =>
      [...await client.unsafe<{ rolname: string; rolpassword: string }[]>(
        "SELECT rolname, rolpassword FROM pg_authid WHERE rolname IN ('coffre_runtime', 'coffre_vault_runtime') ORDER BY rolname",
      )], SMALL_CLUSTER);
  try {
    // A fresh database: nothing made, nothing migrated, and the commands it would show never shown.
    const fresh = setup(['--json'], { stdin: `${url}\n`, workers: true });
    assert.equal(fresh.status, 1, fresh.stderr);
    assert.match(fresh.stderr, /✗ Check 127\.0\.0\.1\/setup_small has room for Hyperdrive\n\s+the database's max_connections is 15, 3 of them reserved; Hyperdrive takes at least 5 for each of coffre's three configs, .*raise max_connections to 21 or more/s);
    assert.equal(fresh.stdout, '');
    assert.deepEqual(await verifiers(), []);
    assertNoAdministrator(fresh, url);

    // Not a Workers deployment, which needs no Hyperdrive: set up as ever.
    const node = json(setup(['--json'], { stdin: `${url}\n` }));
    const before = await verifiers();
    assert.equal(before.length, 2);

    // --reset-passwords in the Workers deployment: refused before the new
    // passwords, which Hyperdrive would never have got, so the running app
    // keeps logging in with the ones it has.
    const reset = setup(['--reset-passwords', '--json'], { stdin: `${url}\n`, workers: true });
    assert.equal(reset.status, 1, reset.stderr);
    assert.match(reset.stderr, /✗ Check .*raise max_connections to 21 or more/s);
    assert.doesNotMatch(reset.stderr, /✓ (Set new passwords|Created|Kept|Migrated|The database is up to date)/, 'no step after it ran');
    assert.deepEqual(await verifiers(), before);
    assert.ok(await connects(node.app.DATABASE_URL!));
    assert.ok(await connects(node.vault.DATABASE_URL!));
  } finally {
    await emptyCluster(SMALL_CLUSTER);
  }
});

test('a database that holds data gets new passwords but no keys: its keys are the ones it was set up with', needsCluster, async () => {
  const url = await database('setup_used', 'superuser');
  const first = json(setup(['--json'], { stdin: `${url}\n` }));
  const vault = postgresClient(first.vault.DATABASE_URL!, { max: 1 });
  await vault.unsafe(`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
    VALUES (0, 'vault', 'vault:probe', 0, 'system:vault', 'key.check', 'allow', '{}', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))`);
  await vault.end();
  const after = json(setup(['--reset-passwords', '--json'], { stdin: `${url}\n` }));
  assert.deepEqual(Object.keys(after.app), ['DATABASE_URL']);
  assert.deepEqual(Object.keys(after.vault), ['DATABASE_URL', 'HOT_DATABASE_URL']);
  assert.ok(await connects(after.vault.DATABASE_URL!));
  // The backup login reads the vault's entry, through coffre_backup's policy on the log.
  assert.deepEqual(await logEntries(after.backup.DATABASE_URL!), ['key.check']);
});

test('a deployment set up before setup made the backup login: a rerun makes it, or takes one made by hand, and grants it its group, the others kept', needsCluster, async () => {
  const url = await database('setup_later', 'owner');
  const first = json(setup(['--json'], { stdin: `${url}\n` }));
  // As a deployment set up before has it: no backup login.
  await asSuperuser('setup_later', (client) => client.unsafe('DROP ROLE coffre_backup_login'));
  const made = setup(['--json'], { stdin: `${url}\n` });
  const shown = json(made);
  assert.match(made.stderr, /✓ Kept coffre_runtime, coffre_vault_runtime and coffre_vault_hot, with their passwords; created coffre_backup_login\n/);
  assert.deepEqual(Object.keys(shown.app), [], 'no key for a deployment that has its own');
  assert.deepEqual(Object.keys(shown.vault), []);
  assert.deepEqual(Object.keys(shown.backup), ['DATABASE_URL']);
  assert.ok(await connects(first.app.DATABASE_URL!), 'the app keeps its password');
  assert.deepEqual(await logEntries(shown.backup.DATABASE_URL!), []);
  assert.deepEqual(await membership('setup_later'), [{ admin: false, inherit: true, set: false }]);

  // Made by setup, then unable to log in, as a Cloudflare run stopped before it showed the password leaves it: given one, unasked, the others kept.
  await asSuperuser('setup_later', (client) => client.unsafe('ALTER ROLE coffre_backup_login NOLOGIN'));
  const locked = setup(['--json'], { stdin: `${url}\n` });
  const unlocked = json(locked);
  assert.match(locked.stderr, /✓ Kept coffre_runtime, coffre_vault_runtime and coffre_vault_hot, with their passwords; set a new password for coffre_backup_login\n/);
  assert.deepEqual(Object.keys(unlocked.backup), ['DATABASE_URL']);
  assert.deepEqual(await logEntries(unlocked.backup.DATABASE_URL!), []);
  assert.equal(await connects(shown.backup.DATABASE_URL!), false, 'the password the run before set, replaced');

  // Made by hand, as Terraform does, with no group: kept as it is, its password included, and granted the group.
  await asSuperuser('setup_later', async (client) => {
    await client.unsafe('DROP ROLE coffre_backup_login');
    await client.unsafe("CREATE ROLE coffre_backup_login LOGIN PASSWORD 'by-hand-p4ss'");
  });
  const byHand = setup(['--json'], { stdin: `${url}\n` });
  assert.equal(json(byHand).logins.coffre_backup_login!.password, 'kept');
  assert.match(byHand.stderr, /coffre_backup_login\s+can read the log; cannot write members, delete log entries or create tables\n/);
  const login = new URL(url);
  login.username = 'coffre_backup_login';
  login.password = 'by-hand-p4ss';
  assert.deepEqual(await logEntries(login.href), []);
  assert.deepEqual(await membership('setup_later'), [{ admin: false, inherit: true, set: false }]);

  // One another role made, unable to log in: on Postgres 16, the owner may not change it without its ADMIN. Said so, before the others change.
  await asSuperuser('setup_later', (client) => client.unsafe('ALTER ROLE coffre_backup_login NOLOGIN'));
  const refused = setup(['--reset-passwords', '--json'], { stdin: `${url}\n` });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /✗ Make the four logins\n\s+setup_owner may not change coffre_backup_login, which another role made: have that role grant setup_owner ADMIN on coffre_backup_login, or drop coffre_backup_login, then run coffre setup again/);
  assert.ok(await connects(first.app.DATABASE_URL!), 'the app keeps its password');
  assert.ok(await connects(first.vault.DATABASE_URL!), 'the vault keeps its password');
});

test("a deployment migrated before setup made the hot path's login: 0022 made it unable to log in, and a rerun makes it one, the others kept", needsCluster, async () => {
  const url = await database('setup_hot', 'owner');
  const first = json(setup(['--json'], { stdin: `${url}\n` }));
  // As 0022 leaves it on a database set up before: a role that cannot log in, and has no password.
  await asSuperuser('setup_hot', (client) => client.unsafe('ALTER ROLE coffre_vault_hot NOLOGIN PASSWORD NULL'));
  const made = setup(['--json'], { stdin: `${url}\n` });
  const shown = json(made);
  // Unasked, and said made: no Hyperdrive config can have logged in as it, so its config is to make, not update.
  assert.match(made.stderr, /✓ Kept coffre_runtime, coffre_vault_runtime and coffre_backup_login, with their passwords; created coffre_vault_hot\n/);
  assert.match(made.stderr, /coffre_vault_hot\s+can read the log and write members; cannot delete log entries or create tables\n/);
  assert.deepEqual(Object.keys(shown.app), [], 'no key for a deployment that has its own');
  assert.deepEqual(Object.keys(shown.vault), ['HOT_DATABASE_URL']);
  assert.ok(await connects(shown.vault.HOT_DATABASE_URL!));
  assert.ok(await connects(first.app.DATABASE_URL!), 'the app keeps its password');
  assert.ok(await connects(first.vault.DATABASE_URL!), 'the vault keeps its password');
  assert.deepEqual(await hotRole('setup_hot'), { member: [{ admin: false, inherit: true, set: false }], settings: ['lock_timeout=1s', 'plan_cache_mode=force_generic_plan', 'statement_timeout=2s'] });

  // Dropped after 0022 ran, which never runs again: setup makes it, and the migrate run gives it its group and settings, so every new password works.
  await asSuperuser('setup_hot', (client) => client.unsafe('DROP ROLE coffre_vault_hot'));
  const remade = setup(['--reset-passwords', '--json'], { stdin: `${url}\n` });
  const again = json(remade);
  assert.match(remade.stderr, /coffre_vault_hot\s+can read the log and write members; cannot delete log entries or create tables\n/);
  assert.equal(again.logins.coffre_vault_hot!.password, 'created');
  for (const each of [again.app.DATABASE_URL!, again.vault.DATABASE_URL!, again.vault.HOT_DATABASE_URL!]) assert.ok(await connects(each));
  assert.deepEqual(await hotRole('setup_hot'), { member: [{ admin: false, inherit: true, set: false }], settings: ['lock_timeout=1s', 'plan_cache_mode=force_generic_plan', 'statement_timeout=2s'] });

  // Remade with a setting for this database alone, which would outrank the hot path's at login: refused, as 0022 refuses it, saying what to run.
  await asSuperuser('setup_hot', async (client) => {
    await client.unsafe('DROP ROLE coffre_vault_hot');
    await client.unsafe('CREATE ROLE coffre_vault_hot NOLOGIN');
    await client.unsafe('GRANT coffre_vault_hot TO setup_owner WITH ADMIN TRUE');
    await client.unsafe('ALTER ROLE coffre_vault_hot IN DATABASE setup_hot SET statement_timeout = 0');
  });
  const outranked = setup(['--json'], { stdin: `${url}\n` });
  assert.equal(outranked.status, 1);
  assert.match(outranked.stderr, /✗ Checking the database is up to date\n\s+the database is at the migrated schema, but reasserting its privileges failed: coffre_vault_hot has its own lock_timeout, statement_timeout or plan_cache_mode in this database, over the hot path's: run ALTER ROLE coffre_vault_hot IN DATABASE setup_hot RESET ALL/);
  assert.equal(outranked.stdout, '', 'no URL shown for a login without its bounds');

  // Remade with a membership that may grant coffre_vault, to the app's login say: refused, as 0022 refuses it.
  await asSuperuser('setup_hot', async (client) => {
    await client.unsafe('DROP ROLE coffre_vault_hot');
    await client.unsafe('CREATE ROLE coffre_vault_hot NOLOGIN');
    await client.unsafe('GRANT coffre_vault_hot TO setup_owner WITH ADMIN TRUE');
    await client.unsafe('GRANT coffre_vault TO coffre_vault_hot WITH ADMIN TRUE, INHERIT TRUE, SET FALSE');
  });
  const granting = setup(['--json'], { stdin: `${url}\n` });
  assert.equal(granting.status, 1);
  assert.match(granting.stderr, /reasserting its privileges failed: coffre_vault_hot may set or grant coffre_vault: have its grantor run REVOKE coffre_vault FROM coffre_vault_hot/);
  assert.equal(granting.stdout, '');

  // One another role made, unable to log in: on Postgres 16, the owner may not change it without its ADMIN. Said so, before the app's and the vault's change.
  await asSuperuser('setup_hot', async (client) => {
    await client.unsafe('DROP ROLE coffre_vault_hot');
    await client.unsafe('CREATE ROLE coffre_vault_hot NOLOGIN');
  });
  const refused = setup(['--reset-passwords', '--json'], { stdin: `${url}\n` });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /✗ Make the four logins\n\s+setup_owner may not change coffre_vault_hot, which another role made: have that role grant setup_owner ADMIN on coffre_vault_hot, or drop coffre_vault_hot, then run coffre setup again/);
  assert.ok(await connects(again.app.DATABASE_URL!), 'the app keeps its password');
  assert.ok(await connects(again.vault.DATABASE_URL!), 'the vault keeps its password');
});

test("the hot path's URL logs in under its own bounds: the administrator's session settings are left out of it, and one it cannot leave out is refused", needsCluster, async () => {
  const url = await database('setup_hot_url', 'superuser');
  const loose = new URL(url);
  loose.searchParams.set('statement_timeout', '0');
  loose.searchParams.set('lock_timeout', '0');
  const shown = json(setup(['--json'], { stdin: `${loose.href}\n` }));
  const hot = new URL(shown.vault.HOT_DATABASE_URL!);
  assert.deepEqual([hot.searchParams.has('statement_timeout'), hot.searchParams.has('lock_timeout')], [false, false]);
  assert.equal(new URL(shown.vault.DATABASE_URL!).searchParams.get('statement_timeout'), '0', "the vault's URL, as the administrator's");
  const client = postgresClient(hot.href, { max: 1 });
  try {
    const [held] = await client.unsafe<{ statement: string; lock: string }[]>("SELECT current_setting('statement_timeout') AS statement, current_setting('lock_timeout') AS lock");
    assert.deepEqual(held, { statement: '2s', lock: '1s' });
  } finally {
    await client.end();
  }
  // A setting in its options, which a URL's own parameters cannot say apart from a host's: refused before anything is shown.
  const options = new URL(url);
  options.searchParams.set('options', '-c plan_cache_mode=auto');
  const refused = setup(['--reset-passwords', '--json'], { stdin: `${options.href}\n` });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /coffre_vault_hot logs in with plan_cache_mode auto, not the hot path's plan_cache_mode force_generic_plan/);
  assert.equal(refused.stdout, '');
});

test('a boundary that is not what coffre needs fails, and shows nothing', needsCluster, async () => {
  const url = await database('setup_loose', 'superuser');
  json(setup(['--json'], { stdin: `${url}\n` }));
  await asSuperuser('setup_loose', (client) => client.unsafe('GRANT INSERT ON vault_members TO coffre_app'));
  for (const args of [['--reset-passwords', '--json'], ['--json']]) {
    const run = setup(args, { stdin: `${url}\n` });
    assert.equal(run.status, 1);
    assert.match(run.stderr, /✗ Check each login's rights\n\s+coffre_runtime can write members: the database's privileges are not what coffre needs/);
    assert.equal(run.stdout, '');
    assertNoAdministrator(run, url);
  }
});

test('a wrong password, or a login that cannot create roles, is refused without quoting the connection string', needsCluster, async () => {
  const url = await database('setup_wrong', 'superuser');
  const wrong = new URL(url);
  wrong.password = 'not-the-password';
  const refused = setup(['--json'], { stdin: `${wrong.href}\n` });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /✗ Connect to 127\.0\.0\.1\/setup_wrong\n\s+password authentication failed/);
  assertNoAdministrator(refused, wrong.href);

  await asSuperuser('postgres', (client) => client.unsafe("CREATE ROLE setup_owner LOGIN PASSWORD 'owner-only-p4ss'"));
  const plain = new URL(url);
  plain.username = 'setup_owner';
  plain.password = 'owner-only-p4ss';
  const weak = setup(['--json'], { stdin: `${plain.href}\n` });
  assert.equal(weak.status, 1);
  assert.match(weak.stderr, /✗ Check setup_owner can create roles\n\s+setup_owner cannot create roles/);
  assertNoAdministrator(weak, plain.href);
});

test('on a terminal: the steps on the main screen, the values on the alternate screen alone, and working', { skip: needsCluster.skip || ptySkip }, async () => {
  const url = await database('setup_terminal', 'owner');
  const { output, code } = await inTerminal(['setup'], { PATH: process.env.PATH, HOME: tmpdir() }, typingUrl(url, async (terminal) => {
    await terminal.waitFor('reveal all');
    terminal.send('R');
    await terminal.waitFor('Vault database URL');
    terminal.send('q');
    await terminal.waitFor('Have you saved all 7 values?');
    terminal.send('y');
    await terminal.waitFor('were shown once');
  }));
  assert.equal(code, 0);
  const { main, alternate } = screens(output);
  assert.match(visible(main), /✓ Each login holds only its rights/);
  const urls = [...new Set(visible(alternate).match(/postgresql:\/\/coffre_(?:(?:vault_)?runtime|vault_hot|backup_login):[A-Za-z0-9_-]{32}@[^\s']+/g))];
  const keys = [...new Set(visible(alternate).match(/[A-Za-z0-9+/]{43}=/g))];
  assert.equal(urls.length, 4);
  assert.equal(keys.length, 2);
  for (const secret of [...urls.map((each) => new URL(each).password), ...keys]) assert.ok(!main.includes(secret), 'a secret on the main screen');
  for (const each of urls) assert.ok(await connects(each), 'a URL shown that does not connect');
  assert.ok(!output.includes(new URL(url).password), "the administrator's password");
});
