import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';

import { asJson, hyperdriveCommand, loginFor, loginUrl, scramVerifier, setupScreen, setupValues, type SetupResult } from '../src/setup.ts';
import { inTerminal, ptySkip, screens, visible } from './pty.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));

/**
 * A superuser's URL, without a database, to a disposable Postgres cluster:
 * roles are cluster-wide, so these tests make and drop coffre's own.
 * scripts/test-setup.sh starts one, from `pnpm test:schema`.
 */
const CLUSTER = process.env.COFFRE_TEST_SETUP_CLUSTER;
const needsCluster = { skip: CLUSTER === undefined && 'needs a disposable cluster: scripts/test-setup.sh' };

type Run = { status: number | null; stdout: string; stderr: string };

/** `coffre setup` as an operator runs it, in an empty directory with no home: the URL from the environment, or piped in. */
function setup(args: string[], how: { env?: string; stdin?: string }): Run {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-setup-'));
  try {
    const result = spawnSync(process.execPath, ['--conditions=coffre:source', main, 'setup', ...args], {
      cwd: dir,
      env: { PATH: process.env.PATH, HOME: dir, ...(how.env === undefined ? {} : { COFFRE_SETUP_DATABASE_URL: how.env }) },
      input: how.stdin ?? '',
      encoding: 'utf8',
    });
    assert.deepEqual(readdirSync(dir), [], 'it writes no file');
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
    vault: { VAULT_KEY_ID?: string; VAULT_KEY?: string; DATABASE_URL?: string };
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
  for (const args of [[url], [`--url=${url}`]]) {
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
  version: '0.1.3',
};

test('--json carries the same values as the screen, under the names the examples give them', () => {
  const { app, vault } = setupValues(made);
  const onScreen = Object.fromEntries([...app, ...vault].map(({ label, value }) => [label, value]));
  const printed = asJson(made);
  assert.deepEqual(onScreen, {
    'App key': printed.app.APP_KEY,
    'App database URL': printed.app.DATABASE_URL,
    'Vault ID': printed.vault.VAULT_KEY_ID,
    'Vault key': printed.vault.VAULT_KEY,
    'Vault database URL': printed.vault.DATABASE_URL,
  });
  assert.deepEqual(setupScreen(made).sections.map(({ title, values }) => [title, values.map(({ label }) => label)]), [
    ['App', ['App key', 'App database URL']],
    ['Vault', ['Vault ID', 'Vault key', 'Vault database URL']],
  ]);
});

test('where the values go: new Hyperdrive configs, or after a reset, the ones to update, never with a password in the command', () => {
  const commands = (result: SetupResult) =>
    setupScreen(result).guide.flatMap(({ lines }) => lines.flatMap((line) => (typeof line === 'string' ? [] : [line.command])));
  assert.deepEqual(commands(made).slice(0, 2), [
    hyperdriveCommand('create coffre --caching-disabled'),
    hyperdriveCommand('create coffre-vault --caching-disabled'),
  ]);
  const reset = { ...made, keys: null, app: { ...made.app, password: 'reset' as const }, vault: { ...made.vault, password: 'reset' as const } };
  assert.deepEqual(commands(reset), [hyperdriveCommand("update <the app's config id>"), hyperdriveCommand("update <the vault's config id>")]);
  for (const command of [...commands(made), ...commands(reset)]) assert.ok(!/p1|p2|postgresql:/.test(command), command);
  assert.deepEqual(setupScreen(reset).sections.flatMap(({ values }) => values.map(({ label }) => label)), ['App database URL', 'Vault database URL']);
});

test('a Hyperdrive command reads the URL without echo, and hands wrangler it without its parameters', { skip: spawnSync('bash', ['-c', 'true']).status !== 0 && 'needs bash' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-hyperdrive-'));
  try {
    writeFileSync(join(dir, 'pnpm'), `#!/bin/sh\nprintf '%s\\n' "$@" > "${dir}/argv"\n`);
    chmodSync(join(dir, 'pnpm'), 0o755);
    const url = 'postgresql://coffre_runtime.x7k2:s3cret@eu.pg.psdb.cloud:5432/coffre?sslmode=verify-full&sslrootcert=system';
    const run = spawnSync('bash', ['-c', `${hyperdriveCommand('create coffre --caching-disabled')}; echo "left:[$COFFRE_DB_URL]"`], {
      input: `${url}\n`,
      env: { PATH: `${dir}:${process.env.PATH}` },
      encoding: 'utf8',
    });
    assert.equal(run.stdout, 'left:[]\n', 'nothing echoed, and the variable gone');
    assert.deepEqual(readFileSync(join(dir, 'argv'), 'utf8').trim().split('\n'), [
      'exec', 'wrangler', 'hyperdrive', 'create', 'coffre', '--caching-disabled',
      '--connection-string=postgresql://coffre_runtime.x7k2:s3cret@eu.pg.psdb.cloud:5432/coffre',
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- against a disposable cluster -------------------------------------------------------

async function asSuperuser<T>(database: string, work: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: `${CLUSTER}/${database}` });
  await client.connect();
  try {
    return await work(client);
  } finally {
    await client.end();
  }
}

/** Connect as `url`, and say whether it worked. */
async function connects(url: string): Promise<boolean> {
  const client = new pg.Client({ connectionString: url });
  try {
    await client.connect();
    await client.query('SELECT count(*) FROM vault_members');
    return true;
  } catch {
    return false;
  } finally {
    await client.end().catch(() => {});
  }
}

/** The cluster as a fresh managed service's: no coffre roles, no databases of ours. */
async function emptyCluster(): Promise<void> {
  await asSuperuser('postgres', async (client) => {
    for (const { datname } of (await client.query<{ datname: string }>("SELECT datname FROM pg_database WHERE datname LIKE 'setup\\_%'")).rows) {
      await client.query(`DROP DATABASE ${client.escapeIdentifier(datname)} WITH (FORCE)`);
    }
    await client.query('DROP ROLE IF EXISTS coffre_runtime, coffre_vault_runtime, coffre_app, coffre_vault, setup_owner');
  });
}

/**
 * A database, and the URL of its administrator: the superuser, or an owner
 * as PlanetScale and other managed hosts give one, with CREATEROLE and
 * CREATEDB but neither superuser nor any role's membership.
 */
async function database(name: string, as: 'superuser' | 'owner'): Promise<string> {
  if (as === 'superuser') {
    await asSuperuser('postgres', (client) => client.query(`CREATE DATABASE ${name}`));
    return `${CLUSTER}/${name}`;
  }
  await asSuperuser('postgres', (client) => client.query("CREATE ROLE setup_owner LOGIN CREATEROLE CREATEDB PASSWORD 'owner-only-p4ss'"));
  const owner = new URL(CLUSTER!);
  owner.username = 'setup_owner';
  owner.password = 'owner-only-p4ss';
  const client = new pg.Client({ connectionString: `${owner.href.replace(/\/$/, '')}/postgres` });
  await client.connect();
  await client.query(`CREATE DATABASE ${name}`);
  await client.end();
  return `${owner.href.replace(/\/$/, '')}/${name}`;
}

beforeEach(async () => {
  if (CLUSTER !== undefined) await emptyCluster();
});

for (const as of ['superuser', 'owner'] as const) {
  test(`as ${as === 'owner' ? 'an owner' : 'a superuser'}: makes the logins, migrates, checks the boundary, and shows every value once`, needsCluster, async () => {
    const url = await database(`setup_${as}`, as);
    const first = setup(['--json'], { env: url });
    const shown = json(first);
    assertNoAdministrator(first, url);
    assert.match(first.stderr, /✓ Created coffre_runtime and coffre_vault_runtime\n/);
    assert.match(first.stderr, /✓ Migrated the database to coffre \S+'s schema: 1 migration applied\n/);
    assert.match(first.stderr, /coffre_runtime\s+cannot write members, delete log entries or create tables\n\s+coffre_vault_runtime\s+can write members; cannot delete log entries or create tables\n/);
    assert.deepEqual(shown.logins, {
      coffre_runtime: { login: 'coffre_runtime', password: 'created' },
      coffre_vault_runtime: { login: 'coffre_vault_runtime', password: 'created' },
    });
    assert.match(shown.vault.VAULT_KEY_ID!, /^vault-\d{4}-\d{2}-\d{2}-[a-z2-7]{6}$/);
    for (const key of [shown.vault.VAULT_KEY!, shown.app.APP_KEY!]) assert.equal(Buffer.from(key, 'base64').length, 32);
    assert.equal(new URL(shown.app.DATABASE_URL!).username, 'coffre_runtime');
    assert.equal(new URL(shown.vault.DATABASE_URL!).username, 'coffre_vault_runtime');
    assert.ok(await connects(shown.app.DATABASE_URL!));
    assert.ok(await connects(shown.vault.DATABASE_URL!));
    const stored = await asSuperuser(`setup_${as}`, async (client) => ({
      verifiers: (await client.query<{ rolpassword: string }>(
        "SELECT rolpassword FROM pg_authid WHERE rolname IN ('coffre_runtime', 'coffre_vault_runtime') ORDER BY rolname",
      )).rows.map((row) => row.rolpassword),
      migrations: (await client.query('SELECT hash FROM drizzle.__drizzle_migrations')).rowCount,
    }));
    for (const verifier of stored.verifiers) assert.match(verifier, /^SCRAM-SHA-256\$4096:/);
    assert.ok(stored.migrations! > 0);

    // Again, piped in, without --reset-passwords: nothing changes, and nothing is shown.
    const again = setup(['--json'], { stdin: `${url}\n` });
    assert.deepEqual(json(again), {
      app: {},
      vault: {},
      logins: {
        coffre_runtime: { login: 'coffre_runtime', password: 'kept' },
        coffre_vault_runtime: { login: 'coffre_vault_runtime', password: 'kept' },
      },
    });
    assert.match(again.stderr, /✓ Kept coffre_runtime and coffre_vault_runtime, with their passwords/);
    assert.match(again.stderr, /✓ The database is up to date/);
    assert.match(again.stderr, /coffre_runtime and coffre_vault_runtime: from the catalog, with no new password to log in with/);
    assertNoAdministrator(again, url);
    assert.deepEqual(
      await asSuperuser(`setup_${as}`, async (client) => ({
        verifiers: (await client.query<{ rolpassword: string }>(
          "SELECT rolpassword FROM pg_authid WHERE rolname IN ('coffre_runtime', 'coffre_vault_runtime') ORDER BY rolname",
        )).rows.map((row) => row.rolpassword),
        migrations: (await client.query('SELECT hash FROM drizzle.__drizzle_migrations')).rowCount,
      })),
      stored,
    );
    assert.ok(await connects(shown.app.DATABASE_URL!), 'the first passwords still work');

    // With --reset-passwords: new ones, and the old stop working. The database is still unused, so new keys come with them.
    const reset = json(setup(['--reset-passwords', '--json'], { env: url }));
    assert.equal(reset.logins.coffre_runtime!.password, 'reset');
    assert.ok(await connects(reset.app.DATABASE_URL!));
    assert.ok(await connects(reset.vault.DATABASE_URL!));
    assert.equal(await connects(shown.app.DATABASE_URL!), false);
    assert.ok(reset.vault.VAULT_KEY !== undefined && reset.vault.VAULT_KEY !== shown.vault.VAULT_KEY);
  });
}

test('a database that holds data gets new passwords but no keys: its keys are the ones it was set up with', needsCluster, async () => {
  const url = await database('setup_used', 'superuser');
  const first = json(setup(['--json'], { env: url }));
  const vault = new pg.Client({ connectionString: first.vault.DATABASE_URL });
  await vault.connect();
  await vault.query(`INSERT INTO audit_log (seq, author, key_id, occurred_at, actor, action, decision, metadata, prev_hash, mac, hash)
    VALUES (0, 'vault', 'vault:probe', 0, 'system:vault', 'key.check', 'allow', '{}', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))`);
  await vault.end();
  const after = json(setup(['--reset-passwords', '--json'], { env: url }));
  assert.deepEqual(Object.keys(after.app), ['DATABASE_URL']);
  assert.deepEqual(Object.keys(after.vault), ['DATABASE_URL']);
  assert.ok(await connects(after.vault.DATABASE_URL!));
});

test('a boundary that is not what coffre needs fails, and shows nothing', needsCluster, async () => {
  const url = await database('setup_loose', 'superuser');
  json(setup(['--json'], { env: url }));
  await asSuperuser('setup_loose', (client) => client.query('GRANT INSERT ON vault_members TO coffre_app'));
  for (const args of [['--reset-passwords', '--json'], ['--json']]) {
    const run = setup(args, { env: url });
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
  const refused = setup(['--json'], { env: wrong.href });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /✗ Connect to 127\.0\.0\.1\/setup_wrong\n\s+password authentication failed/);
  assertNoAdministrator(refused, wrong.href);

  await asSuperuser('postgres', (client) => client.query("CREATE ROLE setup_owner LOGIN PASSWORD 'owner-only-p4ss'"));
  const plain = new URL(url);
  plain.username = 'setup_owner';
  plain.password = 'owner-only-p4ss';
  const weak = setup(['--json'], { env: plain.href });
  assert.equal(weak.status, 1);
  assert.match(weak.stderr, /✗ Check setup_owner can create roles\n\s+setup_owner cannot create roles/);
  assertNoAdministrator(weak, plain.href);
});

test('on a terminal: the steps on the main screen, the values on the alternate screen alone, and working', { skip: needsCluster.skip || ptySkip }, async () => {
  const url = await database('setup_terminal', 'owner');
  const { output, code } = await inTerminal(['setup'], { PATH: process.env.PATH, HOME: tmpdir(), COFFRE_SETUP_DATABASE_URL: url }, async (terminal) => {
    await terminal.waitFor('reveal all');
    terminal.send('R');
    await terminal.waitFor('Vault database URL');
    terminal.send('q');
    await terminal.waitFor('Have you saved all five values?');
    terminal.send('y');
    await terminal.waitFor('were shown once');
  });
  assert.equal(code, 0);
  const { main, alternate } = screens(output);
  assert.match(visible(main), /✓ Each login holds only its rights/);
  const urls = [...new Set(visible(alternate).match(/postgresql:\/\/coffre_(?:vault_)?runtime:[A-Za-z0-9_-]{32}@[^\s']+/g))];
  const keys = [...new Set(visible(alternate).match(/[A-Za-z0-9+/]{43}=/g))];
  assert.equal(urls.length, 2);
  assert.equal(keys.length, 2);
  for (const secret of [...urls.map((each) => new URL(each).password), ...keys]) assert.ok(!main.includes(secret), 'a secret on the main screen');
  for (const each of urls) assert.ok(await connects(each), 'a URL shown that does not connect');
  assert.ok(!output.includes(new URL(url).password), "the administrator's password");
});
