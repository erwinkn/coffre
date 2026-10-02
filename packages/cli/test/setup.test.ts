import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseDotenv } from '@coffre/core/dotenv';
import pg from 'pg';

import { formatSetup, hyperdriveUrl, loginFor, loginUrl, scramVerifier, type SetupResult } from '../src/setup.ts';

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
  return JSON.parse(run.stdout) as {
    app: { AUDIT_CHAIN_KEY?: string; DATABASE_URL?: string };
    vault: { KEK_ID?: string; KEK?: string; DATABASE_URL?: string };
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
  // Hyperdrive makes its own TLS connection, and takes no sslrootcert.
  assert.equal(hyperdriveUrl(url), 'postgresql://coffre_runtime.x7k2m9q4w1:fresh-password@eu.pg.psdb.cloud:5432/coffre');
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
    const run = setup([], { stdin: `${given}\n` });
    assert.equal(run.status, 1);
    assert.ok(!run.stderr.includes('hunter2-secret'), run.stderr);
  }
});

test('what it shows: a dotenv block for each component, then where each value goes', () => {
  const result: SetupResult = {
    keys: { KEK_ID: 'kek-2026-10-02', KEK: 'K'.repeat(43) + '=', AUDIT_CHAIN_KEY: 'A'.repeat(43) + '=' },
    app: { role: 'coffre_runtime', login: 'coffre_runtime', password: 'created', url: 'postgresql://coffre_runtime:p1@db.example.com:5432/coffre?sslmode=verify-full' },
    vault: { role: 'coffre_vault_runtime', login: 'coffre_vault_runtime', password: 'created', url: 'postgresql://coffre_vault_runtime:p2@db.example.com:5432/coffre?sslmode=verify-full' },
  };
  const text = formatSetup(result);
  assert.match(text, /^# SAVE THESE NOW/);
  const [app, vault] = text.split('\n\n').slice(1, 3).map((block) => {
    const { entries, problems } = parseDotenv(block);
    assert.deepEqual(problems, []);
    return Object.fromEntries(entries.map((entry) => [entry.key, entry.value]));
  });
  assert.deepEqual(app, { AUDIT_CHAIN_KEY: result.keys!.AUDIT_CHAIN_KEY, DATABASE_URL: result.app.url });
  assert.deepEqual(vault, { KEK_ID: 'kek-2026-10-02', KEK: result.keys!.KEK, DATABASE_URL: result.vault.url });
  assert.match(text, /hyperdrive create coffre --caching-disabled \\\n#\s+--connection-string='postgresql:\/\/coffre_runtime:p1@db\.example\.com:5432\/coffre'/);
  assert.match(text, /hyperdrive create coffre-vault --caching-disabled/);
  assert.match(text, /wrangler secret put KEK -c vault\/wrangler\.jsonc/);

  // After a restore: new passwords for a deployment that has its keys, and Hyperdrive configs to update.
  const reset = formatSetup({
    keys: null,
    app: { ...result.app, password: 'reset' },
    vault: { ...result.vault, password: 'reset' },
  });
  assert.match(reset, /No keys: this database holds a deployment's data already/);
  assert.match(reset, /hyperdrive update <the app's config id> \\/);
  assert.doesNotMatch(reset, /KEK=|AUDIT_CHAIN_KEY=|secret put/);

  const nothing = formatSetup({ keys: null, app: { ...result.app, password: 'kept', url: null }, vault: { ...result.vault, password: 'kept', url: null } });
  assert.match(nothing, /^# Nothing to save/);
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
    assert.match(first.stderr, /created coffre_runtime\n/);
    assert.match(first.stderr, /coffre_runtime\s+cannot write members, delete log entries or create tables\n\s+coffre_vault_runtime\s+can write members; cannot delete log entries or create tables\n/);
    assert.deepEqual(shown.logins, {
      coffre_runtime: { login: 'coffre_runtime', password: 'created' },
      coffre_vault_runtime: { login: 'coffre_vault_runtime', password: 'created' },
    });
    assert.match(shown.vault.KEK_ID!, /^kek-\d{4}-\d{2}-\d{2}$/);
    for (const key of [shown.vault.KEK!, shown.app.AUDIT_CHAIN_KEY!]) assert.equal(Buffer.from(key, 'base64').length, 32);
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
    assert.match(again.stderr, /coffre_runtime and coffre_vault_runtime exist already/);
    assert.match(again.stderr, /by the catalog: its password is unchanged/);
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
    assert.match(setup([], { stdin: url }).stdout, /^# Nothing to save/);

    // With --reset-passwords: new ones, and the old stop working. The database is still unused, so new keys come with them.
    const reset = json(setup(['--reset-passwords', '--json'], { env: url }));
    assert.equal(reset.logins.coffre_runtime!.password, 'reset');
    assert.ok(await connects(reset.app.DATABASE_URL!));
    assert.ok(await connects(reset.vault.DATABASE_URL!));
    assert.equal(await connects(shown.app.DATABASE_URL!), false);
    assert.ok(reset.vault.KEK !== undefined && reset.vault.KEK !== shown.vault.KEK);
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
  for (const args of [['--reset-passwords'], []]) {
    const run = setup(args, { env: url });
    assert.equal(run.status, 1);
    assert.match(run.stderr, /coffre_runtime can write members: the database's privileges are not what coffre needs/);
    assert.equal(run.stdout, '');
    assertNoAdministrator(run, url);
  }
});

test('a wrong password, or a login that cannot create roles, is refused without quoting the connection string', needsCluster, async () => {
  const url = await database('setup_wrong', 'superuser');
  const wrong = new URL(url);
  wrong.password = 'not-the-password';
  const refused = setup([], { env: wrong.href });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /password authentication failed/);
  assertNoAdministrator(refused, wrong.href);

  await asSuperuser('postgres', (client) => client.query("CREATE ROLE setup_owner LOGIN PASSWORD 'owner-only-p4ss'"));
  const plain = new URL(url);
  plain.username = 'setup_owner';
  plain.password = 'owner-only-p4ss';
  const weak = setup([], { env: plain.href });
  assert.equal(weak.status, 1);
  assert.match(weak.stderr, /setup_owner cannot create roles/);
  assertNoAdministrator(weak, plain.href);
});
