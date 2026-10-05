import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';

import { migrationsFolder } from '@coffre/db/migrate';

import { migrationFailure, pinProblem } from '../src/migrate.ts';
import { cliVersion } from '../src/version.ts';
import { database, emptyCluster, needsCluster } from './cluster.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const journal = JSON.parse(readFileSync(join(migrationsFolder('postgres'), 'meta', '_journal.json'), 'utf8')) as {
  entries: { tag: string; when: number }[];
};
const KNOWN = journal.entries.map((entry) => entry.tag);

// --- without a database ------------------------------------------------------------

test("a migration's refusal is its own sentence, not the SQL around it", () => {
  const refusal = Object.assign(new Error('secrets_folder_check: a row holds a folder this version refuses'), { code: 'P0001' });
  const wrapped = new Error('Failed query: DO $$ BEGIN … END $$\nparams: ', { cause: refusal });
  assert.equal(
    migrationFailure(wrapped),
    'secrets_folder_check: a row holds a folder this version refuses. Nothing was changed: the migrations run in one transaction.',
  );
});

/** A deployment's folder, as `coffre init --node` writes one, its coffre packages pinned as given. */
function deploymentFolder(pins: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-deployment-'));
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src', 'vault.ts'), '');
  writeFileSync(join(dir, 'vault.env.example'), '');
  const [dependencies, devDependencies] = [{} as Record<string, string>, {} as Record<string, string>];
  for (const [name, version] of Object.entries(pins)) (name === '@coffre/cli' ? devDependencies : dependencies)[name] = version;
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ private: true, dependencies, devDependencies }));
  return dir;
}

const pinnedAt = (version: string) => ({ '@coffre/server': version, '@coffre/vault': version, '@coffre/cli': version });

/** `coffre migrate`, as a deployment's pipeline runs it in its folder: no terminal, no session, the URL on stdin. */
function migrateIn(dir: string, url: string | null, args: string[] = ['--yes'], session: string[] = []): Promise<{ code: number | null; output: string }> {
  const home = mkdtempSync(join(tmpdir(), 'coffre-migrate-'));
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, ...session, 'migrate', ...args], {
    cwd: dir,
    env: { PATH: process.env.PATH, HOME: home },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  // A run that stops before reading stdin closes it: not this test's failure.
  child.stdin.on('error', () => {});
  child.stdin.end(url ?? '');
  let output = '';
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (output += chunk));
  return new Promise((resolve) =>
    child.on('close', (code) => {
      rmSync(home, { recursive: true, force: true });
      resolve({ code, output });
    }),
  );
}

test("in a deployment's folder, a CLI that is not the version it pins refuses, before asking for anything", async () => {
  assert.equal(pinProblem('0.1.17', '0.1.17'), null);
  const dirs = [deploymentFolder(pinnedAt('0.0.1')), deploymentFolder({ ...pinnedAt(cliVersion()), '@coffre/vault': '0.0.1' })];
  try {
    const other = await migrateIn(dirs[0]!, null);
    assert.equal(other.code, 1);
    assert.match(other.output, new RegExp(`this deployment pins coffre 0\\.0\\.1, and this CLI is ${cliVersion().replace(/\./g, '\\.')}, whose migrations are another version's: migrate with the deployment's own, \`pnpm exec coffre migrate\``));
    assert.doesNotMatch(other.output, /connection string/, 'it never asks for the database');
    const mixed = await migrateIn(dirs[1]!, null);
    assert.equal(mixed.code, 1);
    assert.match(mixed.output, /pinned at .* and 0\.0\.1, not one: `coffre update` moves them together/);
    // It migrates a database, never an instance.
    const named = await migrateIn(deploymentFolder(pinnedAt(cliVersion())), null, ['--yes'], ['--url', 'https://coffre.example']);
    assert.equal(named.code, 1);
    assert.match(named.output, /--url does nothing for coffre migrate/);
  } finally {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  }
});

test("outside a deployment's folder, migrate says where it runs, before asking for anything", async () => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-elsewhere-'));
  try {
    const run = await migrateIn(dir, null);
    assert.equal(run.code, 1);
    assert.match(run.output, /coffre migrate runs in a deployment's folder, as its pipeline does before each deploy/);
    assert.doesNotMatch(run.output, /connection string/, 'it never asks for the database');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- on a disposable cluster ---------------------------------------------------------

/** A new database, its runtime logins made, as setup makes them before it migrates. */
async function fresh(name: string): Promise<string> {
  await emptyCluster();
  const url = await database(name, 'superuser');
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query('CREATE ROLE coffre_runtime LOGIN');
    await client.query('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await client.end();
  }
  return url;
}

async function applied(url: string): Promise<number> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    const ledger = (await client.query("SELECT to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS present")).rows[0].present as boolean;
    return ledger ? Number((await client.query('SELECT count(*) AS n FROM drizzle.__drizzle_migrations')).rows[0].n) : 0;
  } finally {
    await client.end();
  }
}

/** What a coffre's own migrator records, written straight into the ledger. */
async function record(url: string, hash: string, createdAt: number): Promise<void> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query('CREATE SCHEMA IF NOT EXISTS drizzle');
    await client.query('CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)');
    await client.query('INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2)', [hash, createdAt]);
  } finally {
    await client.end();
  }
}

const SPINNER = /[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]/;

test("in a deployment's folder, its pipeline migrates a new database before the deploy, then finds nothing to do", needsCluster, async () => {
  const url = await fresh('setup_migrate_pipeline');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  try {
    // Without a terminal, only with --yes.
    const asked = await migrateIn(dir, url, []);
    assert.equal(asked.code, 1);
    assert.match(asked.output, /Not a terminal, so nothing to confirm on: pass --yes to migrate without asking\./);
    assert.equal(await applied(url), 0);

    const run = await migrateIn(dir, url);
    assert.equal(run.code, 0, run.output);
    assert.match(run.output, new RegExp(`${KNOWN.length === 1 ? '1 migration' : `${KNOWN.length} migrations`} to apply to \\S+, for coffre ${cliVersion().replace(/\./g, '\\.')}: ${KNOWN[0]}`));
    assert.match(run.output, /✓ Applied .*, and reasserted the database's privileges/);
    // As a CI log keeps it: plain lines, no escape codes, no spinner, no password.
    assert.doesNotMatch(run.output, /\x1b\[/);
    assert.doesNotMatch(run.output, SPINNER);
    assert.ok(!run.output.includes(new URL(url).password), 'the password is never shown');
    assert.equal(await applied(url), KNOWN.length);

    const again = await migrateIn(dir, url);
    assert.equal(again.code, 0, again.output);
    assert.match(again.output, new RegExp(`✓ \\S+ is up to date, at coffre \\S+'s schema: ${KNOWN.length === 1 ? '1 migration' : `${KNOWN.length} migrations`}, the last ${KNOWN.at(-1)}`));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a database a newer coffre migrated is refused in a deployment's folder, its unknown migration named, and nothing changes", needsCluster, async () => {
  const url = await fresh('setup_migrate_ahead');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  try {
    assert.equal((await migrateIn(dir, url)).code, 0);
    // What a later coffre would have recorded: a migration this one has never seen.
    await record(url, 'ab'.repeat(32), Date.UTC(2030, 0, 2, 3, 4));

    const run = await migrateIn(dir, url);
    assert.equal(run.code, 1);
    assert.match(
      run.output,
      new RegExp(`is ahead of coffre \\S+: has applied a migration this version does not know, after ${KNOWN.at(-1)}: one made 2030-01-02 03:04 UTC \\(abababababab\\)\\. A newer coffre migrated it\\. Deploy that version, or, to go back, restore the database from before it \\(docs/restore\\.md\\)\\. Nothing was changed`),
    );
    assert.equal(await applied(url), KNOWN.length + 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a database a coffre before 0.4.0 made is refused, with what to do instead, and nothing changes', needsCluster, async () => {
  const url = await fresh('setup_migrate_before');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  try {
    // 0.3's ledger began with a baseline of its own, which this version does not have.
    await record(url, 'cd'.repeat(32), Date.UTC(2026, 8, 30));
    const run = await migrateIn(dir, url);
    assert.equal(run.code, 1);
    assert.match(run.output, /the database was made by a coffre before 0\.4\.0, which is a clean break: deploy afresh, on a new database \(docs\/deploy\.md\)/);
    assert.equal(await applied(url), 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
