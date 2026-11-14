import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { postgresClient } from '@coffre/db/connect';
import { AfterMigrations, managedObjects, migrateDatabase, migrationsFolder, NotOwner } from '@coffre/db/migrate';

import { migrationFailure, pinProblem } from '../src/migrate.ts';
import { cliVersion } from '../src/version.ts';
import { asSuperuser, database, emptyCluster, needsCluster } from './cluster.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const journal = JSON.parse(readFileSync(join(migrationsFolder(), 'meta', '_journal.json'), 'utf8')) as {
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

test('a failure after the migrations committed never says nothing was changed', () => {
  const refusal = Object.assign(new Error('permission denied to grant role "coffre_backup"'), { code: '42501' });
  assert.equal(
    migrationFailure(new AfterMigrations(refusal)),
    `the database is at the migrated schema, but reasserting its privileges failed: permission denied to grant role "coffre_backup"`,
  );
});

const scratch: string[] = [];
after(() => {
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

/** A temp directory removed when the file's tests end, passed or failed. */
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratch.push(dir);
  return dir;
}

/** A deployment's folder, as `coffre init --node` writes one, its coffre packages pinned as given. */
function deploymentFolder(pins: Record<string, string>): string {
  const dir = tempDir('coffre-deployment-');
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
  const home = tempDir('coffre-migrate-');
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
    child.on('close', (code) => resolve({ code, output })),
  );
}

test("a login that cannot change coffre's tables is told whose they are, and the GRANT that would let it, its roles quoted as SQL takes them", () => {
  const sixteen = { grantsInherit: true, inherits: true };
  const one = new NotOwner('pscale_api_qj93', [{ name: 'pscale_api_2rmo', member: false }], sixteen);
  assert.equal(
    migrationFailure(one),
    "coffre's tables are owned by pscale_api_2rmo, and this login, pscale_api_qj93, is neither it nor a member of it: " +
      'migrate with pscale_api_2rmo\'s connection string, or, as a role that administers it, run GRANT "pscale_api_2rmo" TO "pscale_api_qj93" WITH INHERIT TRUE. Nothing was changed',
  );
  assert.match(
    new NotOwner('ci-deploy', [{ name: 'user', member: false }, { name: 'Old"Owner', member: false }], sixteen).message,
    /owned by user and Old"Owner, and this login, ci-deploy, is neither one nor a member of one: migrate with their connection string, or, as a role that administers them, run GRANT "user" TO "ci-deploy" WITH INHERIT TRUE; GRANT "Old""Owner" TO "ci-deploy" WITH INHERIT TRUE$/,
  );
  // A member that does not inherit: on Postgres 16, a grant that does; before it, a login that does.
  assert.match(
    new NotOwner('deployer', [{ name: 'owner', member: true }], sixteen).message,
    /owned by owner, and this login, deployer, is a member of it but does not inherit its privileges: migrate with owner's connection string, or, as a role that administers it, run GRANT "owner" TO "deployer" WITH INHERIT TRUE$/,
  );
  assert.match(new NotOwner('deployer', [{ name: 'owner', member: true }], { grantsInherit: false, inherits: false }).message, /does not inherit its privileges: .* run ALTER ROLE "deployer" INHERIT$/);
  assert.match(new NotOwner('deployer', [{ name: 'owner', member: false }], { grantsInherit: false, inherits: true }).message, /run GRANT "owner" TO "deployer"$/);
});

test("coffre's objects are what its migrations make, by name, as Postgres folds it", () => {
  assert.deepEqual(
    managedObjects([
      'CREATE TABLE "audit_log" (\n "id" bigint);\nCREATE TABLE IF NOT EXISTS public."Mixed" ();\n--> statement-breakpoint\nCREATE UNLOGGED TABLE Folded ();',
      'CREATE MATERIALIZED VIEW "totals" AS SELECT 1;\nCREATE SEQUENCE "public"."numbers";\nCREATE FUNCTION audit_log_append_only() RETURNS trigger\nCREATE OR REPLACE FUNCTION "Quoted" ()\nALTER TABLE "audit_log" ADD COLUMN "scope" text;',
    ]),
    { relations: ['audit_log', 'Mixed', 'folded', 'totals', 'numbers'], functions: ['audit_log_append_only', 'Quoted'] },
  );
  const made = managedObjects(readdirSync(migrationsFolder()).filter((file) => file.endsWith('.sql')).map((file) => readFileSync(join(migrationsFolder(), file), 'utf8')));
  assert.ok(made.relations.includes('vault_members') && made.relations.includes('mcp_approvals') && made.functions.includes('secret_versions_erase_only'), JSON.stringify(made));
});

test("in a deployment's folder, a CLI that is not the version it pins refuses, before asking for anything", async () => {
  assert.equal(pinProblem('0.1.17', '0.1.17'), null);
  const dirs = [deploymentFolder(pinnedAt('0.0.1')), deploymentFolder({ ...pinnedAt(cliVersion()), '@coffre/vault': '0.0.1' })];
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
});

test("outside a deployment's folder, migrate says where it runs, before asking for anything", async () => {
  const dir = tempDir('coffre-elsewhere-');
  const run = await migrateIn(dir, null);
  assert.equal(run.code, 1);
  assert.match(run.output, /coffre migrate runs in a deployment's folder, as its pipeline does before each deploy/);
  assert.doesNotMatch(run.output, /connection string/, 'it never asks for the database');
});

// --- on a disposable cluster ---------------------------------------------------------

/** A new database, its runtime logins made, as setup makes them before it migrates. */
async function fresh(name: string): Promise<string> {
  await emptyCluster();
  const url = await database(name, 'superuser');
  const client = postgresClient(url, { max: 1 });
  try {
    await client.unsafe('CREATE ROLE coffre_runtime LOGIN');
    await client.unsafe('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await client.end();
  }
  return url;
}

async function applied(url: string): Promise<number> {
  const client = postgresClient(url, { max: 1 });
  try {
    const [{ present }] = await client.unsafe<[{ present: boolean }]>("SELECT to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS present");
    return present ? Number((await client.unsafe<[{ n: string }]>('SELECT count(*) AS n FROM drizzle.__drizzle_migrations'))[0].n) : 0;
  } finally {
    await client.end();
  }
}

/** What a coffre's own migrator records, written straight into the ledger. */
async function record(url: string, hash: string, createdAt: number): Promise<void> {
  const client = postgresClient(url, { max: 1 });
  try {
    await client.unsafe('CREATE SCHEMA IF NOT EXISTS drizzle');
    await client.unsafe('CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)');
    await client.unsafe('INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2)', [hash, createdAt]);
  } finally {
    await client.end();
  }
}

const SPINNER = /[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]/;

test("in a deployment's folder, its pipeline migrates a new database before the deploy, then finds nothing to do", needsCluster, async () => {
  const url = await fresh('setup_migrate_pipeline');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  // Without a terminal, only with --yes.
  const asked = await migrateIn(dir, url, []);
  assert.equal(asked.code, 1);
  assert.match(asked.output, /Not a terminal, so nothing to confirm on: pass --yes to migrate without asking\./);
  assert.equal(await applied(url), 0);

  const run = await migrateIn(dir, url);
  assert.equal(run.code, 0, run.output);
  assert.match(run.output, new RegExp(`${KNOWN.length === 1 ? '1 migration' : `${KNOWN.length} migrations`} to apply to \\S+, for coffre ${cliVersion().replace(/\./g, '\\.')}: ${KNOWN[0]}`));
  assert.match(run.output, /✓ Applied .*, and reasserted the database's privileges\n/);
  // As a CI log keeps it: plain lines, no escape codes, no spinner, no password.
  assert.doesNotMatch(run.output, /\x1b\[/);
  assert.doesNotMatch(run.output, SPINNER);
  assert.ok(!run.output.includes(new URL(url).password), 'the password is never shown');
  assert.equal(await applied(url), KNOWN.length);

  // The backup login, made after the migrations: a run with nothing to apply grants it its group when named.
  await asSuperuser('postgres', (client) => client.unsafe("CREATE ROLE coffre_backup_login LOGIN PASSWORD 'backup'"));
  const membership = () => asSuperuser('postgres', async (client) =>
    [...await client.unsafe("SELECT admin_option, inherit_option, set_option FROM pg_auth_members WHERE roleid = 'coffre_backup'::regrole AND member = 'coffre_backup_login'::regrole")]);
  const again = await migrateIn(dir, url);
  assert.equal(again.code, 0, again.output);
  assert.match(again.output, new RegExp(`✓ \\S+ is up to date, at coffre \\S+'s schema: ${KNOWN.length === 1 ? '1 migration' : `${KNOWN.length} migrations`}, the last ${KNOWN.at(-1)}; reasserted the database's privileges\n`));
  assert.deepEqual(await membership(), []);
  const granted = await migrateIn(dir, url, ['--yes', '--backup-login', 'coffre_backup_login']);
  assert.equal(granted.code, 0, granted.output);
  assert.match(granted.output, /; reasserted the database's privileges and coffre_backup_login's membership in coffre_backup\n/);
  assert.deepEqual(await membership(), [{ admin_option: false, inherit_option: true, set_option: false }]);
  const absent = await migrateIn(dir, url, ['--yes', '--backup-login', 'nobody_here']);
  assert.equal(absent.code, 1, absent.output);
  assert.match(absent.output, /reasserting its privileges failed: role "nobody_here" does not exist/);
});

test("a database a newer coffre migrated is refused in a deployment's folder, its unknown migration named, and nothing changes", needsCluster, async () => {
  const url = await fresh('setup_migrate_ahead');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
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
});

test('a database a coffre before 0.4.0 made is refused, with what to do instead, and nothing changes', needsCluster, async () => {
  const url = await fresh('setup_migrate_before');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  // 0.3's ledger began with a baseline of its own, which this version does not have.
  await record(url, 'cd'.repeat(32), Date.UTC(2026, 8, 30));
  const run = await migrateIn(dir, url);
  assert.equal(run.code, 1);
  assert.match(run.output, /the database was made by a coffre before 0\.4\.0, which is a clean break: deploy afresh, on a new database \(docs\/deploy\.md\)/);
  assert.equal(await applied(url), 1);
});

test("a login that neither owns coffre's tables nor is a member of their owner is refused, the owner named, before anything changes", needsCluster, async () => {
  await emptyCluster();
  // Migrated by one login, as a managed host's first: CREATEROLE, not superuser.
  const owned = await database('setup_migrate_owners', 'owner');
  const owner = postgresClient(owned, { max: 1 });
  try {
    await owner.unsafe('CREATE ROLE coffre_runtime LOGIN');
    await owner.unsafe('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await owner.end();
  }
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  assert.equal((await migrateIn(dir, owned)).code, 0);
  // Then deployed with another, as PlanetScale gives a second: CREATEROLE too, a member of no role.
  await asSuperuser('postgres', (client) => client.unsafe("CREATE ROLE setup_deployer LOGIN CREATEROLE PASSWORD 'deployer-only-p4ss'"));
  const deployer = new URL(owned);
  deployer.username = 'setup_deployer';
  deployer.password = 'deployer-only-p4ss';
  const refusal = /coffre's tables are owned by setup_owner, and this login, setup_deployer, is neither it nor a member of it: migrate with setup_owner's connection string, or, as a role that administers it, run GRANT "setup_owner" TO "setup_deployer" WITH INHERIT TRUE/;

  // One that may not even read the ledger is refused, up to date as the database is.
  const unread = await migrateIn(dir, deployer.href);
  assert.equal(unread.code, 1);
  assert.match(unread.output, new RegExp(`${refusal.source}\\. Nothing was changed`));
  assert.doesNotMatch(unread.output, /permission denied/);

  // PlanetScale's reads and writes every table, and owns none.
  await asSuperuser('postgres', (client) => client.unsafe('GRANT pg_read_all_data, pg_write_all_data TO setup_deployer'));
  // Up to date, it applies nothing, and says the next migration needs another login.
  const current = await migrateIn(dir, deployer.href);
  assert.equal(current.code, 0, current.output);
  assert.match(current.output, /is up to date/);
  assert.match(current.output, new RegExp(`The next migration needs another login: ${refusal.source}`));
  // Asked to grant the backup group, which it may not reassert either, it is refused rather than do nothing.
  const backup = await migrateIn(dir, deployer.href, ['--yes', '--backup-login', 'setup_deployer']);
  assert.equal(backup.code, 1, backup.output);
  assert.match(backup.output, new RegExp(`${refusal.source}\\. Nothing was changed`));

  // With a migration to apply, refused before it asks, not "permission denied for schema drizzle".
  const last = await asSuperuser('setup_migrate_owners', async (client) =>
    (await client.unsafe<[{ hash: string; created_at: string }]>('DELETE FROM drizzle.__drizzle_migrations WHERE id = (SELECT max(id) FROM drizzle.__drizzle_migrations) RETURNING hash, created_at'))[0],
  );
  const pending = await migrateIn(dir, deployer.href);
  assert.equal(pending.code, 1);
  assert.match(pending.output, new RegExp(`${refusal.source}\\. Nothing was changed`));
  assert.doesNotMatch(pending.output, /permission denied|to apply to/);
  assert.equal(await applied(owned), KNOWN.length - 1);
  await record(owned, last.hash, Number(last.created_at));

  // The migrator itself refuses, under its lock, whatever calls it.
  await assert.rejects(migrateDatabase(deployer.href), (error) => error instanceof NotOwner && error.owners.map(({ name }) => name).join() === 'setup_owner' && error.login === 'setup_deployer');

  // A member of the owner migrates, and is told nothing more.
  await asSuperuser('postgres', (client) => client.unsafe('GRANT setup_owner TO setup_deployer'));
  await migrateDatabase(deployer.href);
  const member = await migrateIn(dir, deployer.href);
  assert.equal(member.code, 0, member.output);
  assert.doesNotMatch(member.output, /another login/);

  // A table of the database's own in public, which another role owns, is not coffre's to change.
  await asSuperuser('setup_migrate_owners', async (client) => {
    await client.unsafe('CREATE ROLE setup_reporting');
    await client.unsafe('CREATE TABLE public.unrelated_reporting_data (id int)');
    await client.unsafe('ALTER TABLE public.unrelated_reporting_data OWNER TO setup_reporting');
  });
  await migrateDatabase(owned);
  const unrelated = await migrateIn(dir, owned);
  assert.equal(unrelated.code, 0, unrelated.output);
  assert.doesNotMatch(unrelated.output, /another login|setup_reporting/);
});

test('a member of the owner that does not inherit its privileges is told so, and the GRANT it says lets it migrate', needsCluster, async () => {
  await emptyCluster();
  const owned = await database('setup_migrate_inherit', 'owner');
  const owner = postgresClient(owned, { max: 1 });
  try {
    await owner.unsafe('CREATE ROLE coffre_runtime LOGIN');
    await owner.unsafe('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await owner.end();
  }
  await migrateDatabase(owned);
  // NOINHERIT: on Postgres 16 its memberships do not inherit unless granted so; a plain GRANT gives one that does not.
  await asSuperuser('postgres', async (client) => {
    await client.unsafe("CREATE ROLE setup_deployer LOGIN NOINHERIT PASSWORD 'deployer-only-p4ss'");
    await client.unsafe('GRANT setup_owner TO setup_deployer');
  });
  const deployer = new URL(owned);
  deployer.username = 'setup_deployer';
  deployer.password = 'deployer-only-p4ss';
  const refused = await migrateDatabase(deployer.href).then(
    () => assert.fail('migrated without the owner\'s privileges'),
    (error: unknown) => error as NotOwner,
  );
  assert.ok(refused instanceof NotOwner, String(refused));
  assert.match(refused.message, /this login, setup_deployer, is a member of it but does not inherit its privileges: .* run GRANT "setup_owner" TO "setup_deployer" WITH INHERIT TRUE$/);
  // What it says to run, run as it says.
  await asSuperuser('postgres', (client) => client.unsafe(refused.message.slice(refused.message.lastIndexOf('run ') + 4)));
  await migrateDatabase(deployer.href);
});
