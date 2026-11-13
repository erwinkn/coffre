import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { postgresClient } from '@coffre/db/connect';

import { AfterMigrations, HandOverFailed, LockWaitsExhausted, managedObjects, migrateDatabase, MIGRATION_LOCK_ATTEMPTS, MIGRATION_LOCK_WAIT_MS, migrationsFolder, NotOwner } from '@coffre/db/migrate';

import { describeEveryProject, migrationFailure, pinProblem } from '../src/migrate.ts';
import { cliVersion } from '../src/version.ts';
import { asSuperuser, CLUSTER, database, emptyCluster, needsCluster } from './cluster.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const journal = JSON.parse(readFileSync(join(migrationsFolder(), 'meta', '_journal.json'), 'utf8')) as {
  entries: { tag: string; when: number }[];
};
const KNOWN = journal.entries.map((entry) => entry.tag);

// --- without a database ------------------------------------------------------------

test('migrate says what the vault will make of each grant on every project of 0.4, and nothing when there is none', () => {
  assert.equal(describeEveryProject([]), '');
  const paths = { m: 'market', b: 'billing', 'm-dev': 'market/dev' };
  const said = describeEveryProject([
    {
      principal: 'user:ada@acme.example',
      before: [{ place: '*/dev', role: 'developer', expiresAt: null }],
      conversion: { role: 'developer', scope: { projects: 'all', environments: { only: ['dev'] } }, grants: [], narrowed: [] },
      paths,
      reported: false,
    },
    {
      principal: 'user:bob@acme.example',
      before: [{ place: '*', role: 'maintainer', expiresAt: null }],
      conversion: {
        role: 'developer',
        scope: { projects: 'all', environments: 'all' },
        grants: [{ projectId: 'b', environmentId: null, role: 'maintainer', expiresAt: null, replaces: null }],
        narrowed: [
          { kind: 'later-projects', grant: { environmentSlug: null, role: 'maintainer', expiresAt: null } },
          { kind: 'lost', grant: { environmentSlug: null, role: 'maintainer', expiresAt: null }, projectId: 'm', environmentId: null, lost: 'maintainer', kept: 'owner', keptUntil: Date.UTC(2026, 10, 1) },
        ],
      },
      paths,
      reported: false,
    },
    {
      principal: 'user:cy@acme.example',
      before: [{ place: '*', role: 'viewer', expiresAt: null }],
      conversion: {
        role: 'member',
        scope: { projects: 'all', environments: 'all' },
        grants: [
          { projectId: 'b', environmentId: null, role: 'viewer', expiresAt: null, replaces: null },
          { projectId: 'm', environmentId: 'm-dev', role: 'viewer', expiresAt: null, replaces: null },
        ],
        narrowed: [
          { kind: 'later-projects', grant: { environmentSlug: null, role: 'viewer', expiresAt: null } },
          { kind: 'environments', grant: { environmentSlug: null, role: 'viewer', expiresAt: null }, projectId: 'm', role: 'viewer' },
        ],
      },
      paths,
      reported: false,
    },
    {
      principal: 'token:deploy',
      before: [{ place: '*', role: 'maintainer', expiresAt: null }],
      conversion: {
        role: 'member',
        scope: { projects: 'all', environments: 'all' },
        grants: [{ projectId: 'm', environmentId: null, role: 'maintainer', expiresAt: null, replaces: 'access-manager' }],
        narrowed: [
          { kind: 'later-projects', grant: { environmentSlug: null, role: 'maintainer', expiresAt: null } },
          { kind: 'lost', grant: { environmentSlug: null, role: 'maintainer', expiresAt: null }, projectId: 'm', environmentId: null, lost: 'access-manager', kept: 'maintainer', keptUntil: null },
        ],
      },
      paths,
      reported: false,
    },
    {
      principal: 'token:ci',
      before: [{ place: '*/dev', role: 'viewer', expiresAt: null }],
      conversion: {
        role: 'member',
        scope: { projects: 'all', environments: 'all' },
        grants: [{ projectId: 'm', environmentId: 'm-dev', role: 'viewer', expiresAt: null, replaces: null }],
        narrowed: [{ kind: 'later-projects', grant: { environmentSlug: 'dev', role: 'viewer', expiresAt: null } }],
      },
      paths,
      reported: false,
    },
    {
      principal: 'token:old',
      before: [{ place: '*', role: 'viewer', expiresAt: null }],
      conversion: {
        role: 'member',
        scope: { projects: 'all', environments: 'all' },
        grants: [{ projectId: 'b', environmentId: null, role: 'viewer', expiresAt: null, replaces: null }],
        narrowed: [{ kind: 'later-projects', grant: { environmentSlug: null, role: 'viewer', expiresAt: null } }],
      },
      paths,
      reported: true,
    },
  ]);
  assert.equal(said, [
    '',
    'Grants on every project are gone in this version. When it first runs, the vault replaces them:',
    '  user:ada@acme.example: developer on dev in every project → Developer, All projects · dev only',
    '  user:bob@acme.example: maintainer on every project → Developer, and maintainer on billing; not projects made later; loses maintainer on market (keeps owner until 2026-11-01)',
    '  user:cy@acme.example: viewer on every project → viewer on billing, market/dev; not projects made later; viewer on market only through its environments, not those made later',
    '  service:deploy: maintainer on every project → maintainer on market; not projects made later; loses access-manager on market (keeps maintainer)',
    '  service:ci: viewer on dev in every project → viewer on market/dev; not projects made later',
    '  service:old: viewer on every project → left as it is: the vault reported their row tampered with (if the vault finds that report forged, it makes: viewer on billing; not projects made later)',
    "Those of a member whose row the vault finds tampered with stay as they are: migrate holds no key to check a row, nor whether a report is the vault's own.",
    'Revoke or regrant any of them before you deploy to choose otherwise (docs/design/instance-roles.md).',
    '',
  ].join('\n'));
});

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

test("a migration that gave up waiting for a table says how many times and what held it, not Postgres's one wait", () => {
  const wait = Object.assign(new Error('canceling statement due to lock timeout'), { code: '55P03' });
  const failed = Object.assign(new Error('Failed query: ALTER TABLE "credentials" ADD COLUMN "passkey_id" uuid;\nparams: ', { cause: wait }), { query: 'ALTER TABLE "credentials" ADD COLUMN "passkey_id" uuid;' });
  const said = migrationFailure(new LockWaitsExhausted(MIGRATION_LOCK_ATTEMPTS, [
    { pid: 42, prepared: null, login: 'coffre_backup_login', application: 'pg_dump', tables: ['public.credentials'] },
    { pid: null, prepared: 'deploy-7', login: 'coffre_owner', application: null, tables: ['public.credentials', 'public.secrets'] },
    { pid: 43, prepared: null, login: null, application: null, tables: ['public.secrets'] },
  ], failed));
  assert.ok(said.startsWith(`the migrations waited for a lock ${MIGRATION_LOCK_ATTEMPTS} times, ${MIGRATION_LOCK_WAIT_MS} ms each, and gave up,`), said);
  assert.ok(said.includes('at ALTER TABLE "credentials" ADD COLUMN "passkey_id" uuid. '), said);
  assert.ok(said.includes("Sessions holding coffre's tables: pid 42 (coffre_backup_login, pg_dump) on public.credentials; prepared transaction 'deploy-7' (coffre_owner) on public.credentials, public.secrets; pid 43 on public.secrets. "), said);
  assert.ok(said.endsWith('Nothing was changed: the migrations run in one transaction.'), said);
  assert.ok(!said.includes('canceling statement'), said);

  // A migration's statement as Drizzle sends it, its comments first (0029_use_objects).
  const commented = Object.assign(new Error('Failed query: …', { cause: wait }), {
    query: "-- Its newest reference row's end, which a use reads.\n\n-- Kept in step by the vault.\nALTER TABLE \"secret_references\" ADD COLUMN \"ended_at\" bigint;",
  });
  const fromComment = migrationFailure(new LockWaitsExhausted(MIGRATION_LOCK_ATTEMPTS, [], commented));
  assert.ok(fromComment.includes('gave up, at ALTER TABLE "secret_references" ADD COLUMN "ended_at" bigint. '), fromComment);

  const unread = migrationFailure(new LockWaitsExhausted(MIGRATION_LOCK_ATTEMPTS, { unread: new Error('connection lost') }, failed));
  assert.ok(unread.includes("Which sessions held coffre's tables could not be read: connection lost. "), unread);
  assert.ok(!unread.includes('No session held'), unread);
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
  // One that inherits the ledger's owner's privileges but may not become it, which handing it an object asks (T193).
  assert.equal(
    new NotOwner('deployer', [{ name: 'owner', member: true }], { ...sixteen, settable: false }).message,
    "coffre's tables are owned by owner, and this login, deployer, inherits its privileges but may not become it (SET ROLE), which handing it what the migrations make asks: " +
      'migrate with owner\'s connection string, or, as a role that administers it, run GRANT "owner" TO "deployer" WITH SET TRUE',
  );
  // The ledger's owner, whose member made objects of coffre's before T193: granting the member to it would be a cycle.
  assert.equal(
    new NotOwner('owner', [{ name: 'deployer', member: false, memberOfLogin: true }], sixteen).message,
    "coffre's tables are owned by deployer, and this login, owner, is neither it nor a member of it: " +
      "migrate once with deployer's connection string, or a superuser's, which hands its objects to the owner of coffre's ledger",
  );
  // A member that owns the ledger, as its first run of a fresh database makes it: migrating as it would hand it all again.
  assert.equal(
    new NotOwner('owner', [{ name: 'deployer', member: false, memberOfLogin: true, ownsLedger: true }], sixteen).message,
    "coffre's tables are owned by deployer, and this login, owner, is neither it nor a member of it: " +
      "coffre's ledger, the drizzle schema, is deployer's, a member of this login, which makes deployer the owner of coffre's objects: migrate with deployer's connection string",
  );
  // That member, and another owner it cannot act for: migrating as the member alone would be refused again, so a superuser's run hands it the rest first.
  assert.equal(
    new NotOwner('owner', [{ name: 'admin', member: false }, { name: 'deployer', member: false, memberOfLogin: true, ownsLedger: true }], sixteen).message,
    "coffre's tables are owned by admin and deployer, and this login, owner, is neither one nor a member of one: " +
      "coffre's ledger, the drizzle schema, is deployer's, a member of this login, which makes deployer the owner of coffre's objects: " +
      "migrate once with a superuser's connection string, which hands admin's objects to deployer, then with deployer's",
  );
  // Owners that can be granted and one that cannot: the GRANT, and the run that hands the other's over.
  assert.equal(
    new NotOwner('owner', [{ name: 'admin', member: false }, { name: 'deployer', member: false, memberOfLogin: true }], sixteen).message,
    "coffre's tables are owned by admin and deployer, and this login, owner, is neither one nor a member of one: " +
      'migrate with admin\'s connection string, or, as a role that administers it, run GRANT "admin" TO "owner" WITH INHERIT TRUE; ' +
      "and, for deployer, a member of this login, migrate once with deployer's connection string, or a superuser's, which hands its objects to the owner of coffre's ledger",
  );
});

test('a hand-over Postgres refuses says it was the hand-over, and what it was moving', () => {
  const refused = Object.assign(new Error('permission denied for schema public'), { code: '42501' });
  assert.equal(
    migrationFailure(new HandOverFailed('ALTER TABLE log_uses_20370103 OWNER TO "owner"', refused)),
    'handing coffre\'s objects to the owner of its ledger failed, at ALTER TABLE log_uses_20370103 OWNER TO "owner": permission denied for schema public. ' +
      'Nothing was changed: the migrations run in one transaction.',
  );
});

test("coffre's objects are what its migrations make, by name, as Postgres folds it", () => {
  assert.deepEqual(
    managedObjects([
      'CREATE TABLE "audit_log" (\n "id" bigint);\nCREATE TABLE IF NOT EXISTS public."Mixed" ();\n--> statement-breakpoint\nCREATE UNLOGGED TABLE Folded ();',
      'CREATE MATERIALIZED VIEW "totals" AS SELECT 1;\nCREATE SEQUENCE "public"."numbers";\nCREATE FUNCTION audit_log_append_only() RETURNS trigger\nCREATE OR REPLACE FUNCTION "Quoted" ()\nALTER TABLE "audit_log" ADD COLUMN "scope" text;',
      'ALTER TABLE "totals" RENAME TO "Sums";\nALTER TABLE public.folded RENAME TO Kept;\nALTER TABLE "audit_log" RENAME CONSTRAINT "a" TO "b";',
      'CREATE TYPE use_row AS (state text);\nCREATE TYPE "public"."Kind" AS ENUM (\'a\');\nALTER TYPE use_row ADD ATTRIBUTE at bigint;',
    ]),
    { relations: ['audit_log', 'Mixed', 'folded', 'totals', 'numbers', 'Sums', 'kept'], functions: ['audit_log_append_only', 'Quoted'], types: ['use_row', 'Kind'] },
  );
  const made = managedObjects(readdirSync(migrationsFolder()).filter((file) => file.endsWith('.sql')).map((file) => readFileSync(join(migrationsFolder(), file), 'utf8')));
  assert.ok(made.relations.includes('vault_members') && made.relations.includes('principals') && made.relations.includes('mcp_approvals') && made.functions.includes('secret_versions_erase_only'), JSON.stringify(made));
  assert.deepEqual(made.types.toSorted(), ['use_row', 'use_view'], JSON.stringify(made));
  // A name followed by a dot is a schema: the SQL that 0022's and 0049's functions run makes no table named public.
  assert.ok(!made.relations.includes('public'), JSON.stringify(made));
  assert.deepEqual(managedObjects(["EXECUTE format('CREATE TABLE public.%I (LIKE public.log_uses)', name);\nCREATE TABLE drizzle.ledger ();\nCREATE TABLE \"public\".made ();"]).relations, ['made']);
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

/** The change 0.15.0's vault writes in its log at its first start (0041's `log_cutover`), without which 0.15.0's database is refused. */
async function cutOver(name: string): Promise<void> {
  await asSuperuser(name, (client) => client.unsafe(
    `INSERT INTO log_changes (number, at, request_id, object, actor, payload, seal, mac)
      VALUES (1, 0, 'cutover', log_object('log', 'cutover'), 'system:vault', '{"op":"cutover"}', NULL, '\\x${'00'.repeat(16)}')`,
  ));
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

/** A runtime login's settings, server-wide, as `pg_db_role_setting` holds them. */
function roleSettings(login: string): Promise<string[]> {
  return asSuperuser('postgres', async (client) =>
    [...((await client.unsafe<{ setconfig: string[] }[]>('SELECT setconfig FROM pg_db_role_setting WHERE setrole = $1::regrole AND setdatabase = 0', [login]))[0]?.setconfig ?? [])]);
}

test("a login that may alter the runtime logins gives them their statement timeout; one that may not migrates, and says what an administrator runs", needsCluster, async () => {
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  const timeouts = async () => [await roleSettings('coffre_runtime'), await roleSettings('coffre_vault_runtime')];
  // A superuser may: nothing said, the timeout given.
  const run = await migrateIn(dir, await fresh('setup_migrate_timeouts'));
  assert.equal(run.code, 0, run.output);
  assert.doesNotMatch(run.output, /statement timeout/);
  assert.deepEqual(await timeouts(), [['statement_timeout=60s'], ['statement_timeout=60s']]);

  // An owner with CREATEROLE but not ADMIN on the logins, which a superuser made: the run goes on, and says so.
  await emptyCluster();
  const owned = await database('setup_migrate_timeouts_owner', 'owner');
  await asSuperuser('postgres', async (client) => {
    await client.unsafe('CREATE ROLE coffre_runtime LOGIN');
    await client.unsafe('CREATE ROLE coffre_vault_runtime LOGIN');
  });
  const said =
    /\n {2}! coffre_runtime and coffre_vault_runtime lack coffre's statement timeout, 60s, which this login may not give them\. coffre works without it; to bound a stuck statement, have a login with CREATEROLE and ADMIN on them run, once per server: ALTER ROLE coffre_runtime SET statement_timeout = '60s'; ALTER ROLE coffre_vault_runtime SET statement_timeout = '60s'; \(docs\/deploy\.md, "Statement timeouts"\)\n/;
  const left = await migrateIn(dir, owned);
  assert.equal(left.code, 0, left.output);
  assert.match(left.output, said);
  assert.deepEqual(await timeouts(), [[], []]);
  // A run with nothing to apply says it again, until an administrator has run them.
  assert.match((await migrateIn(dir, owned)).output, said);
  await asSuperuser('postgres', async (client) => {
    await client.unsafe("ALTER ROLE coffre_runtime SET statement_timeout = '60s'");
    await client.unsafe("ALTER ROLE coffre_vault_runtime SET statement_timeout = '60s'");
  });
  assert.doesNotMatch((await migrateIn(dir, owned)).output, /statement timeout/);
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

test('a database a release before 0.15.0 made, or a 0.15.0 whose vault has not cut its log over, is refused, and nothing changes', needsCluster, async () => {
  const url = await fresh('setup_migrate_uncut');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  // One short of 0.15.0's last migration: a database a release before 0.15.0 left.
  const before = KNOWN[KNOWN.indexOf('0049_reads') - 1]!;
  await migrateThrough(url, before);
  const old = await migrateIn(dir, url);
  assert.equal(old.code, 1);
  assert.match(old.output, /the database was made by a coffre before 0\.15\.0, which this version does not upgrade from: upgrade it to 0\.15\.0 and start it once/);
  assert.equal(await applied(url), KNOWN.indexOf(before) + 1);
  // 0.15.0's schema, its vault never started: no cutover change in its log.
  await migrateThrough(url, '0049_reads');
  const uncut = await migrateIn(dir, url);
  assert.equal(uncut.code, 1);
  assert.match(uncut.output, /the database's audit log is not moved to 0\.15's yet, which 0\.15\.0's vault does at its first start: start 0\.15\.0 once/);
  await assert.rejects(migrateDatabase(url), /the database's audit log is not moved to 0\.15's yet/);
  assert.equal(await applied(url), KNOWN.indexOf('0049_reads') + 1);
});

test("a 0.15.0 database whose vault cut its log over migrates to this version", needsCluster, async () => {
  const url = await fresh('setup_migrate_cut');
  await migrateThrough(url, '0049_reads');
  await cutOver('setup_migrate_cut');
  const run = await migrateIn(deploymentFolder(pinnedAt(cliVersion())), url);
  assert.equal(run.code, 0, run.output);
  assert.equal(await applied(url), KNOWN.length);
});

test("a database that applied 0000's or 0022's text from before 0.16.0 migrates on; any other text there is refused", needsCluster, async () => {
  const url = await fresh('setup_migrate_rewritten');
  await migrateDatabase(url);
  const ledger = (tag: string, hash: string) => asSuperuser('setup_migrate_rewritten', (client) => client.unsafe(
    'UPDATE drizzle.__drizzle_migrations SET hash = $1 WHERE created_at = $2',
    [hash, journal.entries.find((entry) => entry.tag === tag)!.when],
  ));
  // 0.15.0's texts: 0000 altered and granted the group roles even when they were right, 0022 gave the hot login generic plans.
  await ledger('0000_baseline', '9d41ba8fdca496e46583f631984217b9d571f08700af891e44652e1f818d78fd');
  await ledger('0022_log_015', '738dd033a0339eac8218494a5cc43568c1b06ad363cd2aa3c0dfc9c82570a2da');
  await migrateDatabase(url);
  await ledger('0022_log_015', 'ef'.repeat(32));
  await assert.rejects(migrateDatabase(url), /migration history diverged at 0022_log_015; applied migrations must never be edited/);
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

/**
 * coffre's objects in public and drizzle that `owner` does not own, with their owners: relations but indexes, a
 * composite type among them, statistics objects, functions, and the other types but arrays, comma-separated, or
 * null when there is none.
 */
async function notTheOwners(databaseName: string, owner: string): Promise<string | null> {
  return asSuperuser(databaseName, async (client) => {
    const [{ names }] = await client.unsafe<[{ names: string | null }]>(
      `SELECT string_agg(name, ', ' ORDER BY name) AS names FROM (
        SELECT c.oid::regclass::text || '=' || pg_get_userbyid(c.relowner) AS name FROM pg_class c
         WHERE c.relnamespace IN ('public'::regnamespace, 'drizzle'::regnamespace) AND c.relowner <> $1::regrole AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c')
        UNION ALL SELECT s.stxname || '=' || pg_get_userbyid(s.stxowner) FROM pg_statistic_ext s
         WHERE s.stxnamespace IN ('public'::regnamespace, 'drizzle'::regnamespace) AND s.stxowner <> $1::regrole
        UNION ALL SELECT p.oid::regprocedure::text || '=' || pg_get_userbyid(p.proowner) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proowner <> $1::regrole
        UNION ALL SELECT t.oid::regtype::text || '=' || pg_get_userbyid(t.typowner) FROM pg_type t
         WHERE t.typnamespace = 'public'::regnamespace AND t.typowner <> $1::regrole AND t.typrelid = 0 AND t.typelem = 0
      ) AS objects`,
      [owner],
    );
    return names;
  });
}

/** Apply this version's migrations to `url` up to `last`, as a release that stopped there did, in one transaction. */
async function migrateThrough(url: string, last: string): Promise<void> {
  const client = postgresClient(url, { max: 1 });
  try {
    await client.begin(async (tx) => {
      await tx.unsafe('CREATE SCHEMA IF NOT EXISTS drizzle');
      await tx.unsafe('CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)');
      const [{ n }] = await tx.unsafe<[{ n: string }]>('SELECT count(*) AS n FROM drizzle.__drizzle_migrations');
      for (const { tag, when } of journal.entries.slice(Number(n), KNOWN.indexOf(last) + 1)) {
        const text = readFileSync(join(migrationsFolder(), `${tag}.sql`), 'utf8');
        for (const statement of text.split('--> statement-breakpoint')) await tx.unsafe(statement);
        await tx.unsafe('INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2)', [createHash('sha256').update(text).digest('hex'), when]);
      }
    });
  } finally {
    await client.end();
  }
}

test("a member of the owner hands it, before the migrations commit, what it made, partitions and detached tables included, and nothing when they fail; one that may not become the owner is told the GRANT that lets it", needsCluster, async () => {
  await emptyCluster();
  const owned = await database('setup_migrate_as_owner', 'owner');
  const owner = postgresClient(owned, { max: 1 });
  try {
    await owner.unsafe('CREATE ROLE coffre_runtime LOGIN');
    await owner.unsafe('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await owner.end();
  }
  await migrateDatabase(owned);
  // A member that inherits, as a managed host's admin login, which made a table, functions and a type of coffre's
  // itself, as its migrations did before T193, and with them a day of uses and a range of tiles, partitions. Each of
  // those then detached, as retention's first step leaves it, which a later run drops (0027's `drop_day`, `drop_tiles`).
  await asSuperuser('postgres', (client) => client.unsafe("CREATE ROLE setup_deployer LOGIN PASSWORD 'deployer-only-p4ss' IN ROLE setup_owner"));
  const deployer = new URL(owned);
  deployer.username = 'setup_deployer';
  deployer.password = 'deployer-only-p4ss';
  await asSuperuser('setup_migrate_as_owner', async (client) => {
    await client.unsafe('ALTER TABLE principals OWNER TO setup_deployer');
    await client.unsafe('ALTER FUNCTION make_day(date) OWNER TO setup_deployer');
    await client.unsafe('ALTER FUNCTION make_tiles(bigint, bigint) OWNER TO setup_deployer');
    await client.unsafe('ALTER TYPE use_row OWNER TO setup_deployer');
    // A statistics object is its maker's, which an ALTER of its table leaves (0065).
    await client.unsafe('ALTER STATISTICS log_changes_records_stats OWNER TO setup_deployer');
    await client.unsafe("SET ROLE setup_deployer; SELECT make_day(date '2031-01-01'), make_day(date '2031-01-02'), make_tiles(4294967296, 4294967552); RESET ROLE");
    await client.unsafe('ALTER TABLE log_uses DETACH PARTITION log_uses_20310101');
    await client.unsafe('ALTER TABLE log_tiles_uses_leaves DETACH PARTITION log_tiles_uses_4294967296');
  });
  const made = 'log_changes_records_stats=setup_deployer, log_tiles_uses_4294967296=setup_deployer, log_uses_20310101=setup_deployer, log_uses_20310102=setup_deployer, ' +
    'make_day(date)=setup_deployer, make_tiles(bigint,bigint)=setup_deployer, principals=setup_deployer, use_row=setup_deployer';
  assert.equal(await notTheOwners('setup_migrate_as_owner', 'setup_owner'), made, 'the indexes and the sequences move with their table');

  // The hand-over is the migrations' transaction's: a run that fails, here waiting for a table another session reads,
  // hands over nothing, as it applies nothing.
  await asSuperuser('setup_migrate_as_owner', (client) =>
    client.begin(async (tx) => {
      await tx.unsafe('LOCK TABLE principals IN ACCESS SHARE MODE');
      await assert.rejects(migrateDatabase(deployer.href), (error) => error instanceof LockWaitsExhausted);
    }),
  );
  assert.equal(await notTheOwners('setup_migrate_as_owner', 'setup_owner'), made);

  await migrateDatabase(deployer.href);
  assert.equal(await notTheOwners('setup_migrate_as_owner', 'setup_owner'), null, "every one of them is the owner's");
  await asSuperuser('setup_migrate_as_owner', async (client) => {
    const [{ inherited }] = await client.unsafe<[{ inherited: string }]>("SELECT pg_get_userbyid(relowner) AS inherited FROM pg_class WHERE oid = 'principals_pkey'::regclass");
    assert.equal(inherited, 'setup_owner');
    // Retention's second step, as the owner its functions run as: it drops what it detached.
    await client.unsafe('SET ROLE setup_owner; DROP TABLE public.log_uses_20310101; DROP TABLE public.log_tiles_uses_4294967296; RESET ROLE');
  });

  // A membership that inherits the owner's privileges but may not become it: what it made would be its own.
  await asSuperuser('postgres', (client) => client.unsafe('GRANT setup_owner TO setup_deployer WITH SET FALSE'));
  const refusal = 'coffre\'s tables are owned by setup_owner, and this login, setup_deployer, inherits its privileges but may not become it (SET ROLE), which handing it what the migrations make asks: ' +
    'migrate with setup_owner\'s connection string, or, as a role that administers it, run GRANT "setup_owner" TO "setup_deployer" WITH SET TRUE';
  const refused = await migrateDatabase(deployer.href).then(
    () => assert.fail('migrated as a member that may not become the owner'),
    (error: unknown) => error as NotOwner,
  );
  assert.ok(refused instanceof NotOwner, String(refused));
  assert.equal(refused.message, refusal);
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  const told = await migrateIn(dir, deployer.href);
  assert.equal(told.code, 0, told.output);
  assert.ok(told.output.includes(`The next migration needs another login: ${refusal}`), told.output);
  // What it says to run, run as it says.
  await asSuperuser('postgres', (client) => client.unsafe(refusal.slice(refusal.lastIndexOf('run ') + 4)));
  await migrateDatabase(deployer.href);
});

test("a superuser migrates with its own attributes, and hands the owner what a member made, which the owner itself is told to have handed", needsCluster, async () => {
  await emptyCluster();
  // 0.15.0, cut over, whose owner then lost CREATEROLE: the superuser migrates.
  const owned = await database('setup_migrate_superuser', 'owner');
  const owner = postgresClient(owned, { max: 1 });
  try {
    await owner.unsafe('CREATE ROLE coffre_runtime LOGIN');
    await owner.unsafe('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await owner.end();
  }
  await migrateThrough(owned, '0049_reads');
  await cutOver('setup_migrate_superuser');
  await asSuperuser('postgres', (client) => client.unsafe("CREATE ROLE setup_deployer LOGIN PASSWORD 'deployer-only-p4ss' IN ROLE setup_owner"));
  await asSuperuser('setup_migrate_superuser', (client) => client.unsafe('ALTER TABLE vault_members OWNER TO setup_deployer'));

  // The owner lacks its member's privileges, and granting them to it would be a cycle: it is told whose login, or a
  // superuser's, hands them over, and nothing changes.
  const refused = await migrateDatabase(owned).then(
    () => assert.fail("the owner migrated over its member's table"),
    (error: unknown) => error as NotOwner,
  );
  assert.ok(refused instanceof NotOwner, String(refused));
  assert.equal(
    refused.message,
    "coffre's tables are owned by setup_deployer, and this login, setup_owner, is neither it nor a member of it: " +
      "migrate once with setup_deployer's connection string, or a superuser's, which hands its objects to the owner of coffre's ledger",
  );
  assert.equal(await applied(owned), KNOWN.indexOf('0049_reads') + 1);

  await asSuperuser('postgres', (client) => client.unsafe('ALTER ROLE setup_owner NOCREATEROLE'));
  await migrateDatabase(`${CLUSTER}/setup_migrate_superuser`);
  assert.equal(await applied(owned), KNOWN.length);
  assert.equal(await notTheOwners('setup_migrate_superuser', 'setup_owner'), null, "what the superuser made and the member's table are the owner's");
  await asSuperuser('postgres', (client) => client.unsafe('ALTER ROLE setup_owner CREATEROLE'));
  // The owner, and its member, migrate on.
  await migrateDatabase(owned);
  const deployer = new URL(owned);
  deployer.username = 'setup_deployer';
  deployer.password = 'deployer-only-p4ss';
  await migrateDatabase(deployer.href);
});

test("a day of uses that a call under way when the hand-over committed makes as the member stays the member's until a run after its transaction commits hands it over, and a table of the database's own named public stays the member's", needsCluster, async () => {
  await emptyCluster();
  const owned = await database('setup_migrate_meanwhile', 'owner');
  const owner = postgresClient(owned, { max: 1 });
  try {
    await owner.unsafe('CREATE ROLE coffre_runtime LOGIN');
    await owner.unsafe('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await owner.end();
  }
  await migrateDatabase(owned);
  await asSuperuser('postgres', (client) => client.unsafe("CREATE ROLE setup_deployer LOGIN PASSWORD 'deployer-only-p4ss' IN ROLE setup_owner"));
  const deployer = new URL(owned);
  deployer.username = 'setup_deployer';
  deployer.password = 'deployer-only-p4ss';
  // make_day as a member made it before T193, and, beside coffre's, a table of the database's own, public.public.
  await asSuperuser('setup_migrate_meanwhile', async (client) => {
    await client.unsafe('ALTER FUNCTION make_day(date) OWNER TO setup_deployer');
    await client.unsafe('CREATE TABLE public.public (id int); ALTER TABLE public.public OWNER TO setup_deployer');
  });

  // A call of make_day enters as the member, then waits for the uses' table, which another session holds, to make its
  // day: the hand-over commits meanwhile, and the call, let go once it has, makes the day as the role it entered as.
  // The run does not wait for it (docs/deploy.md): the day is the member's until the next run, which hands it over.
  const caller = postgresClient(deployer.href, { max: 1 });
  try {
    await asSuperuser('setup_migrate_meanwhile', async (holder) => {
      await holder.unsafe('BEGIN; LOCK TABLE public.log_uses IN ACCESS EXCLUSIVE MODE');
      // A query of postgres.js's is sent once it is awaited, or then'd.
      const day = caller.unsafe("SELECT make_day(date '2037-01-03')").then(() => undefined);
      const waits = async (query: string) => {
        for (let tries = 0; (await asSuperuser('setup_migrate_meanwhile', (other) => other.unsafe(query))).length === 0; tries += 1) {
          assert.ok(tries < 200, `never: ${query}`);
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
      };
      await waits("SELECT 1 FROM pg_locks WHERE relation = 'public.log_uses'::regclass AND NOT granted");
      const migrated = migrateDatabase(deployer.href);
      await waits("SELECT 1 FROM pg_proc WHERE oid = 'make_day(date)'::regprocedure AND proowner = 'setup_owner'::regrole");
      await holder.unsafe('COMMIT');
      await Promise.all([day, migrated]);
    });
  } finally {
    await caller.end();
  }
  assert.equal(await notTheOwners('setup_migrate_meanwhile', 'setup_owner'), 'log_uses_20370103=setup_deployer, public=setup_deployer', "the day the call made is the member's");
  await migrateDatabase(deployer.href);
  assert.equal(await notTheOwners('setup_migrate_meanwhile', 'setup_owner'), 'public=setup_deployer', "the next run, with nothing to apply, hands the owner the day, and leaves the database's own table its own");

  // A call that has made its day but whose transaction is still open when the runs hand over: no run sees the day
  // until that transaction commits, so a run meanwhile, however many, misses it, and the first one after hands it over.
  await asSuperuser('setup_migrate_meanwhile', (client) => client.unsafe('ALTER FUNCTION make_day(date) OWNER TO setup_deployer'));
  const open = postgresClient(deployer.href, { max: 1 });
  try {
    await open.unsafe("BEGIN; SELECT make_day(date '2037-01-04')");
    await migrateDatabase(deployer.href);
    await migrateDatabase(deployer.href);
    assert.equal(await notTheOwners('setup_migrate_meanwhile', 'setup_owner'), 'public=setup_deployer', "no other session sees the open transaction's day yet");
    await open.unsafe('COMMIT');
  } finally {
    await open.end();
  }
  assert.equal(await notTheOwners('setup_migrate_meanwhile', 'setup_owner'), 'log_uses_20370104=setup_deployer, public=setup_deployer', "committed after the runs, the day is the member's");
  await migrateDatabase(deployer.href);
  assert.equal(await notTheOwners('setup_migrate_meanwhile', 'setup_owner'), 'public=setup_deployer', 'the first run after the commit hands it over');
});
