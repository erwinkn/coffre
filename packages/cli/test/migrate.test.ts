import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';

import { AfterMigrations, managedObjects, migrateDatabase, migrationsFolder, NotOwner } from '@coffre/db/migrate';

import { describeEveryProject, describeFirstRun, describeIssuers, describeUnsealed, migrationFailure, pinProblem } from '../src/migrate.ts';
import { cliVersion } from '../src/version.ts';
import { asSuperuser, database, emptyCluster, needsCluster } from './cluster.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const journal = JSON.parse(readFileSync(join(migrationsFolder('postgres'), 'meta', '_journal.json'), 'utf8')) as {
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

test("migrate lists 0.4's tokens and bindings by account, which keep what their account holds when this version first runs", () => {
  assert.equal(describeUnsealed([]), '');
  assert.equal(
    describeUnsealed([
      { kind: 'token', id: 't1', principal: 'token:ci-web', createdBy: 'erwin@acme.example', scope: null },
      { kind: 'token', id: 't2', principal: 'token:ci-web', createdBy: 'erwin@acme.example', scope: null },
      { kind: 'binding', id: 'b1', principal: 'token:ci-web', createdBy: 'erwin@acme.example', scope: null },
      { kind: 'binding', id: 'b2', principal: 'token:deploy', createdBy: 'erwin@acme.example', scope: null },
    ]),
    [
      '',
      'Service tokens and trust bindings now carry their own scope, and what an account is given later reaches none made before.',
      'When this version first checks a credential, each of these keeps what its account holds then, after any conversion above:',
      '  service:ci-web: 2 tokens and 1 trust binding',
      '  service:deploy: 1 trust binding',
      'Grant or revoke before you deploy to choose what they keep; to change one after, issue another and revoke it.',
      '',
    ].join('\n'),
  );
});

test('migrate lists the tokens and bindings of a release before 0.11 by account and issuer, which read sensitive values where their issuer owns the project', () => {
  assert.equal(describeIssuers([]), '');
  const scope = '[{"projectId":"p","environmentId":null,"role":"viewer"}]';
  assert.equal(
    describeIssuers([
      { kind: 'token', id: 't1', principal: 'token:ci-web', createdBy: 'erwin@acme.example', scope },
      { kind: 'binding', id: 'b1', principal: 'token:ci-web', createdBy: 'ada@acme.example', scope },
      { kind: 'binding', id: 'b2', principal: 'token:deploy', createdBy: 'erwin@acme.example', scope },
    ]),
    [
      '',
      'A service token or trust binding now reads a sensitive value only where an Owner of its project issued it.',
      'When this version first checks a credential, each of these reads them where whoever issued it is an Owner of the project then, project by project:',
      '  service:ci-web: 1 token and 1 trust binding, issued by erwin@acme.example, ada@acme.example',
      '  service:deploy: 1 trust binding, issued by erwin@acme.example',
      "Anyone else's, one whose issuer has left included, read every other value; an Owner of the project issues one that reads them too.",
      '',
    ].join('\n'),
  );
});

test('migrate says which accounts hold nothing, whose tokens and bindings would reach nothing for good', () => {
  const unsealed = [
    { kind: 'token' as const, id: 't1', principal: 'token:ci-web', createdBy: 'erwin@acme.example', scope: null },
    { kind: 'token' as const, id: 't2', principal: 'token:idle', createdBy: 'erwin@acme.example', scope: null },
    { kind: 'binding' as const, id: 'b1', principal: 'token:idle', createdBy: 'erwin@acme.example', scope: null },
    { kind: 'token' as const, id: 't3', principal: 'token:old', createdBy: 'erwin@acme.example', scope: null },
  ];
  const conversion = (grants: number) => ({ role: 'member', scope: { projects: 'all', environments: 'all' }, grants: Array.from({ length: grants }, () => ({ projectId: 'p', environmentId: null, role: 'viewer' })), narrowed: [] });
  const said = describeFirstRun({
    everyProject: [
      // On every project, which the vault converts: it holds what that becomes.
      { principal: 'token:ci-web', before: [{ place: '*', role: 'viewer', expiresAt: null }], conversion: conversion(1), paths: { p: 'market' }, reported: false },
      // Reported tampered with: left as it is, which no scope reaches.
      { principal: 'token:old', before: [{ place: '*', role: 'viewer', expiresAt: null }], conversion: conversion(1), paths: { p: 'market' }, reported: true },
    ] as never,
    unsealed,
    holding: new Set(['user:ada@acme.example']),
  }).split('\n');
  assert.ok(said.includes('  service:ci-web: 1 token'));
  assert.ok(said.includes('  service:idle: 1 token and 1 trust binding, which will reach nothing: grant the account before you deploy, or reissue them after'));
  assert.ok(said.includes('  service:old: 1 token, which will reach nothing: grant the account before you deploy, or reissue it after'));
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
    `the migrations are applied, but reasserting the database's privileges after them failed: permission denied to grant role "coffre_backup"`,
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
  const made = managedObjects(readdirSync(migrationsFolder('postgres')).filter((file) => file.endsWith('.sql')).map((file) => readFileSync(join(migrationsFolder('postgres'), file), 'utf8')));
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
  await asSuperuser('postgres', (client) => client.query("CREATE ROLE coffre_backup_login LOGIN PASSWORD 'backup'"));
  const membership = () => asSuperuser('postgres', async (client) =>
    (await client.query("SELECT admin_option, inherit_option, set_option FROM pg_auth_members WHERE roleid = 'coffre_backup'::regrole AND member = 'coffre_backup_login'::regrole")).rows);
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
  assert.match(absent.output, /reasserting the database's privileges after them failed: role "nobody_here" does not exist/);
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
  const owner = new pg.Client({ connectionString: owned });
  await owner.connect();
  try {
    await owner.query('CREATE ROLE coffre_runtime LOGIN');
    await owner.query('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await owner.end();
  }
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  assert.equal((await migrateIn(dir, owned)).code, 0);
  // Then deployed with another, as PlanetScale gives a second: CREATEROLE too, a member of no role.
  await asSuperuser('postgres', (client) => client.query("CREATE ROLE setup_deployer LOGIN CREATEROLE PASSWORD 'deployer-only-p4ss'"));
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
  await asSuperuser('postgres', (client) => client.query('GRANT pg_read_all_data, pg_write_all_data TO setup_deployer'));
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
    (await client.query('DELETE FROM drizzle.__drizzle_migrations WHERE id = (SELECT max(id) FROM drizzle.__drizzle_migrations) RETURNING hash, created_at')).rows[0] as { hash: string; created_at: string },
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
  await asSuperuser('postgres', (client) => client.query('GRANT setup_owner TO setup_deployer'));
  await migrateDatabase(deployer.href);
  const member = await migrateIn(dir, deployer.href);
  assert.equal(member.code, 0, member.output);
  assert.doesNotMatch(member.output, /another login/);

  // A table of the database's own in public, which another role owns, is not coffre's to change.
  await asSuperuser('setup_migrate_owners', async (client) => {
    await client.query('CREATE ROLE setup_reporting');
    await client.query('CREATE TABLE public.unrelated_reporting_data (id int)');
    await client.query('ALTER TABLE public.unrelated_reporting_data OWNER TO setup_reporting');
  });
  await migrateDatabase(owned);
  const unrelated = await migrateIn(dir, owned);
  assert.equal(unrelated.code, 0, unrelated.output);
  assert.doesNotMatch(unrelated.output, /another login|setup_reporting/);
});

test('a member of the owner that does not inherit its privileges is told so, and the GRANT it says lets it migrate', needsCluster, async () => {
  await emptyCluster();
  const owned = await database('setup_migrate_inherit', 'owner');
  const owner = new pg.Client({ connectionString: owned });
  await owner.connect();
  try {
    await owner.query('CREATE ROLE coffre_runtime LOGIN');
    await owner.query('CREATE ROLE coffre_vault_runtime LOGIN');
  } finally {
    await owner.end();
  }
  await migrateDatabase(owned);
  // NOINHERIT: on Postgres 16 its memberships do not inherit unless granted so; a plain GRANT gives one that does not.
  await asSuperuser('postgres', async (client) => {
    await client.query("CREATE ROLE setup_deployer LOGIN NOINHERIT PASSWORD 'deployer-only-p4ss'");
    await client.query('GRANT setup_owner TO setup_deployer');
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
  await asSuperuser('postgres', (client) => client.query(refused.message.slice(refused.message.lastIndexOf('run ') + 4)));
  await migrateDatabase(deployer.href);
});
