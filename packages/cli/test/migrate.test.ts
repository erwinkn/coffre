import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';

import { migrationsFolder } from '@coffre/db/migrate';

import { migrationFailure, pendingOf, pinProblem, versionProblem } from '../src/migrate.ts';
import { cliVersion } from '../src/version.ts';
import { database, emptyCluster, needsCluster } from './cluster.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const ORIGIN = 'https://coffre.example';
const journal = JSON.parse(readFileSync(join(migrationsFolder('postgres'), 'meta', '_journal.json'), 'utf8')) as {
  entries: { tag: string; when: number }[];
};
const KNOWN = journal.entries.map((entry) => entry.tag);

// --- without a database ------------------------------------------------------------

test('a CLI older than the instance is told to update to its version; a newer one, to wait for the deploy', () => {
  assert.equal(versionProblem('0.1.12', '0.1.12', ORIGIN), null);
  assert.match(versionProblem('0.1.11', '0.1.12', ORIGIN)!, /runs coffre 0\.1\.12, and this CLI is 0\.1\.11: run `coffre update` \(to 0\.1\.12\)/);
  assert.match(versionProblem('0.1.12', '0.1.11', ORIGIN)!, /deploy 0\.1\.12 first, or migrate with the CLI it runs, `npx @coffre\/cli@0\.1\.11 migrate`/);
  assert.match(versionProblem('0.1.9', '0.1.10', ORIGIN)!, /coffre update/, 'by number, not as text');
});

test('what is pending is what the instance knows and has not applied', () => {
  assert.deepEqual(pendingOf({ version: '0.1.12', migrations: { applied: 1, known: KNOWN } }), KNOWN.slice(1));
  assert.deepEqual(pendingOf({ version: '0.1.12', migrations: { applied: KNOWN.length, known: KNOWN } }), []);
});

test("a migration's refusal is its own sentence, not the SQL around it", () => {
  const refusal = Object.assign(new Error('syncs are removed: migrate destinations to service tokens, back up and clear syncs and sync_keys before upgrading'), {
    code: 'P0001',
  });
  const wrapped = new Error('Failed query: DO $$ BEGIN … END $$\nparams: ', { cause: refusal });
  assert.equal(
    migrationFailure(wrapped),
    'syncs are removed: migrate destinations to service tokens, back up and clear syncs and sync_keys before upgrading. ' +
      'Nothing was changed: the migrations run in one transaction.',
  );
});

/**
 * An instance, as `coffre migrate` asks it: its version and its database's
 * migrations on `/api/me`, and `/readyz`. Its database is the one given,
 * read on each request, so that it reports what a migration did.
 */
async function instance(version: string, url: string | null): Promise<{ origin: string; server: Server }> {
  const applied = async () => {
    if (url === null) return 1;
    const client = new pg.Client({ connectionString: url });
    await client.connect();
    try {
      return Number((await client.query('SELECT count(*) AS n FROM drizzle.__drizzle_migrations')).rows[0].n);
    } finally {
      await client.end();
    }
  };
  const server = createServer(async (request, response) => {
    const send = (body: unknown) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (request.url === '/api/me') {
      return send({
        principal: { type: 'user', id: 'admin@acme.example' },
        registered: true,
        tampered: false,
        instanceRole: 'root-admin',
        isRootAdmin: true,
        canReadAudit: true,
        environments: [],
        instance: { version, migrations: { applied: await applied(), known: KNOWN } },
      });
    }
    // The schema half of readiness: every migration the code requires, which is the baseline.
    if (request.url === '/readyz') return send({ ok: (await applied()) >= 1, heartbeatAgeSeconds: 30, checkpointed: true });
    response.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as { port: number };
  return { origin: `http://127.0.0.1:${address.port}`, server };
}

/** `coffre migrate`, as a script runs it: no terminal, the URL in the environment. */
function migrate(origin: string, url: string | null, args: string[] = ['--yes']): Promise<{ code: number | null; output: string }> {
  const home = mkdtempSync(join(tmpdir(), 'coffre-migrate-'));
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'migrate', ...args], {
    env: {
      PATH: process.env.PATH,
      HOME: home,
      COFFRE_API_URL: origin,
      COFFRE_AUTH_MODE: 'signin',
      COFFRE_TOKEN: 'coffre_svc_test',
      ...(url === null ? {} : { COFFRE_MIGRATE_DATABASE_URL: url }),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
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

test('migrate refuses an instance that runs another version, before asking for anything', async () => {
  const { origin, server } = await instance('99.0.0', null);
  try {
    const run = await migrate(origin, null);
    assert.equal(run.code, 1);
    assert.match(run.output, new RegExp(`runs coffre 99\\.0\\.0, and this CLI is ${cliVersion().replace(/\./g, '\\.')}: run \`coffre update\` \\(to 99\\.0\\.0\\)`));
    assert.doesNotMatch(run.output, /connection string/, 'it never asks for the database');
  } finally {
    server.close();
  }
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

/** `coffre migrate`, as a deployment's pipeline runs it in its folder: no terminal, no session, the URL in the environment. */
function migrateIn(dir: string, url: string | null, args: string[] = ['--yes']): Promise<{ code: number | null; output: string }> {
  const home = mkdtempSync(join(tmpdir(), 'coffre-migrate-'));
  const child = spawn(process.execPath, ['--conditions=coffre:source', main, 'migrate', ...args], {
    cwd: dir,
    env: { PATH: process.env.PATH, HOME: home, ...(url === null ? {} : { COFFRE_MIGRATE_DATABASE_URL: url }) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
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
    // An instance is not what it migrates there.
    const named = await migrateIn(deploymentFolder(pinnedAt(cliVersion())), null, ['--yes', '--url', ORIGIN]);
    assert.equal(named.code, 1);
    assert.match(named.output, /--url names an instance, and in a deployment's folder coffre migrate asks none/);
  } finally {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  }
});

// --- on a disposable cluster ---------------------------------------------------------

/**
 * A database where coffre 0.1.11 left it: the baseline applied, as drizzle
 * records it, and nothing after.
 */
async function atBaseline(name: string): Promise<string> {
  await emptyCluster();
  const url = await database(name, 'superuser');
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    const [baseline] = journal.entries;
    const sql = readFileSync(join(migrationsFolder('postgres'), `${baseline!.tag}.sql`), 'utf8');
    // As setup makes them, before it migrates: the baseline grants to them.
    await client.query('CREATE ROLE coffre_runtime LOGIN');
    await client.query('CREATE ROLE coffre_vault_runtime LOGIN');
    await client.query('CREATE SCHEMA IF NOT EXISTS drizzle');
    await client.query('CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)');
    await client.query(sql.split('--> statement-breakpoint').join('\n'));
    await client.query('INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2)', [
      createHash('sha256').update(sql).digest('hex'),
      baseline!.when,
    ]);
  } finally {
    await client.end();
  }
  return url;
}

async function schema(url: string): Promise<{ applied: number; syncs: boolean }> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    const applied = Number((await client.query('SELECT count(*) AS n FROM drizzle.__drizzle_migrations')).rows[0].n);
    const syncs = (await client.query("SELECT to_regclass('public.syncs') IS NOT NULL AS present")).rows[0].present as boolean;
    return { applied, syncs };
  } finally {
    await client.end();
  }
}

test('migrate applies what a database at the baseline lacks, and the instance then sees it, ready', needsCluster, async () => {
  const url = await atBaseline('setup_migrate_baseline');
  assert.deepEqual(await schema(url), { applied: 1, syncs: true });
  const { origin, server } = await instance(cliVersion(), url);
  try {
    const run = await migrate(origin, url);
    assert.equal(run.code, 0, run.output);
    assert.match(run.output, new RegExp(`Applied ${KNOWN.slice(1, -1).join(', ')} and ${KNOWN.at(-1)}, and reasserted the database's privileges`));
    assert.match(run.output, /sees the new schema, and is ready/);
    assert.ok(!run.output.includes(new URL(url).password), 'the password is never shown');
    assert.deepEqual(await schema(url), { applied: KNOWN.length, syncs: false });

    const again = await migrate(origin, null);
    assert.equal(again.code, 0, again.output);
    assert.match(again.output, /database is up to date/, 'once applied, there is nothing to ask for');
  } finally {
    server.close();
  }
});

const SPINNER = /[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]/;

test("in a deployment's folder, its pipeline migrates before the deploy, asking no instance; the deploy then finds its schema, and is ready", needsCluster, async () => {
  const url = await atBaseline('setup_migrate_pipeline');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  try {
    // Without a terminal, only with --yes.
    const asked = await migrateIn(dir, url, []);
    assert.equal(asked.code, 1);
    assert.match(asked.output, /nothing here to confirm on: run coffre migrate on a terminal, or pass --yes/);
    assert.deepEqual(await schema(url), { applied: 1, syncs: true });

    const run = await migrateIn(dir, url);
    assert.equal(run.code, 0, run.output);
    assert.match(run.output, new RegExp(`${KNOWN.length - 1} migrations to apply to \\S+, for coffre ${cliVersion().replace(/\./g, '\\.')}`));
    assert.match(run.output, new RegExp(`✓ Applied ${KNOWN.slice(1, -1).join(', ')} and ${KNOWN.at(-1)}, and reasserted the database's privileges`));
    // As a CI log keeps it: plain lines, no escape codes, no spinner, no password.
    assert.doesNotMatch(run.output, /\x1b\[/);
    assert.doesNotMatch(run.output, SPINNER);
    assert.ok(!run.output.includes(new URL(url).password), 'the password is never shown');
    assert.deepEqual(await schema(url), { applied: KNOWN.length, syncs: false });

    // Then the deploy: the new version finds every migration it knows applied, and is ready.
    const { origin, server } = await instance(cliVersion(), url);
    try {
      const me = (await (await fetch(`${origin}/api/me`)).json()) as { instance: Parameters<typeof pendingOf>[0] };
      assert.deepEqual(pendingOf(me.instance), []);
      assert.equal(((await (await fetch(`${origin}/readyz`)).json()) as { ok: boolean }).ok, true);
    } finally {
      server.close();
    }
    const again = await migrateIn(dir, url);
    assert.equal(again.code, 0, again.output);
    assert.match(again.output, new RegExp(`✓ \\S+ is up to date, at coffre \\S+'s schema: ${KNOWN.length} migrations, the last ${KNOWN.at(-1)}`));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a database a newer coffre migrated is refused in a deployment's folder, its unknown migration named, and nothing changes", needsCluster, async () => {
  const url = await atBaseline('setup_migrate_ahead');
  const dir = deploymentFolder(pinnedAt(cliVersion()));
  try {
    assert.equal((await migrateIn(dir, url)).code, 0);
    // What a later coffre would have recorded: a migration this one has never seen.
    const client = new pg.Client({ connectionString: url });
    await client.connect();
    await client.query('INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2)', ['ab'.repeat(32), Date.UTC(2030, 0, 2, 3, 4)]);
    await client.end();

    const run = await migrateIn(dir, url);
    assert.equal(run.code, 1);
    assert.match(
      run.output,
      new RegExp(`is ahead of coffre \\S+: has applied a migration this version does not know, after ${KNOWN.at(-1)}: one made 2030-01-02 03:04 UTC \\(abababababab\\)\\. A newer coffre migrated it\\. Deploy that version, or, to go back, restore the database from before it \\(docs/restore\\.md\\)\\. Nothing was changed`),
    );
    assert.deepEqual(await schema(url), { applied: KNOWN.length + 1, syncs: false });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('migrate refuses while syncs remain, in the migration’s own words, and changes nothing', needsCluster, async () => {
  const url = await atBaseline('setup_migrate_syncs');
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  // A destination left configured: its project and secret need not exist for this.
  await client.query('SET session_replication_role = replica');
  await client.query(
    `INSERT INTO syncs (project_id, environment_id, provider, config, credential_secret_id, created_by)
     VALUES (gen_random_uuid(), gen_random_uuid(), 'github-actions', '{}', gen_random_uuid(), 'admin@acme.example')`,
  );
  await client.end();

  const { origin, server } = await instance(cliVersion(), url);
  try {
    const run = await migrate(origin, url);
    assert.equal(run.code, 1);
    assert.match(
      run.output,
      /syncs are removed: migrate destinations to service tokens, back up and clear syncs and sync_keys before upgrading\. Nothing was changed/,
    );
    assert.doesNotMatch(run.output, /Failed query|statement-breakpoint|LOCK TABLE/, 'not the SQL');
    assert.deepEqual(await schema(url), { applied: 1, syncs: true });
  } finally {
    server.close();
  }
});
