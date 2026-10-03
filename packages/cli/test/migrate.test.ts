import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import pg from 'pg';

import { migrationsFolder } from '@coffre/db/migrate';

import { migrationFailure, pendingOf, versionProblem } from '../src/migrate.ts';
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

test('migrate applies 0001 to a database at the baseline, and the instance then sees it, ready', needsCluster, async () => {
  const url = await atBaseline('setup_migrate_baseline');
  assert.deepEqual(await schema(url), { applied: 1, syncs: true });
  const { origin, server } = await instance(cliVersion(), url);
  try {
    const run = await migrate(origin, url);
    assert.equal(run.code, 0, run.output);
    assert.match(run.output, /Applied 0001_remove_syncs, and reasserted the database's privileges/);
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
