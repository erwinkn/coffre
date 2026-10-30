import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createDatabase, type Database } from '@coffre/db';
import { openDatabase } from '@coffre/db/connect';
import type { Engine } from '@coffre/db/dialect';
import { readGrants } from '@coffre/db/grants';
import { migrateDatabase, migrationsFolder } from '@coffre/db/migrate';
import { migrated } from '@coffre/db/schema-version';
import { sql } from 'drizzle-orm';
import { postgresClient, quoteIdentifier } from '@coffre/db/connect';

import { appendAudit } from '../../src/db/audit.ts';
import { TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL } from './connections.ts';
import { TEST_ENGINE } from './engine.ts';

/**
 * 0.15's expand migration (0022_log_015 on Postgres, 0018_log_015 on
 * SQLite) on a database 0.14.5 made and used: every row it held is kept,
 * each sealed table gains a null seal (an environment its protection too, a binding the origin its seal covers, PR 3b) and nothing else, and 0.14.5's code
 * still reads it and appends to its log, the chain unbroken, as it serves
 * between `coffre migrate` and the deploy.
 */

const TAGS: Record<Engine, string> = { postgres: '0022_log_015', sqlite: '0018_log_015' };
const SEALED = ['credentials', 'environments', 'secrets', 'service_bindings', 'vault_members'];
const hex = (byte: number, length = 32) => Buffer.alloc(length, byte).toString('hex');

/** The engine's migrations up to the one before 0.15's first: 0.14.5's schema. */
function before(engine: Engine, dir: string): string {
  const folder = join(dir, 'migrations');
  cpSync(migrationsFolder(engine), folder, { recursive: true });
  const file = join(folder, 'meta/_journal.json');
  const journal = JSON.parse(readFileSync(file, 'utf8')) as { entries: { idx: number; tag: string }[] };
  const at = journal.entries.findIndex((entry) => entry.tag === TAGS[engine]);
  assert.ok(at > 0, `${TAGS[engine]} is one of the migrations`);
  writeFileSync(file, JSON.stringify({ ...journal, entries: journal.entries.slice(0, at) }));
  // It, and every one of 0.15's after it (0023_change_path, …).
  for (const { tag } of journal.entries.slice(at)) rmSync(join(folder, `${tag}.sql`));
  return folder;
}

/** 0.14.5's rows in every table the migration adds a column to, as both engines spell them. */
function rows(engine: Engine): string[] {
  const bytes = (byte: number, length = 32) => (engine === 'postgres' ? `decode('${hex(byte, length)}', 'hex')` : `X'${hex(byte, length)}'`);
  const time = (ms: number) => (engine === 'postgres' ? `to_timestamp(${ms / 1000})` : String(ms));
  return [
    `INSERT INTO projects (id, slug, name) VALUES ('11111111-1111-4111-8111-111111111111', 'market', 'Acme Market')`,
    `INSERT INTO environments (id, project_id, slug, name) VALUES ('22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', 'prod', 'Production')`,
    `INSERT INTO vault_members (principal, status, owner, generation, created_at, created_by, status_changed_at, status_changed_by, access_seq, mac)
       VALUES ('user:ada@acme.example', 'active', true, 1, 1, 'setup', 1, 'setup', 1, ${bytes(1)}),
              ('token:deploy', 'active', false, 1, 1, 'setup', 1, 'setup', 2, ${bytes(2)})`,
    `INSERT INTO vault_grants (principal, project_id, role, granted_at, granted_by) VALUES ('token:deploy', '11111111-1111-4111-8111-111111111111', 'viewer', 1, 'user:ada@acme.example')`,
    `INSERT INTO credentials (id, kind, auth_mac, token_hash, token_hint, generation, principal, created_by, expires_at)
       VALUES ('33333333-3333-4333-8333-333333333333', 'service', ${bytes(3)}, ${bytes(4)}, 'coffre_svc_…abcd', 1, 'token:deploy', 'user:ada@acme.example', ${time(4102444800000)})`,
    `INSERT INTO service_bindings (id, auth_mac, principal, generation, profile, issuer, jwks_uri, claims, created_by)
       VALUES ('66666666-6666-4666-8666-666666666666', ${bytes(5)}, 'token:deploy', 1, 'github', 'https://token.actions.githubusercontent.com', 'https://token.actions.githubusercontent.com/.well-known/jwks', '{"repository":"acme/market"}', 'user:ada@acme.example')`,
    `INSERT INTO secrets (id, project_id, environment_id, key) VALUES ('44444444-4444-4444-8444-444444444444', '11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', 'API_KEY')`,
    `INSERT INTO secret_versions (id, secret_id, version, envelope_version, ciphertext, iv, auth_tag, wrapped_dek, kek_provider, kek_id, kek_version, created_by)
       VALUES ('55555555-5555-4555-8555-555555555555', '44444444-4444-4444-8444-444444444444', 1, 1, ${bytes(6, 8)}, ${bytes(7, 12)}, ${bytes(8, 16)}, ${bytes(9, 40)}, 'local', 'k', '1', 'user:ada@acme.example')`,
    `UPDATE secrets SET current_version_id = '55555555-5555-4555-8555-555555555555', current_version = 1`,
  ];
}

type Opened = { owner: Database; app: Database; vault: Database; close: () => Promise<void> };
type Engine015 = { url: string; folder: string; open: () => Promise<Opened>; drop: () => Promise<void> };

async function postgresDatabase(dir: string): Promise<Engine015> {
  const name = `${new URL(TEST_OWNER_DATABASE_URL).pathname.slice(1)}_0021_${randomBytes(4).toString('hex')}`;
  const at = (base: string) => Object.assign(new URL(base), { pathname: `/${name}` }).toString();
  const admin = postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 });
  try {
    await admin.unsafe(`CREATE DATABASE ${quoteIdentifier(name)}`);
  } finally {
    await admin.end();
  }
  return {
    url: at(TEST_OWNER_DATABASE_URL),
    folder: before('postgres', dir),
    open: async () => {
      const pools = [TEST_OWNER_DATABASE_URL, TEST_RUNTIME_DATABASE_URL, TEST_VAULT_DATABASE_URL].map((base) => postgresClient(at(base), { max: 2 }));
      const [owner, app, vault] = pools.map((pool) => createDatabase(pool)) as [Database, Database, Database];
      return { owner, app, vault, close: async () => void (await Promise.all(pools.map((pool) => pool.end()))) };
    },
    drop: async () => {
      const client = postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 });
      try {
        await client.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(name)} WITH (FORCE)`);
      } finally {
        await client.end();
      }
    },
  };
}

function sqliteDatabase(dir: string): Engine015 {
  const url = `file:${join(dir, 'coffre.db')}`;
  return {
    url,
    folder: before('sqlite', dir),
    // SQLite has no logins: the app and the vault open the same file, as two processes would.
    open: async () => {
      const opened = await Promise.all([openDatabase(url), openDatabase(url), openDatabase(url)]);
      const [owner, app, vault] = opened.map(({ db }) => db) as [Database, Database, Database];
      return { owner, app, vault, close: async () => void (await Promise.all(opened.map(({ close }) => close()))) };
    },
    drop: async () => {},
  };
}

// A Database is a Postgres one to TypeScript (portable.ts); on SQLite, raw SQL goes through libsql's run and all.
type Raw = { execute(query: unknown): Promise<Record<string, unknown>[]>; run(query: unknown): Promise<unknown>; all(query: unknown): Promise<Record<string, unknown>[]> };

async function exec(db: Database, text: string): Promise<void> {
  const raw = db as unknown as Raw;
  await (TEST_ENGINE === 'postgres' ? raw.execute(sql.raw(text)) : raw.run(sql.raw(text)));
}

/** Rows as plain values, a column's bytes as hex, so that two reads compare. */
async function read(db: Database, table: string): Promise<Record<string, unknown>[]> {
  const raw = db as unknown as Raw;
  const query = sql.raw(`SELECT * FROM ${table} ORDER BY 1`);
  const found = TEST_ENGINE === 'postgres' ? [...await raw.execute(query)] : await raw.all(query);
  const plain = (value: unknown) =>
    value instanceof Uint8Array ? Buffer.from(value).toString('hex')
      : value instanceof ArrayBuffer ? Buffer.from(value).toString('hex')
        : value instanceof Date ? value.getTime() : value;
  return found.map((row) => Object.fromEntries(Object.entries(row).map(([key, value]) => [key, plain(value)])));
}

test(`${TAGS[TEST_ENGINE]} keeps 0.14.5's rows and leaves 0.14.5 serving: its reads, and its appends on an unbroken chain`, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-log-015-'));
  const database = TEST_ENGINE === 'postgres' ? await postgresDatabase(dir) : sqliteDatabase(dir);
  t.after(async () => {
    await database.drop();
    rmSync(dir, { recursive: true, force: true });
  });
  const chainKey = randomBytes(32);

  // 0.14.5's database: its schema, its rows, and entries its app appended.
  {
    const opened = await database.open();
    try {
      if (TEST_ENGINE === 'postgres') {
        const { migrate } = await import('drizzle-orm/node-postgres/migrator');
        await migrate(opened.owner as never, { migrationsFolder: database.folder });
      } else {
        const { migrate } = await import('drizzle-orm/libsql/migrator');
        await migrate(opened.owner as never, { migrationsFolder: database.folder });
      }
      assert.equal(await migrated(opened.owner), false, "0.14.5's schema lacks this tree's newest migration");
      for (const statement of rows(TEST_ENGINE)) await exec(opened.owner, statement);
      // This tree's appender names `log015` (0044), which 0.14.5's never does: a column of the old schema's only while
      // it appends as 0.14.5 would.
      await exec(opened.owner, 'ALTER TABLE audit_log ADD COLUMN log015 boolean');
      for (const action of ['project.update', 'secret.read']) {
        await opened.app.transaction((tx) => appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'test', action, decision: 'allow' }]));
      }
      await exec(opened.owner, 'ALTER TABLE audit_log DROP COLUMN log015');
    } finally {
      await opened.close();
    }
  }
  const kept = await (async () => {
    const opened = await database.open();
    try {
      return Object.fromEntries(await Promise.all([...SEALED, 'projects', 'vault_grants', 'secret_versions', 'audit_log'].map(async (table) => [table, await read(opened.owner, table)] as const)));
    } finally {
      await opened.close();
    }
  })();

  await migrateDatabase(database.url);

  const opened = await database.open();
  try {
    assert.equal(await migrated(opened.owner), true);
    for (const [table, before] of Object.entries(kept)) {
      const after = await read(opened.owner, table);
      if (SEALED.includes(table)) {
        // What 0.15 adds to its rows: the seal, an environment's protection, and a binding's origin.
        assert.deepEqual(after.map(({ seal, protected: _, origin: __, ...row }) => row), before, `${table} keeps its rows`);
        assert.ok(after.every((row) => row.seal === null && (row.protected ?? null) === null && (row.origin ?? null) === null), `${table}'s rows are not sealed yet`);
      } else if (table === 'audit_log') {
        // What 0.15 adds to its entries: whether a writer under its log wrote them (0044), none of 0.14.5's.
        assert.deepEqual(after.map(({ log015: _, ...row }) => row), before, `${table} is as it was`);
        assert.ok(after.every((row) => row.log015 === null), "0.14.5's entries are 0.14's");
      } else {
        assert.deepEqual(after, before, `${table} is as it was`);
      }
    }
    const [fence] = await read(opened.owner, 'log_fence');
    assert.ok(fence !== undefined && Number(fence.at_floor) > Date.now() - 600_000, 'the fence has its floor');
    for (const table of ['log_changes', 'log_uses', 'log_bulk', 'log_checkpoints', 'log_tiles', 'log_config']) {
      assert.deepEqual(await read(opened.owner, table), [], `${table} starts empty`);
    }

    // 0.14.5 serving: the vault reads its members' grants, and the app appends, a write and a read, after its entries.
    assert.deepEqual((await readGrants(opened.vault, { principal: 'token:deploy' })).map(({ role, projectId }) => [role, projectId]), [['viewer', '11111111-1111-4111-8111-111111111111']]);
    for (const action of ['project.update', 'secret.read']) {
      await opened.app.transaction((tx) => appendAudit(tx, chainKey, [{ actorType: 'system', actorId: 'test', action, decision: 'allow' }]));
    }
    const log = await read(opened.owner, 'audit_log');
    assert.deepEqual(log.map((entry) => Number(entry.seq)), [0, 1, 2, 3], 'the appends carry on from 0.14.5\'s');
    for (const [index, entry] of log.entries()) {
      if (index > 0) assert.equal(entry.prev_hash, log[index - 1]!.hash, `entry ${index} links to the one before`);
    }
  } finally {
    await opened.close();
  }
});
