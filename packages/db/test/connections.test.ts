// What coffre's logins may hold of the database's connections (docs/design/config.md, Q2, Q3), and the statement
// timeout `coffre migrate` gives the app's and the vault's logins (Q5).
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { sql } from 'drizzle-orm';

import { CALL_DEADLINE_MS, HOT_STATEMENT_TIMEOUT_MS, RUNTIME_STATEMENT_TIMEOUT_MS } from '@coffre/core/vault';

import { openDatabase, poolsAt } from '../src/connect.ts';
import {
  connectionsNeeded,
  databaseFacts,
  FEWEST,
  HELD_BACK,
  hyperdriveConnections,
  nodePools,
  share,
  TooFewConnections,
  tooFewConnections,
  unboundedStatements,
} from '../src/connections.ts';
import { createDatabase } from '../src/database.ts';
import { holdRuntimeTimeouts, RUNTIME_LOGINS, RUNTIME_SETTINGS } from '../src/migrate.ts';
import { postgresClient, quoteIdentifier, quoteLiteral } from '../src/postgres.ts';

const skip = process.env.COFFRE_TEST_ENGINE === 'sqlite' ? 'Postgres only' : false;
const PORT = process.env.COFFRE_POSTGRES_PORT ?? '55432';
const DATABASE = process.env.COFFRE_TEST_DATABASE ?? 'coffre_test';
const OWNER = `postgresql://coffre_owner:local-dev-only@127.0.0.1:${PORT}/${DATABASE}`;

test("each login's share at a small, the usual and a large database, and each pool on Node", () => {
  // PlanetScale's smallest, Postgres's default, and a large one: 3 reserved for superusers, Postgres's default.
  assert.equal(HELD_BACK, 4);
  assert.deepEqual(nodePools({ max: 25, reserved: 3 }), { app: 6, hot: 6, vault: 4, checkpointer: 2 });
  assert.deepEqual(nodePools({ max: 100, reserved: 3 }), { app: 31, hot: 31, vault: 29, checkpointer: 2 });
  assert.deepEqual(nodePools({ max: 500, reserved: 3 }), { app: 164, hot: 164, vault: 162, checkpointer: 2 });
  // On Workers, the vault's Hyperdrive config: its share, at most Free's 20.
  assert.deepEqual([25, 100, 500].map((max) => hyperdriveConnections({ max, reserved: 3 })), [6, 20, 20]);
});

test('below a share of FEWEST, no pools, and the refusal names the max_connections a database needs', () => {
  assert.equal(FEWEST, 5);
  assert.equal(connectionsNeeded(3), 3 * 5 + 4 + 3);
  assert.equal(share({ max: 22, reserved: 3 }), 5);
  assert.deepEqual(nodePools({ max: 22, reserved: 3 }), { app: 5, hot: 5, vault: 3, checkpointer: 2 });
  assert.equal(nodePools({ max: 21, reserved: 3 }), null);
  assert.match(new TooFewConnections({ max: 21, reserved: 3 }).message, /^coffre cannot start: the database's max_connections is 21, 3 of them reserved; coffre needs at least 5 for each of its three logins' pools, and keeps 4 for migrations and backups: raise max_connections to 22 or more/);
  assert.match(tooFewConnections({ max: 15, reserved: 3 }, { workers: true }), /Hyperdrive takes at least 5 for each of coffre's three configs, and setup keeps 4 .*raise max_connections to 22 or more/);
});

test("a login's statement timeout is warned of when none, or longer than a read call's deadline", () => {
  assert.equal(RUNTIME_STATEMENT_TIMEOUT_MS, CALL_DEADLINE_MS);
  assert.ok(HOT_STATEMENT_TIMEOUT_MS < RUNTIME_STATEMENT_TIMEOUT_MS, "the hot login's own stays the shorter");
  assert.equal(RUNTIME_SETTINGS.statement_timeout, '5s');
  assert.equal(unboundedStatements({ login: 'coffre_runtime', statementMs: 5_000 }), null);
  assert.equal(unboundedStatements({ login: 'coffre_runtime', statementMs: 2_000 }), null);
  assert.match(unboundedStatements({ login: 'coffre_runtime', statementMs: 0 })!, /^coffre_runtime runs with no statement_timeout: .* ALTER ROLE coffre_runtime SET statement_timeout = '5s'/);
  assert.match(unboundedStatements({ login: 'Odd"One', statementMs: 60_000 })!, /^Odd"One runs with a statement_timeout of 60000 ms: .* ALTER ROLE "Odd""One" SET/);
});

test('the database says what it lets in, and the login its statement timeout; a Node process sizes its pools to it', { skip }, async () => {
  const client = postgresClient(OWNER, { max: 1 });
  try {
    const db = createDatabase(client);
    const facts = await databaseFacts(db);
    const [expected] = await client.unsafe<{ max: number; reserved: number }[]>(
      "SELECT current_setting('max_connections')::int AS max, current_setting('superuser_reserved_connections')::int + current_setting('reserved_connections')::int AS reserved",
    );
    assert.deepEqual(facts, { connections: { max: expected!.max, reserved: expected!.reserved }, statementMs: 0, login: 'coffre_owner' });
    assert.deepEqual(await poolsAt(OWNER), nodePools(facts!.connections));
    await client.unsafe("SET statement_timeout = '1500ms'");
    assert.equal((await databaseFacts(db))!.statementMs, 1_500);
  } finally {
    await client.end();
  }
  assert.equal(await poolsAt('file:unused.db'), null);
});

/** A login of the test's own, so that setting its role changes no login another test file connects as: roles are the server's. */
async function withLogin(run: (login: string, url: string) => Promise<void>): Promise<void> {
  const login = `coffre_t_runtime_${randomBytes(4).toString('hex')}`;
  const password = 'local-test-only';
  const owner = postgresClient(OWNER, { max: 1 });
  await owner.unsafe(`CREATE ROLE ${quoteIdentifier(login)} LOGIN PASSWORD ${quoteLiteral(password)}`);
  try {
    await run(login, `postgresql://${login}:${password}@127.0.0.1:${PORT}/${DATABASE}`);
  } finally {
    await owner.unsafe(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = ${quoteLiteral(login)}`);
    await owner.unsafe(`DROP ROLE ${quoteIdentifier(login)}`);
    await owner.end();
  }
}

test("migrate gives a runtime login its statement timeout, server-wide, and a warmed pool takes it at its next query", { skip }, async () => {
  assert.deepEqual(RUNTIME_LOGINS, ['coffre_runtime', 'coffre_vault_runtime']);
  await withLogin(async (login, url) => {
    const pool = await openDatabase(url, { max: 2 });
    const owner = postgresClient(OWNER, { max: 1 });
    try {
      const timeout = async () => ((await pool.db.execute(sql`SELECT current_setting('statement_timeout') AS t`)) as unknown as [{ t: string }])[0].t;
      // Warmed: both of its connections open, idle, at the login's setting then.
      assert.deepEqual(await Promise.all([timeout(), timeout()]), ['0', '0']);
      assert.deepEqual(await holdRuntimeTimeouts(owner, [login]), []);
      const [role] = await owner.unsafe<{ setconfig: string[] }[]>('SELECT setconfig FROM pg_db_role_setting WHERE setrole = $1::regrole AND setdatabase = 0', [login]);
      assert.deepEqual(role!.setconfig, ['statement_timeout=5s']);
      // Its idle sessions were ended: the pool connects again, with the role's setting. A query sent on one as Postgres
      // ends it fails, once, as on a restart: the backend leaves pg_stat_activity a moment before its socket closes.
      await waitFor(async () => (await owner.unsafe(`SELECT 1 FROM pg_stat_activity WHERE usename = ${quoteLiteral(login)}`)).length === 0);
      let now: string | undefined;
      await waitFor(async () => {
        now = await timeout().catch((error: unknown) => {
          if ((error as { cause?: { code?: string } }).cause?.code !== 'CONNECTION_CLOSED') throw error;
          return undefined;
        });
        return now !== undefined;
      });
      assert.equal(now, '5s');
      assert.deepEqual(await Promise.all([timeout(), timeout()]), ['5s', '5s']);
      // What it found it keeps: an administrator's own, longer or shorter.
      await owner.unsafe(`ALTER ROLE ${quoteIdentifier(login)} SET statement_timeout = '30s'`);
      assert.deepEqual(await holdRuntimeTimeouts(owner, [login]), []);
      const [kept] = await owner.unsafe<{ setconfig: string[] }[]>('SELECT setconfig FROM pg_db_role_setting WHERE setrole = $1::regrole AND setdatabase = 0', [login]);
      assert.deepEqual(kept!.setconfig, ['statement_timeout=30s']);
      // A login that does not exist is no one's to set.
      assert.deepEqual(await holdRuntimeTimeouts(owner, [`${login}_none`]), []);
    } finally {
      await pool.close();
      await owner.end();
    }
  });
});

test("a login that may not alter the role leaves it without, and says which", { skip }, async () => {
  await withLogin(async (login) => {
    await withLogin(async (other, otherUrl) => {
      const client = postgresClient(otherUrl, { max: 1 });
      try {
        assert.deepEqual(await holdRuntimeTimeouts(client, [login]), [login]);
      } finally {
        await client.end();
      }
      const owner = postgresClient(OWNER, { max: 1 });
      try {
        const rows = await owner.unsafe('SELECT 1 FROM pg_db_role_setting WHERE setrole = $1::regrole', [login]);
        assert.equal(rows.length, 0, `${other} changed nothing`);
      } finally {
        await owner.end();
      }
    });
  });
});

async function waitFor(check: () => Promise<boolean>, within = 10_000): Promise<void> {
  const until = Date.now() + within;
  while (!(await check())) {
    if (Date.now() > until) throw new Error('not within 10 s');
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}
