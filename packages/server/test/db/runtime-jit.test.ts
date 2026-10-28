import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { postgresClient, type PostgresClient } from '@coffre/db/connect';
import { turnJitOff } from '@coffre/db/migrate';

import { TEST_OWNER_DATABASE_URL } from './connections.ts';
import { postgresOnly } from './engine.ts';

/** The URL of the suite's database, as another login. */
function asLogin(login: string, password: string): string {
  const url = new URL(TEST_OWNER_DATABASE_URL);
  url.username = login;
  url.password = password;
  return url.href;
}

async function jitOf(login: string, password: string): Promise<string> {
  const client = postgresClient(asLogin(login, password), { max: 1 });
  try {
    const [row] = await client.unsafe<{ jit: string }[]>("SELECT current_setting('jit') AS jit");
    return row!.jit;
  } finally {
    await client.end();
  }
}

/** Roles of their own, never the suite's: roles are the cluster's, and tests of other files run at once. */
async function withRoles(work: (owner: PostgresClient, roles: string[], migrator: { login: string; password: string }) => Promise<void>) {
  const suffix = randomBytes(4).toString('hex');
  const names = ['a', 'b', 'c'].map((letter) => `w_jit_${letter}_${suffix}`);
  const migrator = { login: `w_jit_migrator_${suffix}`, password: 'local-migrator-only' };
  const owner = postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 });
  try {
    for (const name of names) await owner.unsafe(`CREATE ROLE ${name} LOGIN PASSWORD 'local-jit-only'`);
    // Migrates, and administers none of them.
    await owner.unsafe(`CREATE ROLE ${migrator.login} LOGIN PASSWORD '${migrator.password}'`);
    await work(owner, names, migrator);
  } finally {
    for (const name of [...names, migrator.login]) await owner.unsafe(`DROP ROLE IF EXISTS ${name}`);
    await owner.end();
  }
}

const setting = async (owner: PostgresClient, role: string) =>
  (await owner.unsafe<{ setconfig: string[] }[]>(
    "SELECT setconfig FROM pg_db_role_setting WHERE setrole = $1::regrole AND setdatabase = 0",
    [role],
  )).flatMap((row) => row.setconfig);

test(
  'jit is turned off for a login once, however many migrations of other databases race to',
  postgresOnly('SQLite has no JIT'),
  async () => {
    await withRoles(async (owner, [fresh, held]) => {
      // A login with no setting yet (a row to insert) and one with another (a row to update): each change of the same row fails the second.
      await owner.unsafe(`ALTER ROLE ${held!} SET statement_timeout = '30s'`);
      const racers = Array.from({ length: 8 }, () => postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 }));
      try {
        await Promise.all(racers.map((racer) => turnJitOff(racer, [fresh!, held!])));
      } finally {
        await Promise.all(racers.map((racer) => racer.end()));
      }
      assert.deepEqual(await setting(owner, fresh!), ['jit=off']);
      assert.deepEqual((await setting(owner, held!)).sort(), ['jit=off', 'statement_timeout=30s']);
      assert.equal(await jitOf(fresh!, 'local-jit-only'), 'off');
    });
  },
);

test(
  'a login that only migrates is spared when jit is off already, however it is spelled, and told what to run when it is not',
  postgresOnly('SQLite has no JIT'),
  async () => {
    await withRoles(async (owner, [spelled, unset], { login, password }) => {
      await owner.unsafe(`ALTER ROLE ${spelled!} SET jit = false`);
      const migrator = postgresClient(asLogin(login, password), { max: 1 });
      try {
        await turnJitOff(migrator, [spelled!]);
        assert.deepEqual(await setting(owner, spelled!), ['jit=false']);
        await assert.rejects(
          turnJitOff(migrator, [unset!]),
          (error: Error) => error.message.includes(`have a login with CREATEROLE and ADMIN on it run ALTER ROLE ${unset!} SET jit = off`),
        );
      } finally {
        await migrator.end();
      }
    });
  },
);

test(
  "a login's own jit setting for this database, which would outrank the server-wide one, is refused, and a fresh connection runs with jit off once it is gone",
  postgresOnly('SQLite has no JIT'),
  async () => {
    await withRoles(async (owner, [role]) => {
      const name = role!;
      await owner.unsafe(`DO $$ BEGIN EXECUTE format('ALTER ROLE ${name} IN DATABASE %I SET jit = on', current_database()); END $$`);
      await assert.rejects(turnJitOff(owner, [name]), (error: Error) => error.message.includes(`ALTER ROLE ${name} IN DATABASE`) && error.message.includes('RESET jit'));
      // The server-wide setting alone, as a clone of an unprepared database would leave it, does not reach a connection.
      await owner.unsafe(`ALTER ROLE ${name} SET jit = off`);
      assert.equal(await jitOf(name, 'local-jit-only'), 'on');
      await owner.unsafe(`DO $$ BEGIN EXECUTE format('ALTER ROLE ${name} IN DATABASE %I RESET jit', current_database()); END $$`);
      await turnJitOff(owner, [name]);
      assert.equal(await jitOf(name, 'local-jit-only'), 'off');
    });
  },
);
