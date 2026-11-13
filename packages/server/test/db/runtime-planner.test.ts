import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { postgresClient, type PostgresClient } from '@coffre/db/connect';
import { clearPlannerSettings, holdRuntimeTimeouts, RUNTIME_SETTINGS } from '@coffre/db/migrate';

import { TEST_OWNER_DATABASE_URL } from './connections.ts';

/** The URL of the suite's database, as another login. */
function asLogin(login: string, password: string): string {
  const url = new URL(TEST_OWNER_DATABASE_URL);
  url.username = login;
  url.password = password;
  return url.href;
}

/** What a fresh connection of `login` runs with, and where each setting comes from (`user`: the role's own). */
async function plannerOf(login: string, password: string): Promise<Record<string, string>> {
  const client = postgresClient(asLogin(login, password), { max: 1 });
  try {
    const rows = await client.unsafe<{ name: string; setting: string; source: string }[]>(
      "SELECT name, setting, source FROM pg_settings WHERE name IN ('jit', 'plan_cache_mode') ORDER BY name",
    );
    return Object.fromEntries(rows.map((row) => [row.name, `${row.setting} (${row.source})`]));
  } finally {
    await client.end();
  }
}

/** Roles of their own, never the suite's: roles are the cluster's, and tests of other files run at once. */
async function withRoles(work: (owner: PostgresClient, roles: string[], migrator: { login: string; password: string }) => Promise<void>) {
  const suffix = randomBytes(4).toString('hex');
  const names = ['a', 'b', 'c'].map((letter) => `w_plan_${letter}_${suffix}`);
  const migrator = { login: `w_plan_migrator_${suffix}`, password: 'local-migrator-only' };
  const owner = postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 });
  try {
    for (const name of names) await owner.unsafe(`CREATE ROLE ${name} LOGIN PASSWORD 'local-plan-only'`);
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
  "0.15.0's planner settings are cleared from a login once, however they are spelled and however many migrations of other databases race to, and an administrator's own stay, generic plans on a login other than the hot one included",
  async () => {
    await withRoles(async (owner, [hot, spelled, own]) => {
      // As 0.15.0's migrations left the hot login; `false` as an administrator may have spelled it, beside generic plans of its own; and settings coffre never made.
      await owner.unsafe(`ALTER ROLE ${hot!} SET jit = off`);
      await owner.unsafe(`ALTER ROLE ${hot!} SET plan_cache_mode = force_generic_plan`);
      await owner.unsafe(`ALTER ROLE ${hot!} SET statement_timeout = '30s'`);
      await owner.unsafe(`ALTER ROLE ${spelled!} SET jit = false`);
      await owner.unsafe(`ALTER ROLE ${spelled!} SET plan_cache_mode = force_generic_plan`);
      await owner.unsafe(`ALTER ROLE ${own!} SET jit = on`);
      await owner.unsafe(`ALTER ROLE ${own!} SET plan_cache_mode = force_custom_plan`);
      const racers = Array.from({ length: 8 }, () => postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 }));
      try {
        await Promise.all(racers.map((racer) => clearPlannerSettings(racer, { logins: [hot!, spelled!, own!], hot: hot! })));
      } finally {
        await Promise.all(racers.map((racer) => racer.end()));
      }
      assert.deepEqual(await setting(owner, hot!), ['statement_timeout=30s']);
      assert.deepEqual(await setting(owner, spelled!), ['plan_cache_mode=force_generic_plan']);
      assert.deepEqual((await setting(owner, own!)).sort(), ['jit=on', 'plan_cache_mode=force_custom_plan']);
      // A fresh connection of the cleared login takes the server's own: none of the role's.
      const planner = await plannerOf(hot!, 'local-plan-only');
      assert.ok(Object.values(planner).every((value) => !value.endsWith('(user)')), JSON.stringify(planner));
    });
  },
);

test(
  'a login that only migrates, and may not alter the roles, leaves their settings and fails nothing',
  async () => {
    await withRoles(async (owner, [hot], { login, password }) => {
      await owner.unsafe(`ALTER ROLE ${hot!} SET jit = off`);
      await owner.unsafe(`ALTER ROLE ${hot!} SET plan_cache_mode = force_generic_plan`);
      const migrator = postgresClient(asLogin(login, password), { max: 1 });
      try {
        await clearPlannerSettings(migrator, { logins: [hot!], hot: hot! });
      } finally {
        await migrator.end();
      }
      assert.deepEqual((await setting(owner, hot!)).sort(), ['jit=off', 'plan_cache_mode=force_generic_plan']);
    });
  },
);

test(
  "the runtime logins get coffre's statement timeout once, however many migrations race to; one coffre gave before moves to today's, an administrator's own stays, and the login's idle sessions here end",
  async () => {
    await withRoles(async (owner, [none, earlier, own]) => {
      await owner.unsafe(`ALTER ROLE ${earlier!} SET statement_timeout = '45s'`);
      await owner.unsafe(`ALTER ROLE ${own!} SET statement_timeout = '30s'`);
      // An idle session of the login given it: it logged in without it, so it is ended, and its pool logs in again.
      const idle = postgresClient(asLogin(none!, 'local-plan-only'), { max: 1 });
      try {
        const [{ pid }] = await idle.unsafe<[{ pid: number }]>('SELECT pg_backend_pid() AS pid');
        const racers = Array.from({ length: 8 }, () => postgresClient(TEST_OWNER_DATABASE_URL, { max: 1 }));
        try {
          const untimed = await Promise.all(racers.map((racer) => holdRuntimeTimeouts(racer, { logins: [none!, earlier!, own!], given: ['45s'] })));
          assert.deepEqual(untimed, racers.map(() => []));
        } finally {
          await Promise.all(racers.map((racer) => racer.end()));
        }
        const today = `statement_timeout=${RUNTIME_SETTINGS.statement_timeout}`;
        assert.deepEqual(await setting(owner, none!), [today]);
        assert.deepEqual(await setting(owner, earlier!), [today]);
        assert.deepEqual(await setting(owner, own!), ['statement_timeout=30s']);
        for (let waited = 0; ; waited += 50) {
          const [left] = await owner.unsafe<[{ n: number }]>('SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid = $1', [pid]);
          if (left.n === 0) break;
          assert.ok(waited < 5_000, 'the idle session was ended');
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
        const [again] = await idle.unsafe<[{ ms: string; source: string }]>("SELECT setting AS ms, source FROM pg_settings WHERE name = 'statement_timeout'");
        assert.deepEqual(again, { ms: String(Number.parseInt(RUNTIME_SETTINGS.statement_timeout, 10) * 1000), source: 'user' });
      } finally {
        await idle.end();
      }
    });
  },
);

test(
  'a login that may not alter the runtime logins leaves them without the timeout, fails nothing, and names them',
  async () => {
    await withRoles(async (owner, [none, earlier], { login, password }) => {
      await owner.unsafe(`ALTER ROLE ${earlier!} SET statement_timeout = '45s'`);
      const migrator = postgresClient(asLogin(login, password), { max: 1 });
      try {
        assert.deepEqual(await holdRuntimeTimeouts(migrator, { logins: [none!, earlier!], given: ['45s'] }), [none!, earlier!]);
      } finally {
        await migrator.end();
      }
      assert.deepEqual(await setting(owner, none!), []);
      assert.deepEqual(await setting(owner, earlier!), ['statement_timeout=45s']);
    });
  },
);

test(
  "a login that may alter the runtime logins but not signal their sessions gives them the timeout and leaves their idle sessions as they are",
  async () => {
    await withRoles(async (owner, [none], { login, password }) => {
      // As `coffre setup`'s administrator on a managed Postgres may be: CREATEROLE and ADMIN, without the login's privileges.
      await owner.unsafe(`ALTER ROLE ${login} CREATEROLE`);
      await owner.unsafe(`GRANT ${none!} TO ${login} WITH ADMIN OPTION, INHERIT FALSE, SET FALSE`);
      const idle = postgresClient(asLogin(none!, 'local-plan-only'), { max: 1 });
      const migrator = postgresClient(asLogin(login, password), { max: 1 });
      try {
        const [before] = await idle.unsafe<[{ pid: number }]>('SELECT pg_backend_pid() AS pid');
        assert.deepEqual(await holdRuntimeTimeouts(migrator, { logins: [none!], given: [] }), []);
        assert.deepEqual(await setting(owner, none!), [`statement_timeout=${RUNTIME_SETTINGS.statement_timeout}`]);
        const [after] = await idle.unsafe<[{ pid: number }]>('SELECT pg_backend_pid() AS pid');
        assert.equal(after.pid, before.pid);
      } finally {
        await Promise.all([idle.end(), migrator.end()]);
      }
    });
  },
);
