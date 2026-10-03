import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TABLES } from '../src/checks/storage.ts';
import { Browser } from '../src/browser.ts';
import { canaryScan } from '../src/checks/canaries.ts';
import { canary, type People } from '../src/checks/people.ts';
import { postgres, sqlite, using } from '../src/database.ts';
import type { Deployment } from '../src/harness.ts';

test('the canary scan detects plaintext in a Postgres bytea column', {
  skip: (process.env.COFFRE_TEST_ENGINE ?? 'postgres') !== 'postgres' && 'Postgres bytea reader',
}, async (t) => {
  const url = `postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/${process.env.COFFRE_TEST_DATABASE ?? 'coffre_test'}`;
  // Only storage is under test; every HTTP surface answers without a value.
  const clean = async () => new Response('{}');
  t.mock.method(globalThis, 'fetch', clean);
  const browser = new Browser('http://conformance.test');
  const person = { email: 'reader@conformance.example', member: 'user:reader@conformance.example', browser, api: browser.client() };
  const people: People = {
    admin: person, reader: person, bulk: person, stranger: person,
    leaver: { ...person, cli: person.api, cliToken: 'removed' }, service: { member: 'token:removed', token: 'removed', api: person.api },
  };
  const deployment = {
    origin: 'http://conformance.test', database: () => postgres(url), databaseFile: null,
    output: () => '',
  } as Deployment;
  const value = canary();
  await using(postgres(url), async (sql) => {
    await sql.exec('CREATE TABLE conformance_leak_probe (value bytea)');
    try {
      await canaryScan(deployment, people, { KEY: value });
      await sql.query('INSERT INTO conformance_leak_probe VALUES ($1)', [Buffer.from(value)]);
      await assert.rejects(canaryScan(deployment, people, { KEY: value }), /a value was found outside a reveal/);
      await sql.exec('DELETE FROM conformance_leak_probe');
      await canaryScan(deployment, people, { KEY: value });
    } finally {
      await sql.exec('DROP TABLE conformance_leak_probe');
    }
  });
});

test('a missing shared table fails the canary scan instead of passing an incomplete inspection', async (t) => {
  const { deployment, people, sql } = await sqliteFixture(t);
  await sql.exec('DROP TABLE vault_members');
  await assert.rejects(canaryScan(deployment, people, { KEY: canary() }), /shared tables could not be inspected/);
});

test('the binary positive control fails a scanner whose driver hides bytes', async (t) => {
  const { deployment, people, sql } = await sqliteFixture(t);
  const original = sql.query.bind(sql);
  t.mock.method(sql, 'query', async (statement: string, params?: unknown[]) => {
    const rows = await original(statement, params);
    return rows.map((row) => Object.fromEntries(Object.entries(row).map(([key, value]) =>
      [key, value instanceof Uint8Array ? Buffer.from(value).toString('hex') : value])));
  });
  await assert.rejects(canaryScan(deployment, people, { KEY: canary() }), /scanner missed its planted binary canary/);
});

async function sqliteFixture(t: test.TestContext) {
  const directory = mkdtempSync(join(tmpdir(), 'coffre-canary-test-'));
  const file = join(directory, 'coffre.db');
  const sql = sqlite(file);
  t.after(async () => { await sql.close(); rmSync(directory, { recursive: true, force: true }); });
  for (const table of TABLES) await sql.exec(`CREATE TABLE ${table} (id TEXT)`);
  t.mock.method(globalThis, 'fetch', async () => new Response('{}'));
  const browser = new Browser('http://conformance.test');
  const person = { email: 'reader@conformance.example', member: 'user:reader@conformance.example', browser, api: browser.client() };
  const people: People = {
    admin: person, reader: person, bulk: person, stranger: person,
    leaver: { ...person, cli: person.api, cliToken: 'removed' }, service: { member: 'token:removed', token: 'removed', api: person.api },
  };
  // The connection stays open so a test can change how the driver emits bytes.
  const deployment = {
    origin: 'http://conformance.test', database: async () => ({ ...sql, close: async () => {} }), databaseFile: file,
    output: () => '',
  } as Deployment;
  return { deployment, people, sql };
}


test('the HTTP scan waits for every reply and finds a leak in its final answer', async (t) => {
  const { deployment, people } = await sqliteFixture(t);
  const value = canary();
  let calls = 0;
  let active = 0;
  // 22 GET calls as eight callers, and 20 pages as six browser callers.
  const answers = 22 * 8 + 20 * 6;
  t.mock.method(globalThis, 'fetch', async () => {
    const call = ++calls;
    active++;
    await new Promise<void>((resolve) => setImmediate(resolve));
    active--;
    return new Response(call === answers ? value : '{}');
  });
  const database = deployment.database;
  t.mock.method(deployment, 'database', async () => {
    assert.equal(active, 0, 'HTTP replies must finish before storage inspection');
    assert.equal(calls, answers, 'every GET route and page must be read as every caller');
    return database();
  });
  await assert.rejects(canaryScan(deployment, people, { KEY: value }), /a value was found outside a reveal/);
  assert.equal(calls, answers);
});
