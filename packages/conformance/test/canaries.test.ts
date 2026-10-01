import test from 'node:test';
import assert from 'node:assert/strict';
import { Browser } from '../src/browser.ts';
import { canaryScan } from '../src/checks/canaries.ts';
import { canary, type People } from '../src/checks/people.ts';
import { postgres, using } from '../src/database.ts';
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
    await sql.exec('CREATE TABLE conformance_canary_probe (value bytea)');
    try {
      await canaryScan(deployment, people, { KEY: value });
      await sql.query('INSERT INTO conformance_canary_probe VALUES ($1)', [Buffer.from(value)]);
      await assert.rejects(canaryScan(deployment, people, { KEY: value }), /a value was found outside a reveal/);
      await sql.exec('DELETE FROM conformance_canary_probe');
      await canaryScan(deployment, people, { KEY: value });
    } finally {
      await sql.exec('DROP TABLE conformance_canary_probe');
    }
  });
});
