import assert from 'node:assert/strict';
import test from 'node:test';

import { writesAgree } from '../src/checks/audit.ts';
import type { Deployment } from '../src/harness.ts';
import { scratch } from './scratch.ts';

async function versions(t: test.TestContext, written: number[]): Promise<Deployment> {
  const database = await scratch(t);
  const sql = await database();
  const keys = written.map((version) => `{"key":"API_KEY","secret":"secret","version":${version}}`).join(',');
  await sql.exec(`
    CREATE TABLE projects (id TEXT, slug TEXT);
    CREATE TABLE secrets (id TEXT, project_id TEXT, key TEXT);
    CREATE TABLE secret_versions (id TEXT, secret_id TEXT, version INTEGER);
    CREATE TABLE log (seq BIGINT, body TEXT);
    CREATE TABLE log_pending (id BIGINT, body TEXT);
    INSERT INTO projects VALUES ('project', 'conformance');
    INSERT INTO secrets VALUES ('secret', 'project', 'API_KEY');
    INSERT INTO secret_versions VALUES ('v1', 'secret', 1), ('v2', 'secret', 2);
    INSERT INTO log VALUES (0, '{"action":"secret.write","detail":{"keys":[${keys}]}}');
    INSERT INTO log_pending VALUES (1, '{"action":"secret.write","detail":{"keys":[{"key":"API_KEY","secret":"secret","version":2}]}}');
  `);
  await sql.close();
  return { database } as Deployment;
}

test('every stored version with its one write entry, signed or waiting, passes conformance', async (t) => {
  await writesAgree(await versions(t, [1]));
});

test('a stored version without a write entry fails conformance', async (t) => {
  await assert.rejects(writesAgree(await versions(t, [])), /a stored version has no unique write entry/);
});

test('a stored version written twice fails conformance', async (t) => {
  await assert.rejects(writesAgree(await versions(t, [1, 2])), /a stored version has no unique write entry/);
});
