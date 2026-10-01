import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createClient } from '@coffre/client';

import { Browser } from '../src/browser.ts';
import { forgedVaultEntry } from '../src/checks/audit.ts';
import type { People } from '../src/checks/people.ts';
import { sqlite, using } from '../src/database.ts';
import type { Deployment } from '../src/harness.ts';
import { Report } from '../src/report.ts';

async function fixture(t: test.TestContext) {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-storage-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'app.db');
  await using(sqlite(file), (sql) => sql.exec(`
    CREATE TABLE audit_log (seq INTEGER PRIMARY KEY, action TEXT, actor_id TEXT);
    INSERT INTO audit_log VALUES (0, 'secret.read', 'reader');
  `));
  const browser = new Browser('http://conformance.test');
  // This check needs only the verdict on an edited or deleted app row.
  const api = createClient({
    url: 'http://conformance.test',
    transport: async () => using(sqlite(file), async (sql) => {
      const [row] = await sql.query<{ actor_id: string }>('SELECT actor_id FROM audit_log WHERE seq = 0');
      return Response.json(row?.actor_id === 'reader'
        ? { ok: true, checkpoint: { seq: 0 } }
        : { ok: false, log: 'audit', failedAtSeq: 0 });
    }),
  });
  const person = { email: 'reader@conformance.example', member: 'user:reader@conformance.example', browser, api };
  const people: People = {
    admin: person, reader: person, bulk: person, stranger: person,
    leaver: { ...person, cli: api, cliToken: 'removed' }, service: { member: 'token:removed', token: 'removed', api },
  };
  const deployment = {
    origin: 'http://conformance.test', databaseFile: file, database: async () => sqlite(file),
    runtime: null, vaultRuntime: null, output: () => '',
  } as Deployment;
  return { deployment, people };
}

test('unavailable vault tampering is a failed conformance result', async (t) => {
  const { deployment, people } = await fixture(t);
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'error', () => {});
  const report = new Report();
  await report.check('vault tampering', { people }, ({ people }) => forgedVaultEntry(deployment, people));
  assert.deepEqual(report.failed, ['vault tampering']);
});
