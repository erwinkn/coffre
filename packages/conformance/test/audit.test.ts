import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { writesAgree } from '../src/checks/audit.ts';
import { sqlite } from '../src/database.ts';
import type { Deployment } from '../src/harness.ts';

test('a stored version without a write entry fails conformance', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-write-test-'));
  const file = join(dir, 'coffre.db');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const sql = sqlite(file);
  await sql.exec(`
    CREATE TABLE projects (id TEXT, slug TEXT);
    CREATE TABLE environments (id TEXT, project_id TEXT, slug TEXT);
    CREATE TABLE secrets (id TEXT, project_id TEXT, environment_id TEXT, key TEXT);
    CREATE TABLE secret_versions (id TEXT, secret_id TEXT, version INTEGER);
    CREATE TABLE audit_log (seq INTEGER, author TEXT, action TEXT, decision TEXT);
    INSERT INTO projects VALUES ('project', 'conformance');
    INSERT INTO environments VALUES ('env', 'project', 'dev');
    INSERT INTO secrets VALUES ('secret', 'project', 'env', 'API_KEY');
    INSERT INTO secret_versions VALUES ('version', 'secret', 1);
  `);
  await sql.close();
  const deployment = { database: async () => sqlite(file) } as Deployment;
  await assert.rejects(writesAgree(deployment), /a stored version has no unique app write entry/);
});
