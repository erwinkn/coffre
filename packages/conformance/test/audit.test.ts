import assert from 'node:assert/strict';
import test from 'node:test';

import { writesAgree } from '../src/checks/audit.ts';
import type { Deployment } from '../src/harness.ts';
import { scratch } from './scratch.ts';

// A deployment's tables, as much of them as `writesAgree` reads, holding one stored version, `extra` beside it.
async function deploymentWith(t: test.TestContext, extra = ''): Promise<Deployment> {
  const database = await scratch(t);
  const sql = await database();
  await sql.exec(`
    CREATE TABLE projects (id TEXT, slug TEXT);
    CREATE TABLE environments (id TEXT, project_id TEXT, slug TEXT);
    CREATE TABLE secrets (id TEXT, project_id TEXT, environment_id TEXT, key TEXT);
    CREATE TABLE secret_versions (id TEXT, secret_id TEXT, version INTEGER);
    CREATE TABLE audit_log (seq INTEGER, author TEXT, action TEXT, decision TEXT, actor TEXT, metadata TEXT, project_id TEXT, environment_id TEXT, secret_id TEXT, request_id TEXT, operation_id TEXT, related_seq INTEGER);
    CREATE TABLE log_changes (payload TEXT);
    INSERT INTO projects VALUES ('project', 'conformance');
    INSERT INTO environments VALUES ('env', 'project', 'dev');
    INSERT INTO secrets VALUES ('secret', 'project', 'env', 'API_KEY');
    INSERT INTO secret_versions VALUES ('version', 'secret', 1);
    ${extra}
  `);
  await sql.close();
  return { database } as Deployment;
}

// The key's change in 0.15's log a write down the two-trip path leaves, as the vault makes it (packages/vault/src/changes.ts).
const change = (request: object) => `INSERT INTO log_changes VALUES ('${JSON.stringify({ digest: 'd', inputs: 'i', op: 'secret.write', ref: { id: 'secret' }, version: 'version', request })}');`;
const request = { operationId: '6f0b3c64-0000-4000-8000-000000000001', requestId: '6f0b3c64-0000-4000-8000-000000000002' };

test('a stored version without a write entry fails conformance', async (t) => {
  await assert.rejects(writesAgree(await deploymentWith(t)), /a stored version has no unique write record/);
});

test("a stored version recorded by its key's change in 0.15's log alone, naming its request, conforms; with an app write as well, or naming no request, it does not (T179, 0.16.0)", async (t) => {
  assert.match(await writesAgree(await deploymentWith(t, change(request))), /\(1 of them\) one change of 0\.15's log/);
  // 0.14's pair for the same version, the vault's `key.wrap` and the app's `secret.write` naming it: alone it conforms, beside the change not.
  const pair = `
    INSERT INTO audit_log VALUES (1, 'vault', 'key.wrap', 'allow', 'user:ada', '{"secretId":"secret","version":1,"subject":"conformance/dev/API_KEY"}', 'project', 'env', 'secret', 'r', 'o', NULL);
    INSERT INTO audit_log VALUES (2, 'app', 'secret.write', 'allow', 'user:ada', '{"version":1,"key":"API_KEY"}', 'project', 'env', 'secret', 'r', 'o', 1);`;
  assert.match(await writesAgree(await deploymentWith(t, pair)), /\(0 of them\)/);
  await assert.rejects(writesAgree(await deploymentWith(t, change(request) + pair)), /no unique write record/);
  await assert.rejects(writesAgree(await deploymentWith(t, change({}))), /names no operation or request/);
});
