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
    CREATE TABLE log_changes (actor TEXT, payload TEXT);
    INSERT INTO projects VALUES ('project', 'conformance');
    INSERT INTO environments VALUES ('env', 'project', 'dev');
    INSERT INTO secrets VALUES ('secret', 'project', 'env', 'API_KEY');
    INSERT INTO secret_versions VALUES ('version', 'secret', 1);
    ${extra}
  `);
  await sql.close();
  return { database } as Deployment;
}

// The key's change a write down the two-trip path leaves, as the vault makes it (packages/vault/src/changes.ts).
const change = (request: object) => `INSERT INTO log_changes VALUES ('user:ada', '${JSON.stringify({ digest: 'd', inputs: 'i', op: 'secret.write', ref: { id: 'secret' }, version: 'version', request })}');`;
const request = { operationId: '6f0b3c64-0000-4000-8000-000000000001', requestId: '6f0b3c64-0000-4000-8000-000000000002' };
// The key's change an app write leaves, carrying its entry, and the vault's `key.wrap` it names.
const carried = `INSERT INTO log_changes VALUES ('user:ada', '${JSON.stringify({
  op: 'secret.write', ref: { id: 'secret' }, version: 'version',
  reported: { action: 'secret.write', allowed: true, author: 'app', ...request, detail: { key: 'API_KEY', version: 1 }, places: { projectId: 'project', environmentId: 'env', secretId: 'secret' } },
})}');`;
const wrap = `INSERT INTO audit_log VALUES (1, 'vault', 'key.wrap', 'allow', 'user:ada', '{"secretId":"secret","version":1,"subject":"conformance/dev/API_KEY"}', 'project', 'env', NULL, '${request.requestId}', '${request.operationId}', NULL);`;

test('a stored version without a write record fails conformance', async (t) => {
  await assert.rejects(writesAgree(await deploymentWith(t)), /a stored version has no unique write record/);
});

test('a stored version the vault decided, naming its request, conforms; naming none, or beside an app write, it does not', async (t) => {
  assert.match(await writesAgree(await deploymentWith(t, change(request))), /and 1 the vault decided/);
  await assert.rejects(writesAgree(await deploymentWith(t, change({}))), /names no operation or request/);
  await assert.rejects(writesAgree(await deploymentWith(t, change(request) + carried + wrap)), /no unique write record/);
});

test("a stored version whose change carries the app's write conforms with the vault's seal in its operation, and not without it", async (t) => {
  assert.match(await writesAgree(await deploymentWith(t, carried + wrap)), /1 carrying the app's write/);
  await assert.rejects(writesAgree(await deploymentWith(t, carried)), /names no key\.wrap/);
  await assert.rejects(writesAgree(await deploymentWith(t, carried + wrap.replace(request.operationId, 'other'))), /names no key\.wrap/);
});

test("an app write in audit_log fails conformance, whatever else records the version", async (t) => {
  const old = `INSERT INTO audit_log VALUES (2, 'app', 'secret.write', 'allow', 'user:ada', '{"version":1,"key":"API_KEY"}', 'project', 'env', 'secret', 'r', 'o', 1);`;
  await assert.rejects(writesAgree(await deploymentWith(t, carried + wrap + old)), /the app logged an allowed secret\.write in audit_log/);
});
