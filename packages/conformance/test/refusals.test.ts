import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createClient } from '@coffre/client';

import { bulkLimit } from '../src/checks/access.ts';
import { noAuditNoValue } from '../src/checks/audit.ts';
import { DEV, type People } from '../src/checks/people.ts';
import { sqlite, using } from '../src/database.ts';
import type { Deployment } from '../src/harness.ts';

for (const [error, reason, passes] of [
  ['forbidden', 'no_grant', false],
  ['forbidden', 'bulk_limit', false],
  ['bulk_limit', 'no_grant', false],
  ['bulk_limit', 'bulk_limit', true],
] as const) {
  test(`bulk conformance ${passes ? 'accepts' : 'refuses'} ${error} with reason ${reason}`, async () => {
    const api = createClient({ url: 'http://conformance.test', transport: async (request) => {
      if (request.method === 'PATCH') return Response.json({});
      const path = await request.json() as { path: string };
      return path.path.endsWith('/BULK_0') ? Response.json({ values: { BULK_0: 'bulk-0' } })
        : Response.json({ error, message: 'refused', reason }, { status: 403 });
    } });
    const people = { admin: { api }, bulk: { api } } as People;
    if (passes) await bulkLimit(people, 1);
    else await assert.rejects(bulkLimit(people, 1), /not refused as bulk_limit/);
  });
}

async function auditFixture(t: test.TestContext, status: number, error: string, down = false) {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-refusal-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'app.db');
  await using(sqlite(file), (sql) => sql.exec('CREATE TABLE audit_log (action TEXT)'));
  let output = '';
  const deployment = { database: async () => sqlite(file), output: () => output } as Deployment;
  const admin = {
    browser: { send: async () => {
      if (!down) {
        await using(sqlite(file), async (sql) => {
          try {
            await sql.exec("INSERT INTO audit_log VALUES ('secret.read')");
          } catch (cause) {
            output += String(cause);
          }
        });
      }
      return Response.json({ error, message: 'something went wrong; see the server log' }, { status });
    } },
    api: { secrets: { reveal: async () => ({ values: { API_KEY: 'canary' } }) } },
  };
  return { deployment, people: { admin } as unknown as People, canaries: { [`${DEV}/API_KEY`]: 'canary' } };
}

for (const [status, error] of [[403, 'forbidden'], [503, 'unavailable']] as const) {
  test(`an audit refusal answered as ${status} ${error} fails conformance`, async (t) => {
    const { deployment, people, canaries } = await auditFixture(t, status, error);
    await assert.rejects(noAuditNoValue(deployment, people, canaries), /not fail as internal_error/);
  });
}

test('a dead vault does not count as a refused audit append', async (t) => {
  const { deployment, people, canaries } = await auditFixture(t, 500, 'internal_error', true);
  await assert.rejects(noAuditNoValue(deployment, people, canaries), /injected audit refusal/);
});

test('the exact audit failure with its injected cause passes conformance', async (t) => {
  const { deployment, people, canaries } = await auditFixture(t, 500, 'internal_error');
  await noAuditNoValue(deployment, people, canaries);
});
