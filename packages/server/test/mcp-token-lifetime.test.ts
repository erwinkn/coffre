// A deployment that holds service tokens to fewer days (`serviceTokenMaxDays`, R76): MCP asks the person to approve
// only a lifetime issuing then accepts, and refuses a longer one before anyone is asked.
import test from 'node:test';
import assert from 'node:assert/strict';

import { eq } from 'drizzle-orm';

import { clientFor, holdSomething } from './api-fixture.ts';
import { credentials, mcpApprovals } from '@coffre/db/schema';
import { browserFor, callRaw, connect, db, deps, DEV, fromPage, ROOT, route, useMcp } from './mcp-fixture.ts';

useMcp(
  async () => {
    const root = clientFor(deps, ROOT);
    await root.members.add('token:ci-deploy');
    await holdSomething(db.owner, deps.vault, 'token:ci-deploy', `user:${ROOT}`);
    await root.members.add(`user:${DEV}`, { role: 'admin' });
  },
  { approvalWaitMs: 50, passkeys: 'off', serviceTokenMaxDays: 30 },
);

test('a token one day past the deployment maximum is refused before anyone is asked; the maximum itself is approved and issued', async () => {
  const token = await connect(DEV, 'read manage-access');
  const refused = await callRaw(token, 'issue_service_token', { service: 'ci-deploy', label: 'deploys', expiresInDays: 31 });
  assert.equal(refused.body.result!.isError, true, JSON.stringify(refused.body));
  assert.match(refused.body.result!.content[0]!.text!, /between 1 and 30 days/);
  assert.equal((await db.owner.select().from(mcpApprovals)).length, 0);

  const asked = await callRaw(token, 'issue_service_token', { service: 'ci-deploy', label: 'deploys', expiresInDays: 30 });
  const { id } = asked.body.result!.structuredContent!.approval as { id: string };
  const headers = fromPage(await browserFor(DEV));
  const shown = (await (await route(`/api/approvals/${id}`, { headers })).json()) as { approval: { digest: string; basis: string | null } };
  const decided = await route(`/api/approvals/${id}`, {
    method: 'POST',
    headers: fromPage(await browserFor(DEV), { 'content-type': 'application/json' }),
    body: JSON.stringify({ approve: true, digest: shown.approval.digest, basis: shown.approval.basis }),
  });
  assert.equal(((await decided.json()) as { status: string }).status, 'approved');
  assert.equal((await db.owner.select().from(credentials).where(eq(credentials.principal, 'token:ci-deploy'))).length, 1);
});
