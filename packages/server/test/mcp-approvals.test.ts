// Changes through MCP (docs/design/mcp.md, section 7): nothing changes until
// the person approves on coffre's page, and Approve makes the change, once,
// as the person through the connection. A client that opens URLs is asked
// by elicitation and retries with its requestState; any other gets the link
// and calls again. Values come only from the page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { eq } from 'drizzle-orm';

import { clientFor } from './api-fixture.ts';
import { auditLog, mcpApprovals } from './db/tables.ts';
import { callRaw, client, connect, db, deps, DEV, entries, type Result, ROOT, route, sessionFor, useMcp } from './mcp-fixture.ts';

const OTHER = 'other@acme.example';
const SECRET = `value-${randomBytes(8).toString('hex')}`;

useMcp(
  async () => {
    const root = clientFor(deps, ROOT);
    await root.members.add(`user:${DEV}`);
    await root.members.add(`user:${OTHER}`);
    await root.projects.create('market', { name: 'Market' });
    await root.environments.create('market/prod', { name: 'Production' });
    await root.secrets.set('market/prod', { API_KEY: SECRET, OLD_KEY: `old-${SECRET}` });
    await root.access.set(`user:${DEV}`, { market: 'maintainer' });
    await root.access.set(`user:${OTHER}`, { 'market/prod': 'viewer' });
  },
  { approvalWaitMs: 50 },
);

/** The person, on coffre's page: what the approval shows them, as their session sees it. */
async function view(id: string, email = DEV) {
  const session = await sessionFor(email);
  const response = await route(`/api/approvals/${id}`, { headers: { authorization: `Bearer ${session}` } });
  return { status: response.status, body: (await response.json()) as { approval: { digest: string; status: string; summary: string; details: { label: string; value: string }[]; asks: unknown }; message?: string } };
}

/** The person's decision on that page, sent with the digest it showed. */
async function decide(id: string, approve: boolean, extra: { value?: string; digest?: string } = {}, email = DEV) {
  const shown = await view(id, email);
  const session = await sessionFor(email);
  const response = await route(`/api/approvals/${id}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${session}`, 'content-type': 'application/json' },
    body: JSON.stringify({ approve, digest: extra.digest ?? shown.body.approval.digest, ...(extra.value === undefined ? {} : { value: extra.value }) }),
  });
  return { status: response.status, body: (await response.json()) as { status: string; outcome: { text: string }; shown: { label: string; value: string }[]; message?: string } };
}

async function archived(key: string): Promise<boolean> {
  return (await clientFor(deps, ROOT).secrets.history(`market/prod/${key}`)).archived;
}

async function approvalRows() {
  return db.owner.select().from(mcpApprovals);
}

test('with URL elicitation, the official client is asked to open the page, and its retry reports the change the page made, once', async () => {
  const mcp = await client(await connect(DEV, 'browse write'), 'modern', { elicitsUrl: true });
  const prompts: { url: string; message: string }[] = [];
  mcp.setRequestHandler('elicitation/create', async (request) => {
    const params = request.params as { mode: string; url: string; message: string };
    prompts.push(params);
    // Asked: nothing has changed yet. The person opens the page, reads it and approves.
    assert.equal(await archived('OLD_KEY'), false);
    const id = params.url.split('/').at(-1)!;
    const shown = await view(id);
    assert.equal(shown.body.approval.summary, 'archive market/prod/OLD_KEY');
    assert.ok(shown.body.approval.details.some((line) => line.label === 'Now' && /version 1/.test(line.value)));
    assert.equal((await decide(id, true)).body.status, 'approved');
    return { action: 'accept' };
  });
  try {
    const result = (await mcp.callTool({ name: 'archive_secret', arguments: { secret: 'market/prod/OLD_KEY' } })) as Result;
    assert.equal(result.isError, undefined, JSON.stringify(result));
    assert.equal(result.structuredContent!.status, 'approved');
    assert.match(result.content[0]!.text!, /archived/);
  } finally {
    await mcp.close();
  }
  assert.equal(prompts.length, 1);
  assert.match(prompts[0]!.url, /^https:\/\/secrets\.acme\.example\/approvals\/[0-9a-f-]{36}$/);
  assert.equal(prompts[0]!.message, 'Approve on coffre: archive market/prod/OLD_KEY');
  assert.equal(await archived('OLD_KEY'), true);

  // The change's own entry is the person's, through the connection and the approval; the decision is logged too.
  const updates = await entries('secret.archive');
  assert.equal(updates.length, 1, 'made once');
  const via = updates[0]!.metadata.via as { clientName: string; approvalId: string };
  assert.equal(updates[0]!.actor, `user:${DEV}`);
  assert.equal(via.clientName, 'Claude Code');
  const [approval] = await approvalRows();
  assert.equal(via.approvalId, approval!.id);
  assert.notEqual(approval!.reportedAt, null, 'the client heard the outcome');
  assert.deepEqual((await entries('mcp.approve')).map((entry) => entry.metadata.tool), ['archive_secret']);
  assert.deepEqual((await entries('mcp.call')).map((entry) => [entry.decision, entry.metadata.approvalId]), [['allow', approval!.id]], 'the call is logged once, not each retry');
});

test('without URL elicitation, the result carries the link; nothing changes until the person approves, and calling again reports it', async () => {
  const token = await connect(DEV, 'browse write');
  const first = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal(first.status, 200);
  const result = first.body.result!;
  assert.equal(result.isError, undefined);
  const approval = result.structuredContent!.approval as { id: string; url: string };
  assert.equal(result.structuredContent!.status, 'pending');
  assert.match(result.content[0]!.text!, new RegExp(approval.url.replace(/[./]/g, '\\$&')));
  assert.equal(await archived('OLD_KEY'), false);

  // Asked again before the person decided: it waits a little, then says so with the same link.
  const waiting = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal((waiting.body.result!.structuredContent!.approval as { id: string }).id, approval.id, 'the same call rejoins its approval');
  assert.equal(waiting.body.result!.structuredContent!.status, 'pending');

  assert.equal((await decide(approval.id, true)).body.status, 'approved');
  assert.equal(await archived('OLD_KEY'), true, 'the page made the change');
  const after = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal(after.body.result!.structuredContent!.status, 'approved');

  // Heard once, the same call asks afresh.
  const again = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal(again.body.result!.structuredContent!.status, 'pending');
  assert.notEqual((again.body.result!.structuredContent!.approval as { id: string }).id, approval.id);
  assert.equal((await entries('secret.archive')).length, 1);
});

test('a requestState replayed with other arguments, or by another connection, is refused; decline cancels', async () => {
  const token = await connect(DEV, 'browse write');
  const capabilities = { elicitation: { url: {} } };
  const first = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' }, {}, capabilities);
  assert.equal(first.body.result!.resultType, 'input_required');
  const state = first.body.result!.requestState as string;

  const other = await callRaw(token, 'archive_secret', { secret: 'market/prod/API_KEY' }, { requestState: state, inputResponses: { approve: { action: 'accept' } } }, capabilities);
  assert.equal(other.body.error?.code, -32602);
  const elsewhere = await callRaw(await connect(DEV, 'browse write'), 'archive_secret', { secret: 'market/prod/OLD_KEY' }, { requestState: state }, capabilities);
  assert.equal(elsewhere.body.error?.code, -32602);
  const forged = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' }, { requestState: `${state.split('.')[0]}.AAAA` }, capabilities);
  assert.equal(forged.body.error?.code, -32602);

  // Pending: the retry waits, then asks for nothing new, with the state again.
  const held = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' }, { requestState: state }, capabilities);
  assert.equal(held.body.result!.resultType, 'input_required');
  assert.equal(held.body.result!.inputRequests, undefined);

  // Cancelled, the prompt was dismissed, or answered by a client that can ask no one: the link instead, still pending.
  const cancelled = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' }, { requestState: state, inputResponses: { approve: { action: 'cancel' } } }, capabilities);
  assert.equal(cancelled.body.result!.structuredContent!.status, 'pending');
  assert.match(String(cancelled.body.result!.structuredContent!.message), /Show the person the approval's url/);

  const declined = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' }, { requestState: state, inputResponses: { approve: { action: 'decline' } } }, capabilities);
  assert.equal(declined.body.result!.isError, true);
  assert.equal(declined.body.result!.structuredContent!.status, 'cancelled');
  assert.equal(await archived('OLD_KEY'), false);
  assert.equal((await decide((first.body.result!.inputRequests as { approve: { params: { url: string } } }).approve.params.url.split('/').at(-1)!, true)).status, 409);
});

test('only its person decides an approval, with the digest they were shown; a denial changes nothing', async () => {
  const token = await connect(DEV, 'browse write');
  const id = ((await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' })).body.result!.structuredContent!.approval as { id: string }).id;

  const theirs = await view(id, OTHER);
  assert.equal(theirs.status, 403);
  assert.match(theirs.body.message!, /someone else/);
  assert.equal((await decide(id, true, { digest: '0'.repeat(64) })).status, 409, 'not the change the page showed');
  assert.deepEqual((await entries('mcp.view')).map((entry) => [entry.decision, entry.metadata.reason]), [['deny', 'not_yours']]);

  const denied = await decide(id, false);
  assert.equal(denied.body.status, 'denied');
  assert.equal((await decide(id, true)).status, 409, 'decided once');
  const reported = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal(reported.body.result!.isError, true);
  assert.equal(reported.body.result!.structuredContent!.status, 'denied');
  assert.equal(await archived('OLD_KEY'), false);
});

test('a value comes from the page only: the person types it, coffre writes it, and no result or row holds it', async () => {
  const token = await connect(DEV, 'browse write');
  const first = await callRaw(token, 'request_secret_value', { secret: 'market/prod/NEW_KEY', note: 'the Stripe key' });
  const id = (first.body.result!.structuredContent!.approval as { id: string }).id;
  const shown = await view(id);
  assert.deepEqual(shown.body.approval.asks, { value: { label: 'Value', note: 'It goes to coffre only: the app never sees it.' } });
  assert.ok(shown.body.approval.details.some((line) => line.value === 'the Stripe key'));
  assert.equal((await decide(id, true)).status, 400, 'Approve needs the value');
  const typed = `typed-${randomBytes(8).toString('hex')}`;
  assert.equal((await decide(id, true, { value: typed })).body.status, 'approved');
  const result = await callRaw(token, 'request_secret_value', { secret: 'market/prod/NEW_KEY', note: 'the Stripe key' });
  assert.equal(result.body.result!.structuredContent!.status, 'approved');

  const revealed = await clientFor(deps, ROOT).secrets.reveal('market/prod/NEW_KEY');
  assert.equal(JSON.stringify(revealed).includes(typed), true, 'written');
  assert.equal(JSON.stringify(first.body).includes(typed) || JSON.stringify(result.body).includes(typed), false);
  assert.equal(JSON.stringify(await approvalRows()).includes(typed), false, 'never stored with the approval');
  const log = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog);
  assert.equal(JSON.stringify(log).includes(typed), false);
});

test('a token issued through an approval is shown on the page, once, and never to the client', async () => {
  await clientFor(deps, ROOT).members.add('token:ci-deploy');
  await clientFor(deps, ROOT).members.add(`user:${DEV}`, { owner: true });
  const token = await connect(DEV, 'browse manage-access');
  const id = ((await callRaw(token, 'issue_service_token', { service: 'ci-deploy', label: 'deploys', expiresInDays: 30 })).body.result!.structuredContent!.approval as { id: string }).id;
  const decided = await decide(id, true);
  assert.equal(decided.body.status, 'approved', JSON.stringify(decided.body));
  const issued = decided.body.shown.find((line) => line.label === 'Token')!.value;
  assert.match(issued, /^coffre_svc_/);
  const result = await callRaw(token, 'issue_service_token', { service: 'ci-deploy', label: 'deploys', expiresInDays: 30 });
  assert.equal(result.body.result!.structuredContent!.status, 'approved');
  assert.equal(JSON.stringify(result.body).includes(issued), false);
  assert.equal(JSON.stringify(await approvalRows()).includes(issued), false);
});

test('a change the person could not make is refused before anyone is asked; without Write, the step-up starts', async () => {
  const viewer = await connect(OTHER, 'browse write');
  const refused = await callRaw(viewer, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal(refused.body.result!.isError, true);
  assert.match(refused.body.result!.content[0]!.text!, /secret\.archive/);
  assert.equal((await approvalRows()).length, 0);

  const browse = await connect(DEV);
  const stepUp = await callRaw(browse, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal(stepUp.status, 403);
  assert.equal((await approvalRows()).length, 0);
});

test('a 2025-era client makes changes through the link, as any client without URL elicitation (D62); a connection holds at most five waiting', async () => {
  const token = await connect(DEV, 'browse write');
  const legacy = await client(token, 'legacy');
  try {
    const asked = (await legacy.callTool({ name: 'archive_secret', arguments: { secret: 'market/prod/OLD_KEY' } })) as Result;
    assert.equal(asked.structuredContent!.status, 'pending', JSON.stringify(asked));
    assert.equal(await archived('OLD_KEY'), false);
    assert.equal((await decide((asked.structuredContent!.approval as { id: string }).id, true)).body.status, 'approved');
    const reported = (await legacy.callTool({ name: 'archive_secret', arguments: { secret: 'market/prod/OLD_KEY' } })) as Result;
    assert.equal(reported.structuredContent!.status, 'approved');
    assert.equal(await archived('OLD_KEY'), true);
  } finally {
    await legacy.close();
  }
  for (let index = 0; index < 5; index += 1) {
    const asked = await callRaw(token, 'create_environment', { environment: `market/env${index}`, name: `Env ${index}` });
    assert.equal(asked.body.result!.structuredContent!.status, 'pending');
  }
  const sixth = await callRaw(token, 'create_environment', { environment: 'market/env9', name: 'Env 9' });
  assert.equal(sixth.body.result!.isError, true);
  assert.match(sixth.body.result!.content[0]!.text!, /5 changes are waiting/);
});

test('a disconnected app’s approvals can no longer be decided', async () => {
  const token = await connect(DEV, 'browse write');
  const id = ((await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' })).body.result!.structuredContent!.approval as { id: string }).id;
  const [approval] = await db.owner.select().from(mcpApprovals).where(eq(mcpApprovals.id, id));
  const session = await sessionFor(DEV);
  const disconnected = await route(`/api/apps/${approval!.connectionId}`, { method: 'DELETE', headers: { authorization: `Bearer ${session}` } });
  assert.equal(disconnected.status, 200);
  assert.equal((await view(id)).status, 409);
  assert.equal(await archived('OLD_KEY'), false);
});
