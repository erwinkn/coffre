// Changes through MCP (docs/design/mcp.md, section 7): nothing changes until
// the person approves on coffre's page, and Approve makes the change, once,
// as the person through the connection. A client that opens URLs is asked
// by elicitation and retries with its requestState; any other gets the link
// and calls again. Values come only from the page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { and, desc, eq } from 'drizzle-orm';

import { decideApproval } from '../src/db/queries.ts';
import { callDigest } from '../src/mcp/approvals.ts';
import { TOOL_BY_NAME } from '../src/mcp/tools.ts';
import { clientFor } from './api-fixture.ts';
import { auditLog, mcpApprovals, mcpConnections } from './db/tables.ts';
import { browserFor, callRaw, client, connect, db, deps, DEV, documents, entries, fetched, fromPage, type Result, ROOT, route, sessionFor, useMcp } from './mcp-fixture.ts';

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

type View = {
  digest: string;
  basis: string | null;
  status: string;
  summary: string;
  details: { label: string; value: string; note?: string }[];
  asks: unknown;
  reveals: boolean;
  ready: boolean;
  outcome: { text: string; error?: string } | null;
};

/** The person, on coffre's page: what the approval shows them, as their browser session sees it. */
async function view(id: string, email = DEV) {
  const response = await route(`/api/approvals/${id}`, { headers: fromPage(await browserFor(email)) });
  return { status: response.status, body: (await response.json()) as { approval: View; message?: string } };
}

/** The person's decision on that page, sent with the digest and basis it showed, or `shown` if given. */
async function decide(id: string, approve: boolean, extra: { value?: string; digest?: string; shown?: View } = {}, email = DEV) {
  const shown = extra.shown ?? (await view(id, email)).body.approval;
  const response = await route(`/api/approvals/${id}`, {
    method: 'POST',
    headers: fromPage(await browserFor(email), { 'content-type': 'application/json' }),
    body: JSON.stringify({ approve, digest: extra.digest ?? shown.digest, basis: shown.basis, ...(extra.value === undefined ? {} : { value: extra.value }) }),
  });
  return { status: response.status, body: (await response.json()) as { status: string; outcome: { text: string }; shown: { label: string; value: string }[]; message?: string } };
}

async function archived(key: string): Promise<boolean> {
  return (await clientFor(deps, ROOT).secrets.history(`market/prod/${key}`)).archived;
}

async function approvalRows() {
  return db.owner.select().from(mcpApprovals);
}

const idOf = (result: { body: { result?: { structuredContent?: Record<string, unknown> } } }) => (result.body.result!.structuredContent!.approval as { id: string }).id;

test('with URL elicitation, the official client is asked to open the page, and its retry reports the change the page made, once', async () => {
  const mcp = await client(await connect(DEV, 'read write'), 'modern', { elicitsUrl: true });
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
  const token = await connect(DEV, 'read write');
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
  const token = await connect(DEV, 'read write');
  const capabilities = { elicitation: { url: {} } };
  const first = await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' }, {}, capabilities);
  assert.equal(first.body.result!.resultType, 'input_required');
  const state = first.body.result!.requestState as string;

  const other = await callRaw(token, 'archive_secret', { secret: 'market/prod/API_KEY' }, { requestState: state, inputResponses: { approve: { action: 'accept' } } }, capabilities);
  assert.equal(other.body.error?.code, -32602);
  const elsewhere = await callRaw(await connect(DEV, 'read write'), 'archive_secret', { secret: 'market/prod/OLD_KEY' }, { requestState: state }, capabilities);
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
  // The decline is logged, as every other way an approval ends (I2).
  const [cancel] = await entries('mcp.cancel');
  assert.equal(cancel!.actor, `user:${DEV}`);
  assert.equal(cancel!.metadata.approvalId, (first.body.result!.inputRequests as { approve: { params: { url: string } } }).approve.params.url.split('/').at(-1));
  assert.equal((await decide((first.body.result!.inputRequests as { approve: { params: { url: string } } }).approve.params.url.split('/').at(-1)!, true)).status, 409);
});

test('only its person decides an approval, with the digest they were shown; a denial changes nothing', async () => {
  const token = await connect(DEV, 'read write');
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
  const token = await connect(DEV, 'read write');
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
  const token = await connect(DEV, 'read manage-access');
  const id = ((await callRaw(token, 'issue_service_token', { service: 'ci-deploy', label: 'deploys', expiresInDays: 30 })).body.result!.structuredContent!.approval as { id: string }).id;
  assert.ok((await view(id)).body.approval.details.some((line) => line.label === 'The app calls it' && line.value === 'deploys'), 'the label is the app’s');
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
  const viewer = await connect(OTHER, 'read write');
  const refused = await callRaw(viewer, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal(refused.body.result!.isError, true);
  assert.match(refused.body.result!.content[0]!.text!, /secret\.archive/);
  assert.equal((await approvalRows()).length, 0);

  const reading = await connect(DEV);
  const stepUp = await callRaw(reading, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  assert.equal(stepUp.status, 403);
  assert.equal((await approvalRows()).length, 0);
});

test('a 2025-era client makes changes through the link, as any client without URL elicitation (D62); a connection holds at most five waiting', async () => {
  const token = await connect(DEV, 'read write');
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
  const token = await connect(DEV, 'read write');
  const id = ((await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' })).body.result!.structuredContent!.approval as { id: string }).id;
  const [approval] = await db.owner.select().from(mcpApprovals).where(eq(mcpApprovals.id, id));
  const session = await sessionFor(DEV);
  const disconnected = await route(`/api/apps/${approval!.connectionId}`, { method: 'DELETE', headers: { authorization: `Bearer ${session}` } });
  assert.equal(disconnected.status, 200);
  assert.equal((await view(id)).status, 409);
  assert.equal(await archived('OLD_KEY'), false);
});

// --- W47's findings ----------------------------------------------------------

/** An approval as a call would have opened it, for a tool this instance cannot check a call of (trust bindings are off here). */
async function opened(email: string, tool: string, args: Record<string, unknown>): Promise<string> {
  const [connection] = await db.owner.select().from(mcpConnections).where(eq(mcpConnections.principal, `user:${email}`)).orderBy(desc(mcpConnections.createdAt)).limit(1);
  const id = randomUUID();
  await db.owner.insert(mcpApprovals).values({
    id, connectionId: connection!.id, tool, arguments: JSON.stringify(args), digest: Buffer.from(callDigest(tool, args), 'hex'),
    status: 'pending', createdAt: new Date(), expiresAt: new Date(Date.now() + 300_000),
  });
  return id;
}

test("trust_workload's page names each ID from GitHub or GitLab, says when it cannot, and shows the label as the app's (M1)", async () => {
  await clientFor(deps, ROOT).members.add(`user:${DEV}`, { owner: true });
  await connect(DEV, 'read manage-access');
  const notes = async (args: Record<string, unknown>) => {
    const { details } = (await view(await opened(DEV, 'trust_workload', { service: 'ci-deploy', ...args }))).body.approval;
    return Object.fromEntries(details.map((line) => [line.label, line.note ?? line.value]));
  };

  // The IDs a model picked, which name the attacker's project, whatever the label says.
  documents.set('https://gitlab.com/api/v4/projects/55123', { id: 55123, path_with_namespace: 'attacker/web', namespace: { id: 81234, full_path: 'attacker' } });
  const gitlab = await notes({ profile: 'gitlab', claims: { namespace_id: '81234', project_id: '55123', ref_type: 'branch', ref: 'main', pipeline_source: 'push' }, label: 'acme/web deploy' });
  assert.equal(gitlab.project_id, 'the GitLab project attacker/web');
  assert.equal(gitlab.namespace_id, 'the GitLab namespace attacker');
  assert.equal(gitlab['The app calls it'], 'acme/web deploy');
  assert.equal(gitlab.Label, undefined);

  // Private, unknown, or not answered: the person is told to check the ID.
  const unknown = await notes({ profile: 'gitlab', claims: { namespace_id: '77', project_id: '99', ref_type: 'branch', ref: 'main', pipeline_source: 'push' } });
  assert.equal(unknown.project_id, 'private or unknown: check this ID yourself');
  assert.equal(unknown.namespace_id, 'private or unknown: check this ID yourself');

  documents.set('https://api.github.com/repositories/41532', { id: 41532, full_name: 'acme/web', owner: { id: 9919, login: 'acme' } });
  const github = await notes({
    profile: 'github',
    claims: { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/web/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' },
  });
  assert.equal(github.repository_id, 'the GitHub repository acme/web');
  assert.equal(github.repository_owner_id, 'the GitHub account acme');
  documents.set('https://api.github.com/user/5150', { id: 5150, login: 'evil-org' });
  const organization = await notes({
    profile: 'github-reusable-organization',
    claims: { repository_owner_id: '5150', ref: 'refs/heads/main', event_name: 'push', job_workflow_ref: 'acme/ci/.github/workflows/deploy.yml@refs/heads/main', job_workflow_sha: 'a'.repeat(40) },
  });
  assert.equal(organization.repository_owner_id, 'the GitHub account evil-org');
});

test('an approved change that never answered is reported failed, its outcome unknown, never as nothing changed; the person is warned before approving it again (L2)', async () => {
  const token = await connect(DEV, 'read write');
  const call = () => callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' });
  const id = idOf(await call());
  const set = (values: Partial<typeof mcpApprovals.$inferInsert>) => db.owner.update(mcpApprovals).set(values).where(eq(mcpApprovals.id, id));

  // Approve committed, and its change has not answered yet.
  await set({ status: 'approved', decidedAt: new Date() });
  const making = (await call()).body.result!;
  assert.equal(making.structuredContent!.status, 'pending');
  assert.match(making.content[0]!.text!, /^The person approved this, and coffre is making the change/);
  assert.doesNotMatch(JSON.stringify(making), /[Nn]othing (has )?changed/);

  // A minute on, still no answer: the request died. Failed, outcome unknown, on every call that rejoins it.
  await set({ decidedAt: new Date(Date.now() - 2 * 60_000) });
  for (const _ of [1, 2]) {
    const unknown = (await call()).body.result!;
    assert.equal(unknown.isError, true);
    assert.equal(unknown.structuredContent!.status, 'failed');
    assert.equal(idOf({ body: { result: unknown } }), id);
    assert.match(unknown.content[0]!.text!, /does not know whether the change was made/);
    assert.doesNotMatch(JSON.stringify(unknown), /[Nn]othing (has )?changed/);
  }
  const page = (await view(id)).body.approval;
  assert.equal(page.status, 'failed');
  assert.equal(page.outcome?.error, 'unknown_outcome');

  // Past the time a call may rejoin it, the same call asks anew, and its page says the first may have been made.
  await set({ createdAt: new Date(Date.now() - 11 * 60_000) });
  const again = idOf(await call());
  assert.notEqual(again, id);
  assert.equal((await view(again)).body.approval.details[0]!.label, 'Asked before');
});

test('identical calls at once open one approval, logged once, and a burst gets no more than five waiting (L3)', async () => {
  const token = await connect(DEV, 'read write');
  const same = await Promise.all(Array.from({ length: 6 }, () => callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' })));
  assert.equal(new Set(same.map(idOf)).size, 1);
  assert.equal((await approvalRows()).length, 1);
  assert.equal((await entries('mcp.call')).length, 1);

  const burst = await Promise.all(Array.from({ length: 8 }, (_, index) => callRaw(token, 'create_environment', { environment: `market/burst${index}`, name: `Burst ${index}` })));
  assert.equal(burst.filter((result) => result.body.result!.structuredContent?.status === 'pending').length, 4);
  assert.equal(burst.filter((result) => /5 changes are waiting/.test(result.body.result!.content[0]!.text!)).length, 4);
  assert.equal((await approvalRows()).filter((row) => row.status === 'pending').length, 5);
});

test('Approve refuses a change whose page is stale: a version set, or a role changed, since it was shown (L4)', async () => {
  const token = await connect(DEV, 'read write');
  const id = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/API_KEY' }));
  const shown = (await view(id)).body.approval;
  assert.match(shown.basis!, /^[0-9a-f]{64}$/, 'a digest of version 1');
  await clientFor(deps, ROOT).secrets.set('market/prod', { API_KEY: `meanwhile-${SECRET}` });
  const stale = await decide(id, true, { value: 'typed', shown });
  assert.equal(stale.status, 409);
  assert.match(stale.body.message!, /changed since you opened it/);
  assert.equal((await clientFor(deps, ROOT).secrets.reveal('market/prod/API_KEY')).values.API_KEY, `meanwhile-${SECRET}`, 'version 2 stands');
  assert.deepEqual((await entries('mcp.approve')).map((entry) => [entry.decision, entry.metadata.reason]), [['deny', 'replaced']]);
  // Opened again, the page shows version 2, and Approve goes through.
  assert.equal((await decide(id, true, { value: 'typed' })).body.status, 'approved');

  const root = await connect(ROOT, 'read manage-access');
  const access = idOf(await callRaw(root, 'set_access', { member: `user:${OTHER}`, changes: { 'market/prod': 'auditor' } }));
  const page = (await view(access, ROOT)).body.approval;
  assert.ok(page.details.some((line) => line.label === 'market/prod' && line.value === 'viewer → auditor'));
  await clientFor(deps, ROOT).access.set(`user:${OTHER}`, { 'market/prod': 'developer' });
  assert.equal((await decide(access, true, { shown: page }, ROOT)).status, 409);
  assert.equal((await approvalRows()).find((row) => row.id === access)!.status, 'pending');
});

test('approvals asked too long ago to rejoin are not read again, so they never count toward the five (L5)', async () => {
  const token = await connect(DEV, 'read write');
  for (let index = 0; index < 5; index += 1) await callRaw(token, 'create_environment', { environment: `market/env${index}`, name: `Env ${index}` });
  // Rows that still say pending, as if their expiry were far off, but asked eleven minutes ago.
  await db.owner.update(mcpApprovals).set({ createdAt: new Date(Date.now() - 11 * 60_000), expiresAt: new Date(Date.now() + 60_000) });
  const sixth = await callRaw(token, 'create_environment', { environment: 'market/env9', name: 'Env 9' });
  assert.equal(sixth.body.result!.structuredContent!.status, 'pending');
});

test("only the browser's session decides an approval: the CLI's is refused, sent either way, and another site's page is refused before any read (I1, I3)", async () => {
  const token = await connect(DEV, 'read write');
  const id = idOf(await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' }));
  const { approval } = (await view(id)).body;
  const cli = await sessionFor(DEV);
  for (const headers of [{ authorization: `Bearer ${cli}` }, fromPage(cli)]) {
    const read = await route(`/api/approvals/${id}`, { headers });
    assert.equal(read.status, 403);
    assert.match(((await read.json()) as { message: string }).message, /signed in in your browser/);
    const decided = await route(`/api/approvals/${id}`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ approve: true, digest: approval.digest }) });
    assert.equal(decided.status, 403);
  }
  const crossSite = await route(`/api/approvals/${id}`, { headers: fromPage(await browserFor(DEV), { 'sec-fetch-site': 'cross-site' }) });
  assert.equal(crossSite.status, 403);
  assert.match(((await crossSite.json()) as { message: string }).message, /must come from coffre itself/);
  assert.equal(await archived('OLD_KEY'), false);
  assert.equal((await approvalRows())[0]!.status, 'pending');
});

test('the decision reads the approval and its connection again as it commits: expired or disconnected meanwhile, it is refused (I3)', async () => {
  const token = await connect(DEV, 'read write');
  const change = TOOL_BY_NAME.get('request_secret_value')!.change!;
  const replaces = change.replaces!;
  const during = async (id: string, meanwhile: () => Promise<unknown>) => {
    const shown = (await view(id)).body.approval;
    // Between the first checks and the decision's transaction: while Approve reads what the change replaces.
    change.replaces = async (api, args) => {
      await meanwhile();
      return replaces(api, args);
    };
    try {
      return await decide(id, true, { value: 'typed', shown });
    } finally {
      change.replaces = replaces;
    }
  };

  const expiring = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/NEW_KEY' }));
  const expired = await during(expiring, () => db.owner.update(mcpApprovals).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(mcpApprovals.id, expiring)));
  assert.equal(expired.status, 409);
  assert.match(expired.body.message!, /expired already/);

  const disconnecting = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/API_KEY' }));
  const [row] = await db.owner.select().from(mcpApprovals).where(and(eq(mcpApprovals.id, disconnecting)));
  const session = await sessionFor(DEV);
  const disconnected = await during(disconnecting, () => route(`/api/apps/${row!.connectionId}`, { method: 'DELETE', headers: { authorization: `Bearer ${session}` } }));
  assert.equal(disconnected.status, 409);
  assert.match(disconnected.body.message!, /disconnected/);
  assert.deepEqual((await entries('secret.write')).filter((entry) => entry.actor === `user:${DEV}`), [], 'nothing written');
});

test('a change the person could not make is refused before anyone is asked, for every tool: owners only, and access where they manage it (I3)', async () => {
  const dev = await connect(DEV, 'read write manage-access');
  const owners: [string, Record<string, unknown>][] = [
    ['create_project', { project: 'shop', name: 'Shop' }],
    ['admit_member', { member: 'user:new@acme.example' }],
    ['offboard_member', { member: `user:${OTHER}` }],
    ['issue_service_token', { service: 'ci-deploy', expiresInDays: 1 }],
    ['revoke_service_token', { service: 'ci-deploy', id: randomUUID() }],
    ['untrust_workload', { service: 'ci-deploy', id: randomUUID() }],
  ];
  for (const [tool, args] of owners) {
    const refused = (await callRaw(dev, tool, args)).body.result!;
    assert.equal(refused.isError, true, tool);
    assert.match(refused.content[0]!.text!, /only instance owners/, tool);
  }
  const viewer = await connect(OTHER, 'read write manage-access');
  const access = (await callRaw(viewer, 'set_access', { member: `user:${DEV}`, changes: { market: 'viewer' } })).body.result!;
  assert.match(access.content[0]!.text!, /you need grant\.manage on market/);
  const environment = (await callRaw(viewer, 'create_environment', { environment: 'market/stage', name: 'Stage' })).body.result!;
  assert.match(environment.content[0]!.text!, /you need environment\.manage on market/);
  assert.equal((await approvalRows()).length, 0);
});

// --- W49's findings on the fixes -----------------------------------------------

test("trust_workload names IDs only from github.com and gitlab.com: an issuer the app names is flagged, and never asked (M1)", async () => {
  await clientFor(deps, ROOT).members.add(`user:${DEV}`, { owner: true });
  await connect(DEV, 'read manage-access');
  // The attacker's own GitLab would name its project anything.
  documents.set('https://attacker.example/api/v4/projects/55123', { id: 55123, path_with_namespace: 'acme/web', namespace: { id: 81234, full_path: 'acme' } });
  const id = await opened(DEV, 'trust_workload', {
    service: 'ci-deploy', profile: 'gitlab', issuer: 'https://attacker.example',
    claims: { namespace_id: '81234', project_id: '55123', ref_type: 'branch', ref: 'main', pipeline_source: 'push' },
  });
  const { details } = (await view(id)).body.approval;
  const line = (label: string) => details.find((entry) => entry.label === label)!;
  assert.equal(line('project_id').note, "coffre can't check this host: check this ID yourself");
  assert.equal(line('namespace_id').note, "coffre can't check this host: check this ID yourself");
  assert.equal(line('Runs from').value, 'https://attacker.example');
  assert.match(line('Runs from').note!, /Not GitHub's or GitLab's own/);
  assert.equal((line('Runs from') as { warn?: boolean }).warn, true);
  assert.doesNotMatch(JSON.stringify(details), /acme\/web/);
  assert.deepEqual(fetched, [], 'the host the app named was never asked');
});

test('the basis Approve compares is the state the page showed, read once: a version set while the page was made refuses Approve (L4)', async () => {
  const token = await connect(DEV, 'read write');
  const id = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/API_KEY' }));
  const before = (await view(id)).body.approval.basis;
  const change = TOOL_BY_NAME.get('request_secret_value')!.change!;
  const preview = change.preview;
  // Version 2 lands after what it replaces was read, while the rest of the page is made.
  change.preview = async (...args) => {
    const details = await preview(...args);
    await clientFor(deps, ROOT).secrets.set('market/prod', { API_KEY: `meanwhile-${SECRET}` });
    return details;
  };
  let shown: View;
  try {
    shown = (await view(id)).body.approval;
  } finally {
    change.preview = preview;
  }
  assert.ok(shown.details.some((line) => line.label === 'Now' && /^version 1,/.test(line.value)));
  assert.equal(shown.basis, before, 'the basis of version 1, which the page showed');
  assert.equal((await decide(id, true, { value: 'typed', shown })).status, 409);
  assert.equal((await clientFor(deps, ROOT).secrets.reveal('market/prod/API_KEY')).values.API_KEY, `meanwhile-${SECRET}`);
});

test('a change made whose outcome is not stored reads as being made, then unknown, never failed, and is never reported (L2)', async () => {
  await clientFor(deps, ROOT).members.add('token:ci-deploy');
  await clientFor(deps, ROOT).members.add(`user:${DEV}`, { owner: true });
  const token = await connect(DEV, 'read manage-access');
  const call = () => callRaw(token, 'issue_service_token', { service: 'ci-deploy', expiresInDays: 30 });
  const id = idOf(await call());
  const change = TOOL_BY_NAME.get('issue_service_token')!.change!;
  const apply = change.apply;
  const update = deps.db.update;
  // The token is issued; then the database blips, once, as the outcome is written.
  change.apply = async (...args) => {
    const applied = await apply(...args);
    deps.db.update = (() => {
      deps.db.update = update;
      throw new Error('database blip');
    }) as typeof update;
    return applied;
  };
  let decided: Awaited<ReturnType<typeof decide>>;
  try {
    decided = await decide(id, true);
  } finally {
    change.apply = apply;
    deps.db.update = update;
  }
  assert.equal(decided.body.status, 'approved', 'the page hears it was made');
  assert.match(decided.body.shown.find((line) => line.label === 'Token')!.value, /^coffre_svc_/, 'and sees the token, once');
  const [row] = await db.owner.select().from(mcpApprovals).where(eq(mcpApprovals.id, id));
  assert.deepEqual([row!.status, row!.outcome], ['approved', null]);

  assert.match((await call()).body.result!.content[0]!.text!, /^The person approved this, and coffre is making the change/);
  await db.owner.update(mcpApprovals).set({ decidedAt: new Date(Date.now() - 2 * 60_000) }).where(eq(mcpApprovals.id, id));
  const unknown = (await call()).body.result!;
  assert.equal(unknown.structuredContent!.status, 'failed');
  assert.match(unknown.content[0]!.text!, /does not know whether the change was made/);
  assert.doesNotMatch(unknown.content[0]!.text!, /could not make the change/);
  const [after] = await db.owner.select().from(mcpApprovals).where(eq(mcpApprovals.id, id));
  assert.equal(after!.reportedAt, null, 'never heard as an end');
});

test("set_access takes every project, and an environment in each, from an owner, and places as the API reads them; from anyone else, they're refused up front (I3)", async () => {
  const root = await connect(ROOT, 'read manage-access');
  const asked = await callRaw(root, 'set_access', { member: `user:${OTHER}`, changes: { '*': 'viewer', '*/prod': 'developer', ' /market/prod/ ': 'auditor' } });
  assert.equal(asked.body.result!.structuredContent!.status, 'pending', JSON.stringify(asked.body.result));
  const { details } = (await view(idOf(asked), ROOT)).body.approval;
  assert.ok(details.some((line) => line.label === ' /market/prod/ ' && line.value === 'viewer → auditor'), 'the grant held there, found');
  assert.ok(details.some((line) => line.label === '*' && line.value === 'nothing → viewer'));

  const viewer = await connect(OTHER, 'read write manage-access');
  for (const place of ['*', '*/prod']) {
    const refused = (await callRaw(viewer, 'set_access', { member: `user:${DEV}`, changes: { [place]: 'viewer' } })).body.result!;
    assert.match(refused.content[0]!.text!, /only instance owners/, place);
  }
});

test("the decision moves an approval only while it is unexpired by the database's clock as the write runs (I3)", async () => {
  const token = await connect(DEV, 'read write');
  const id = idOf(await callRaw(token, 'archive_secret', { secret: 'market/prod/OLD_KEY' }));
  await db.owner.update(mcpApprovals).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(mcpApprovals.id, id));
  assert.equal(await decideApproval(deps.db, id, 'approved'), 0, 'expired: no write');
  await db.owner.update(mcpApprovals).set({ expiresAt: new Date(Date.now() + 60_000) }).where(eq(mcpApprovals.id, id));
  assert.equal(await decideApproval(deps.db, id, 'approved'), 1);
  assert.equal(await decideApproval(deps.db, id, 'approved'), 0, 'decided once');
});

test("set_access's page and basis carry each grant's end: shortened since it was shown, Approve is refused (L4)", async () => {
  const root = await connect(ROOT, 'read manage-access');
  const id = idOf(await callRaw(root, 'set_access', { member: `user:${OTHER}`, changes: { 'market/prod': 'auditor' } }));
  const shown = (await view(id, ROOT)).body.approval;
  await clientFor(deps, ROOT).access.set(`user:${OTHER}`, { 'market/prod': { role: 'viewer', until: '2099-01-01' } });
  assert.equal((await decide(id, true, { shown }, ROOT)).status, 409);
  const again = (await view(id, ROOT)).body.approval;
  assert.ok(again.details.some((line) => line.label === 'market/prod' && /^viewer until 2099-01-01.* → auditor$/.test(line.value)), JSON.stringify(again.details));
});

test("set_access's basis is a digest, as long for fifty expiring grants as for one, and Approve takes it (L4)", async () => {
  const root = clientFor(deps, ROOT);
  const places = Array.from({ length: 50 }, (_, index) => `market/place-${index}`);
  for (const place of places) await root.environments.create(place, { name: place });
  await root.access.set(`user:${OTHER}`, Object.fromEntries(places.map((place) => [place, { role: 'viewer', until: '2099-01-01' }])));
  const token = await connect(ROOT, 'read manage-access');
  const id = idOf(await callRaw(token, 'set_access', { member: `user:${OTHER}`, changes: Object.fromEntries(places.map((place) => [place, 'auditor'])) }));
  const shown = (await view(id, ROOT)).body.approval;
  assert.equal(shown.details.filter((line) => / until 2099-01-01.* → auditor$/.test(line.value)).length, 50, 'the page still reads each grant');
  assert.match(shown.basis!, /^[0-9a-f]{64}$/);
  const decided = await decide(id, true, { shown }, ROOT);
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  assert.equal(decided.body.status, 'approved');
});

test('what a change replaces, unread on the page or on Approve, approves nothing: the page says so, and Approve is refused (L4)', async () => {
  const root = await connect(ROOT, 'read manage-access');
  const id = idOf(await callRaw(root, 'set_access', { member: `user:${OTHER}`, changes: { 'market/prod': 'auditor' } }));
  const about = deps.vault.about;
  const failing = async <T>(work: () => Promise<T>): Promise<T> => {
    deps.vault.about = async () => {
      throw new Error('vault unreachable');
    };
    try {
      return await work();
    } finally {
      deps.vault.about = about;
    }
  };
  const held = async () => (await clientFor(deps, ROOT).members.list()).members.find((entry) => entry.member === `user:${OTHER}`)!.grants.map((grant) => grant.role);

  // The vault fails while the page reads the member's roles: it can't be approved, and a null basis is refused.
  const blind = await failing(() => view(id, ROOT));
  assert.equal(blind.body.approval.ready, false);
  assert.equal(blind.body.approval.basis, null);
  const unread = await decide(id, true, { shown: blind.body.approval }, ROOT);
  assert.equal(unread.status, 409);
  assert.match(unread.body.message!, /could not read what this replaces/);

  // Read on the page, then the vault fails as Approve reads them again: refused, to retry.
  const shown = (await view(id, ROOT)).body.approval;
  assert.equal(shown.ready, true);
  const retry = await failing(() => decide(id, true, { shown }, ROOT));
  assert.equal(retry.status, 503);
  assert.match(retry.body.message!, /try again/);
  assert.deepEqual(await held(), ['viewer'], 'nothing applied');
  assert.deepEqual((await entries('mcp.approve')).map((entry) => [entry.decision, entry.metadata.reason]), [['deny', 'unconfirmed'], ['deny', 'unconfirmed']]);

  // Read on both sides: approved.
  assert.equal((await decide(id, true, { shown }, ROOT)).body.status, 'approved');
  assert.deepEqual(await held(), ['auditor']);
});
