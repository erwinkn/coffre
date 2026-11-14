// Changes through MCP on the 0.16 contract (docs/design/0.16.md, "An MCP
// client's changes"): nothing changes until the person approves on coffre's
// page, and Approve makes the change, once, on their browser session with the
// connection and the approval named, which the vault holds to them and marks
// approved in the change's own write. A client that opens URLs is asked by
// elicitation and retries with its requestState; any other gets the link and
// calls again naming the approval. Values come only from the page, and go only to it.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { beforeEach, test } from 'node:test';

import { rowsOf } from '@coffre/db/dialect';
import { credential, emptyDatabase, environment, grant, identity, instance, principal, project, role, rows, secret, user, value, write } from '@coffre/vault/testing';
import { sql } from 'drizzle-orm';

import { approvalWait, callDigest } from '../src/mcp/approvals.ts';
import { app, callRaw, client, connect, fromPage, type Result } from './mcp-fixture.ts';

const { world } = app;
const [root, dev, other] = [user('root'), user('dev'), user('other')];
const VALUE = `value-${randomBytes(6).toString('hex')}`;
const CAPABLE = { elicitation: { url: {} } };
approvalWait.ms = 50;

/**
 * market/prod holds API_KEY. Root owns the instance; dev leads market, and
 * writes; other views market/prod. Each has a browser session,
 * `<name>-web`; dev has a CLI's too.
 */
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  const market = project('market');
  const prod = environment(market, 'prod');
  const people = [root, dev, other].map((who) => [who, identity(who)] as const);
  await write(
    world,
    ...rows('policy', instance()),
    ...rows('projects', market),
    ...rows('environments', prod),
    ...rows('secrets', value(world, secret(prod, 'API_KEY'), VALUE)),
    ...rows('roles',
      role(false, 'viewer', ['secret.read', 'secret.use'], []),
      role(false, 'lead', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage']),
      role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'member', [])),
    ...rows('principals', principal(root, { role: 'owner' }), principal(dev), principal(other)),
    ...rows('grants', grant(dev, 'lead', { project: market }), grant(other, 'viewer', { environment: prod })),
    ...rows('identities', ...people.map(([, id]) => id)),
    ...rows('credentials', ...people.map(([who, id]) => credential(`${who.slice(5, who.indexOf('@'))}-web`, who, { kind: 'browser', identityId: id.id })), credential('dev-cli', dev)),
  );
  app.calls.length = 0;
});

type View = { digest: string; basis: string | null; status: string; summary: string; kind: string; details: { label: string; value: string }[]; asks: unknown; ready: boolean; outcome: { text: string } | null };
type Decided = { status: string; outcome: { text: string; result?: Record<string, unknown> }; shown: { label: string; value: string }[]; message?: string; error?: string };

/** The person, on coffre's page: what the approval shows them, as their browser session sees it. */
async function view(id: string, session = 'dev-web', headers = fromPage(session)) {
  const response = await app.request(`/api/approvals/${id}`, { headers });
  return { status: response.status, body: (await response.json()) as { approval: View; message?: string } };
}

/** The person's decision on that page, sent with the digest and basis it showed. */
async function decide(id: string, approve: boolean, extra: { value?: string; digest?: string; shown?: View } = {}, session = 'dev-web', headers = fromPage(session)) {
  const shown = extra.shown ?? (await view(id, session)).body.approval;
  const response = await app.request(`/api/approvals/${id}`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({ approve, digest: extra.digest ?? shown.digest, basis: shown.basis, ...(extra.value === undefined ? {} : { value: extra.value }) }),
  });
  return { status: response.status, body: (await response.json()) as Decided };
}

/** A secret's value now, as root reads it, past what the vault remembers of an earlier read. */
async function valueOf(key: string): Promise<string | null> {
  world.memory.reads.clear();
  const response = await app.request('/api/reveals', { method: 'POST', headers: { ...fromPage('root-web'), 'content-type': 'application/json' }, body: JSON.stringify({ path: `market/prod/${key}` }) });
  return response.status === 200 ? ((await response.json()) as { values: Record<string, string> }).values[key]! : null;
}

/** The vault's entries of `action`, as written. */
async function entries(action: string): Promise<{ actor: string; credential: string; detail: Record<string, unknown>; objects: string[] }[]> {
  return (await rowsOf<{ body: string }>(world.owner, sql`SELECT body FROM log_pending ORDER BY id`)).map((row) => JSON.parse(row.body)).filter((entry) => entry.action === action);
}

const approvals = () => rowsOf<{ id: string; status: string; outcome: string | null; arguments: string }>(world.owner, sql`SELECT id::text, status, outcome, arguments FROM mcp_approvals ORDER BY created_at`);
/** What the vault wrote: its entries and the approvals' rows, as a count and a fingerprint. */
const written = async () => JSON.stringify([(await rowsOf(world.owner, sql`SELECT count(*)::int AS n FROM log_pending`))[0], await approvals()]);
const asRoot = { ...fromPage('root-web'), 'content-type': 'application/json' };
const idOf = (result: { body: { result?: Result } }) => (result.body.result!.structuredContent!.approval as { id: string }).id;
const SET = { secret: 'market/prod/NEW_KEY', note: 'the Stripe key' };

test('with URL elicitation, the official client is asked to open the page, and its retry reports the change the page made, once, the connection named in its entry', async () => {
  const mcp = await client(await connect('dev-web', 'read write'), 'modern', { elicitsUrl: true });
  const prompts: { url: string; message: string }[] = [];
  mcp.setRequestHandler('elicitation/create', async (request) => {
    const params = request.params as { mode: string; url: string; message: string };
    prompts.push(params);
    // Asked: nothing has changed yet. The person opens the page, reads it, types the value and approves.
    assert.equal(await valueOf('NEW_KEY'), null);
    const id = params.url.split('/').at(-1)!;
    const shown = await view(id);
    assert.equal(shown.body.approval.summary, 'set market/prod/NEW_KEY to a value you type on coffre');
    assert.ok(shown.body.approval.details.some((line) => line.label === 'Now' && /none yet/.test(line.value)));
    assert.equal((await decide(id, true, { value: 'typed-on-the-page' })).body.status, 'approved');
    return { action: 'accept' };
  });
  try {
    const result = (await mcp.callTool({ name: 'request_secret_value', arguments: SET })) as Result;
    assert.equal(result.isError, undefined, JSON.stringify(result));
    assert.equal(result.structuredContent!.status, 'approved');
    assert.match(result.content[0]!.text!, /market\/prod\/NEW_KEY is set to the value the person typed on coffre/);
    assert.ok(!JSON.stringify(result).includes('typed-on-the-page'), 'the value never reaches the client');
  } finally {
    await mcp.close();
  }
  assert.equal(prompts.length, 1);
  assert.match(prompts[0]!.url, /^https:\/\/secrets\.acme\.example\/approvals\/[0-9a-f-]{36}$/);
  assert.equal(prompts[0]!.message, 'Approve on coffre: set market/prod/NEW_KEY to a value you type on coffre');
  assert.equal(await valueOf('NEW_KEY'), 'typed-on-the-page');

  // The change's entry is the person's, on their browser session, and names the connection and the approval; made once.
  const [made, ...more] = await entries('secret.write');
  assert.equal(more.length, 0, 'made once');
  const [connection] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM credentials WHERE kind = 'mcp' AND ancestors IS NULL`);
  const [session] = await rowsOf<{ id: string }>(world.owner, sql`SELECT id::text FROM credentials WHERE label = 'dev-web'`);
  const [row] = await approvals();
  assert.deepEqual([made!.actor, made!.credential, made!.detail.via, made!.detail.approval], [dev, session!.id, connection!.id, row!.id]);
  assert.ok(made!.objects.includes(`credential:${connection!.id}`));
  assert.deepEqual([row!.status, row!.outcome], ['approved', null], "approved in the change's own write, with no outcome kept");
  assert.ok(!row!.arguments.includes('typed-on-the-page'), 'no row holds the value');
  // The ask is the client's, on its access token: its tool, place and digest, never its arguments.
  const [asked] = await entries('mcp.ask');
  assert.deepEqual([asked!.actor, asked!.detail.tool, asked!.detail.names, asked!.detail.digest], [dev, 'request_secret_value', ['market/prod/NEW_KEY'], callDigest('request_secret_value', SET)]);
  assert.ok(!JSON.stringify(asked).includes('Stripe'));
});

test('without URL elicitation, the result carries the link and the id; calling again naming it reads how it ended, as often as the client likes, writing nothing', async () => {
  const token = await connect('dev-web', 'read write');
  const first = await callRaw(token, 'request_secret_value', SET);
  assert.equal(first.status, 200);
  const result = first.body.result!;
  const approval = result.structuredContent!.approval as { id: string; url: string };
  assert.equal(result.structuredContent!.status, 'pending');
  assert.match(result.content[0]!.text!, new RegExp(approval.url.replace(/[./]/g, '\\$&')));
  assert.ok(result.content[0]!.text!.includes(`with the same arguments and approval: "${approval.id}"`));

  // Asked again without the id before the person decided: it joins the same approval, waits a little, and says so.
  const waiting = await callRaw(token, 'request_secret_value', SET);
  assert.equal(idOf(waiting), approval.id, 'the same call joins its approval');
  assert.equal(waiting.body.result!.structuredContent!.status, 'pending');
  assert.equal((await entries('mcp.ask')).length, 1);
  assert.equal(await valueOf('NEW_KEY'), null);

  assert.equal((await decide(approval.id, true, { value: 'v1' })).body.status, 'approved');
  // Named, three times over: the same answer, and nothing written.
  const before = await written();
  for (let time = 0; time < 3; time += 1) {
    const after = await callRaw(token, 'request_secret_value', { ...SET, approval: approval.id });
    assert.equal(after.body.result!.structuredContent!.status, 'approved');
    assert.deepEqual(after.body.result!.structuredContent!.result, { secret: 'market/prod/NEW_KEY' });
  }
  assert.equal(await written(), before, 'hearing writes nothing');

  // Without the id, after the decision: a new approval, whose page says the same was approved a moment ago.
  const again = await callRaw(token, 'request_secret_value', SET);
  assert.equal(again.body.result!.structuredContent!.status, 'pending');
  assert.notEqual(idOf(again), approval.id);
  const shown = (await view(idOf(again))).body.approval;
  assert.ok(shown.details.some((line) => line.label === 'Asked before' && line.value === 'You approved this same request less than a minute ago.'), JSON.stringify(shown.details));
  assert.equal((await entries('secret.write')).length, 1);
  // Another call's approval says nothing of it.
  const other = (await view(idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/OTHER' })))).body.approval;
  assert.ok(!other.details.some((line) => line.label === 'Asked before'));
});

test("a call names its approval by requestState or by its argument, alike: another call's is not for it, an unknown one or another connection's is no such approval; cancel gives the link, decline leaves it waiting", async () => {
  const token = await connect('dev-web', 'read write');
  const first = await callRaw(token, 'request_secret_value', SET, {}, CAPABLE);
  assert.equal(first.body.result!.resultType, 'input_required');
  const state = first.body.result!.requestState as string;
  const id = (first.body.result!.inputRequests as { approve: { params: { url: string } } }).approve.params.url.split('/').at(-1)!;
  assert.equal(state, id);

  const elsewhere = await connect('dev-web', 'read write');
  const cases = [
    [{ secret: 'market/prod/OTHER' }, token, state, 'Invalid params: this approval is not for this call'],
    [SET, elsewhere, state, 'Invalid params: no such approval'],
    [SET, token, '00000000-0000-4000-8000-000000000000', 'Invalid params: no such approval'],
  ] as const;
  for (const [args, by, sent, message] of cases) {
    const byState = await callRaw(by, 'request_secret_value', args, { requestState: sent }, CAPABLE);
    const byArgument = await callRaw(by, 'request_secret_value', { ...args, approval: sent });
    assert.deepEqual([byState.body.error?.code, byState.body.error?.message], [-32602, message], JSON.stringify(args));
    assert.deepEqual([byArgument.body.error?.code, byArgument.body.error?.message], [-32602, message], JSON.stringify(args));
  }
  assert.equal((await callRaw(token, 'request_secret_value', { ...SET, approval: 'not-an-id' })).body.result!.isError, true, "the tool's arguments refuse it");

  // Pending: the retry waits, then asks for nothing new, with the state again.
  const held = await callRaw(token, 'request_secret_value', SET, { requestState: state }, CAPABLE);
  assert.deepEqual([held.body.result!.resultType, held.body.result!.inputRequests, held.body.result!.requestState], ['input_required', undefined, state]);

  // Cancelled, the prompt was dismissed, or answered by a client that can ask no one: the link instead, still pending.
  const cancelled = await callRaw(token, 'request_secret_value', SET, { requestState: state, inputResponses: { approve: { action: 'cancel' } } }, CAPABLE);
  assert.equal(cancelled.body.result!.structuredContent!.status, 'pending');
  assert.match(String(cancelled.body.result!.structuredContent!.message), /Show the person the approval's url/);

  // Declined: the client hears it, and the approval waits on, its place held, for its person or its expiry.
  const before = await written();
  const declined = await callRaw(token, 'request_secret_value', SET, { requestState: state, inputResponses: { approve: { action: 'decline' } } }, CAPABLE);
  assert.equal(declined.body.result!.isError, true);
  assert.match(declined.body.result!.content[0]!.text!, /declined to open coffre's page: nothing changed/);
  assert.equal(await written(), before);
  assert.equal((await decide(id, true, { value: 'v' })).body.status, 'approved', 'the person may still approve it');

  // Past the outcome's ten minutes, a named approval says to ask anew.
  await world.owner.execute(sql`UPDATE mcp_approvals SET created_at = created_at - interval '11 minutes' WHERE id = ${id}::uuid`);
  const old = await callRaw(token, 'request_secret_value', { ...SET, approval: id });
  assert.match(old.body.result!.content[0]!.text!, /This approval has expired: call request_secret_value again without approval/);
});

test('a client asking and declining in a loop opens five approvals, writes five entries, and no more until the person decides one or one expires', async () => {
  const token = await connect('dev-web', 'read write');
  for (let round = 0; round < 8; round += 1) {
    const asked = await callRaw(token, 'request_secret_value', { secret: `market/prod/LOOP_${round}` }, {}, CAPABLE);
    const state = asked.body.result!.requestState as string | undefined;
    if (state !== undefined) await callRaw(token, 'request_secret_value', { secret: `market/prod/LOOP_${round}` }, { requestState: state, inputResponses: { approve: { action: 'decline' } } }, CAPABLE);
    else assert.match(asked.body.result!.content[0]!.text!, /5 changes are waiting for the person already/, `round ${round}`);
  }
  assert.equal((await entries('mcp.ask')).length, 5);
  assert.equal((await approvals()).length, 5);
  await world.owner.execute(sql`UPDATE mcp_approvals SET expires_at = now() - interval '1 second' WHERE arguments = ${JSON.stringify({ secret: 'market/prod/LOOP_0' })}`);
  assert.equal((await callRaw(token, 'request_secret_value', { secret: 'market/prod/LOOP_9' }, {}, CAPABLE)).body.result!.resultType, 'input_required');
  assert.equal((await entries('mcp.ask')).length, 6);
});

test('only its person decides, on their browser session and from coffre\'s page; a denial changes nothing, and is reported', async () => {
  const token = await connect('dev-web', 'read write');
  const id = idOf(await callRaw(token, 'request_secret_value', SET));

  const theirs = await view(id, 'other-web');
  assert.deepEqual([theirs.status, theirs.body.message], [403, 'this approval is for someone else']);
  const cli = await view(id, 'dev-cli', { authorization: 'Bearer dev-cli' });
  assert.equal(cli.status, 403, "the CLI's session decides nothing");
  const shown = (await view(id)).body.approval;
  assert.equal((await decide(id, true, { value: 'v', shown }, 'dev-cli', { authorization: 'Bearer dev-cli' })).status, 403);
  // Another site's page is refused before anything is read.
  app.calls.length = 0;
  const crossSite = await app.request(`/api/approvals/${id}`, { headers: { ...fromPage('dev-web'), 'sec-fetch-site': 'cross-site' } });
  assert.deepEqual([crossSite.status, app.calls], [403, []]);

  const denied = await decide(id, false);
  assert.equal(denied.body.status, 'denied');
  assert.equal((await entries('mcp.deny')).length, 1);
  assert.equal((await decide(id, true, { value: 'v', shown })).status, 409, 'decided once');
  const reported = await callRaw(token, 'request_secret_value', { ...SET, approval: id });
  assert.equal(reported.body.result!.isError, true);
  assert.equal(reported.body.result!.structuredContent!.status, 'denied');
  assert.equal(await valueOf('NEW_KEY'), null);
});

test('Approve runs only the ask the page rendered: a digest that is not it, or arguments edited in the row since, is refused before the vault is asked to change anything', async () => {
  const token = await connect('dev-web', 'read write');
  const id = idOf(await callRaw(token, 'request_secret_value', SET));
  const shown = (await view(id)).body.approval;
  assert.equal(shown.digest, callDigest('request_secret_value', SET));
  assert.equal((await decide(id, true, { value: 'v', digest: '0'.repeat(64), shown })).status, 409);

  // A writer of the app's database points the approval at another key, its digest left as it was: the page showed NEW_KEY.
  await world.owner.execute(sql`UPDATE mcp_approvals SET arguments = ${JSON.stringify({ secret: 'market/prod/API_KEY' })} WHERE id = ${id}::uuid`);
  app.calls.length = 0;
  const edited = await decide(id, true, { value: 'v', shown });
  assert.equal(edited.status, 409);
  assert.match(edited.body.message!, /not the one the page showed/);
  assert.deepEqual(app.calls, ['caller'], 'no change asked');
  assert.equal(await valueOf('API_KEY'), VALUE);
});

test("a value comes from the page only: Approve asks for it, writes it, and no outcome, row or client's answer holds it", async () => {
  const token = await connect('dev-web', 'read write');
  const id = idOf(await callRaw(token, 'request_secret_value', SET));
  const shown = (await view(id)).body.approval;
  assert.deepEqual(shown.asks, { value: { label: 'Value', note: 'It goes to coffre only: the app never sees it.' } });
  assert.ok(shown.details.some((line) => line.label === 'The app says' && line.value === 'the Stripe key'));
  assert.equal((await decide(id, true, { shown })).status, 400, 'no value typed');
  const made = await decide(id, true, { value: 'secret-typed', shown });
  assert.equal(made.body.status, 'approved');
  assert.deepEqual(made.body.shown, []);
  assert.equal(await valueOf('NEW_KEY'), 'secret-typed');
  const told = await callRaw(token, 'request_secret_value', { ...SET, approval: id });
  assert.equal(told.body.result!.structuredContent!.status, 'approved');
  assert.ok(!JSON.stringify(told.body).includes('secret-typed'));
  assert.ok((await approvals()).every((row) => !JSON.stringify(row).includes('secret-typed')));
});

test("Approve refuses a change whose page is stale: a version set since it was shown", async () => {
  const token = await connect('dev-web', 'read write');
  const id = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/API_KEY' }));
  const shown = (await view(id)).body.approval;
  assert.ok(shown.details.some((line) => line.label === 'Now' && /version 1/.test(line.value)));
  await app.request('/api/secrets/market/prod', { method: 'PATCH', headers: asRoot, body: JSON.stringify({ API_KEY: 'by-root' }) });
  const stale = await decide(id, true, { value: 'v', shown });
  assert.equal(stale.status, 409);
  assert.match(stale.body.message!, /changed since you opened it/);
  assert.equal(await valueOf('API_KEY'), 'by-root');
  // Still pending: the page opened again shows the version now, and Approve takes it.
  assert.equal((await decide(id, true, { value: 'v' })).body.status, 'approved');
  assert.equal(await valueOf('API_KEY'), 'v');
});

test('Approve refuses a page shown for a key since renamed, whose name another key now holds at the same version', async () => {
  const token = await connect('dev-web', 'read write');
  const id = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/API_KEY' }));
  const shown = (await view(id)).body.approval;
  assert.equal((await app.request('/api/secrets/market/prod/API_KEY', { method: 'PATCH', headers: asRoot, body: JSON.stringify({ key: 'MOVED' }) })).status, 200);
  assert.equal((await app.request('/api/secrets/market/prod', { method: 'PATCH', headers: asRoot, body: JSON.stringify({ API_KEY: 'another' }) })).status, 200);
  // The new API_KEY is at version 1 too: the page read another key.
  assert.ok((await view(id)).body.approval.details.some((line) => line.label === 'Now' && /version 1/.test(line.value)));
  const stale = await decide(id, true, { value: 'v', shown });
  assert.equal(stale.status, 409);
  assert.match(stale.body.message!, /changed since you opened it/);
  assert.deepEqual([await valueOf('API_KEY'), await valueOf('MOVED')], ['another', VALUE]);
});

test("a value written between Approve's read and its change refuses the change in the vault: nothing is written over it, and the approval still waits", async () => {
  const token = await connect('dev-web', 'read write');
  // Over a version, and over none: a key made in that moment is not written over either.
  for (const [secret, key] of [['market/prod/API_KEY', 'API_KEY'], ['market/prod/NEW_KEY', 'NEW_KEY']] as const) {
    const id = idOf(await callRaw(token, 'request_secret_value', { secret }));
    const shown = (await view(id)).body.approval;
    app.beforeChange.next = async (input) => {
      assert.equal((input as { op: string }).op, 'secret.write');
      assert.equal((await app.request('/api/secrets/market/prod', { method: 'PATCH', headers: asRoot, body: JSON.stringify({ [key]: 'by-root' }) })).status, 200);
    };
    const decided = await decide(id, true, { value: 'v', shown });
    assert.equal(app.beforeChange.next, null, 'the write came between');
    assert.equal(decided.status, 409, key);
    assert.match(decided.body.message!, /changed since it was listed/);
    assert.equal(await valueOf(key), 'by-root');
    assert.equal((await view(id)).body.approval.status, 'pending', 'the person reloads, sees the value now, and decides again');
  }
});

test("a reference made, or pointed elsewhere, between Approve's read and its change refuses it in the vault too: the page showed none, or another", async () => {
  const token = await connect('dev-web', 'read write');
  const patch = async (body: Record<string, unknown>) => (await app.request('/api/secrets/market/prod', { method: 'PATCH', headers: asRoot, body: JSON.stringify(body) })).status;
  assert.equal(await patch({ OTHER: 'other', LINK: { ref: 'market/prod/API_KEY' } }), 200);
  for (const [key, between, reads] of [['NEW_KEY', { NEW_KEY: { ref: 'market/prod/API_KEY' } }, VALUE], ['LINK', { LINK: { ref: 'market/prod/OTHER' } }, 'other']] as const) {
    const id = idOf(await callRaw(token, 'request_secret_value', { secret: `market/prod/${key}` }));
    const shown = (await view(id)).body.approval;
    app.beforeChange.next = async () => assert.equal(await patch(between), 200);
    const decided = await decide(id, true, { value: 'v', shown });
    assert.equal(app.beforeChange.next, null, 'the reference came between');
    assert.equal(decided.status, 409, key);
    assert.match(decided.body.message!, /changed since it was listed/);
    assert.equal(await valueOf(key), reads, 'still the reference made between');
    assert.equal((await view(id)).body.approval.status, 'pending');
  }
  // Read again, a reference is written over: the one the page shows now.
  const id = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/LINK' }));
  assert.ok((await view(id)).body.approval.details.some((line) => line.label === 'Now' && line.value === 'a reference to market/prod/OTHER'));
  assert.equal((await decide(id, true, { value: 'v' })).body.status, 'approved');
  assert.equal(await valueOf('LINK'), 'v');
});

/**
 * Can an approval be applied twice, or a change other than the one the page
 * showed be applied under it? Each race lands between Approve's checks on
 * the app and the vault's change: the vault, deciding on the approval's
 * row as it reads it then, refuses the change, and writes nothing.
 */
test("Approve racing another Approve, a denial, the expiry, or the connection's end, between the page's checks and the change: the vault refuses it", async () => {
  const token = await connect('dev-web', 'read write');
  const races: [string, (id: string, shown: View) => Promise<void>, RegExp, string][] = [
    // Its write moved the version on too: the change's own decision refuses it first (`stale`), the approval's second.
    ['another Approve', async (id, shown) => assert.equal((await decide(id, true, { value: 'from-the-other-tab', shown })).body.status, 'approved'), /changed since it was listed|decided already/, 'from-the-other-tab'],
    ['a denial', async (id, shown) => assert.equal((await decide(id, false, { shown })).body.status, 'denied'), /decided already/, VALUE],
    ['the expiry', async (id) => void (await world.owner.execute(sql`UPDATE mcp_approvals SET expires_at = now() + interval '2 seconds' WHERE id = ${id}::uuid`)), /has expired/, VALUE],
    ["the connection's end", async () => {
      const [connection] = ((await (await app.request('/api/apps', { headers: fromPage('dev-web') })).json()) as { apps: { id: string }[] }).apps;
      assert.equal((await app.request(`/api/apps/${connection!.id}`, { method: 'DELETE', headers: fromPage('dev-web') })).status, 200);
    }, /disconnected/, VALUE],
  ];
  for (const [race, between, refused, left] of races) {
    const id = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/API_KEY' }));
    const shown = (await view(id)).body.approval;
    app.beforeChange.next = async () => between(id, shown);
    const decided = await decide(id, true, { value: 'from-this-tab', shown });
    assert.equal(app.beforeChange.next, null, `${race} came between`);
    assert.equal(decided.status, 409, race);
    assert.match(decided.body.message!, refused, race);
    assert.equal(await valueOf('API_KEY'), left, race);
    // Set back for the next race.
    if (left !== VALUE) assert.equal((await app.request('/api/secrets/market/prod', { method: 'PATCH', headers: asRoot, body: JSON.stringify({ API_KEY: VALUE }) })).status, 200);
  }
  assert.equal((await entries('secret.write')).filter((entry) => entry.detail.approval !== undefined && entry.detail.refused === undefined).length, 1, "one change made under an approval: the other tab's");
});

test('a value shown while the approval is denied in another tab: the person sees it, theirs to read, and the client hears it denied', async () => {
  const token = await connect('dev-web', 'read');
  const id = idOf(await callRaw(token, 'show_secret_value', { secret: 'market/prod/API_KEY' }));
  const shown = (await view(id)).body.approval;
  app.beforeChange.next = async (input) => {
    assert.equal((input as { op: string }).op, 'mcp.decide');
    assert.equal((await decide(id, false, { shown })).body.status, 'denied');
  };
  const revealed = await decide(id, true, { shown });
  assert.equal(revealed.status, 200);
  assert.equal(revealed.body.status, 'denied');
  assert.deepEqual(revealed.body.shown, [{ label: 'API_KEY', value: VALUE, kind: 'mono' }]);
  assert.match(revealed.body.outcome.text, /could not record the approval/);
  const told = await callRaw(token, 'show_secret_value', { secret: 'market/prod/API_KEY', approval: id });
  assert.equal(told.body.result!.structuredContent!.status, 'denied');
});

test('a disconnected app\'s approvals can no longer be decided; one expired neither', async () => {
  const token = await connect('dev-web', 'read write');
  const id = idOf(await callRaw(token, 'request_secret_value', SET));
  const shown = (await view(id)).body.approval;
  await world.owner.execute(sql`UPDATE mcp_approvals SET expires_at = now() - interval '1 second' WHERE id = ${id}::uuid`);
  assert.equal((await view(id)).body.approval.status, 'expired');
  assert.equal((await decide(id, true, { value: 'v', shown })).status, 409);

  const second = idOf(await callRaw(token, 'request_secret_value', { secret: 'market/prod/SECOND' }));
  const [connection] = (await (await app.request('/api/apps', { headers: fromPage('dev-web') })).json() as { apps: { id: string }[] }).apps;
  assert.equal((await app.request(`/api/apps/${connection!.id}`, { method: 'DELETE', headers: fromPage('dev-web') })).status, 200);
  const gone = await view(second);
  assert.equal(gone.status, 409);
  assert.match(gone.body.message!, /disconnected/);
  assert.equal(await valueOf('SECOND'), null);
});

test('a change the person could not make is refused before anyone is asked; without Write, the step-up starts', async () => {
  // Other views market/prod: the call fails as the API would, and no approval is opened.
  const theirs = await callRaw(await connect('other-web', 'read write'), 'request_secret_value', SET);
  assert.equal(theirs.body.result!.isError, true);
  assert.match(theirs.body.result!.content[0]!.text!, /you need secret.write on market\/prod/);
  assert.equal((await approvals()).length, 0);
  const readOnly = await callRaw(await connect('dev-web', 'read'), 'request_secret_value', SET);
  assert.equal(readOnly.status, 403);
  assert.match(readOnly.headers.get('www-authenticate')!, /insufficient_scope.*scope="read write"/);
  assert.equal((await approvals()).length, 0);
});

test('identical calls at once open one approval, and a connection holds at most five waiting', async () => {
  const token = await connect('dev-web', 'read write');
  const same = await Promise.all([1, 2, 3].map(() => callRaw(token, 'request_secret_value', SET)));
  assert.equal(new Set(same.map(idOf)).size, 1);
  const keys = ['A', 'B', 'C', 'D', 'E', 'F'].map((key) => `market/prod/KEY_${key}`);
  const burst = await Promise.all(keys.map((secret) => callRaw(token, 'request_secret_value', { secret })));
  assert.equal(burst.filter((call) => call.body.result!.isError === true).length, 2, 'five waiting: the first, and four of the burst');
  assert.match(burst.find((call) => call.body.result!.isError === true)!.body.result!.content[0]!.text!, /5 changes are waiting for the person already/);
  assert.equal((await approvals()).length, 5);
});

test("show_secret_value shows the value to the person on the page, on Read, and never to the client nor into a row", async () => {
  const token = await connect('dev-web', 'read');
  const asked = await callRaw(token, 'show_secret_value', { secret: 'market/prod/API_KEY' });
  const id = idOf(asked);
  const shown = (await view(id)).body.approval;
  assert.deepEqual([shown.kind, shown.asks, shown.ready], ['reveal', null, true]);
  assert.ok(!JSON.stringify(shown).includes(VALUE), 'the page shows no value before Reveal');
  const revealed = await decide(id, true, { shown });
  assert.equal(revealed.body.status, 'approved');
  assert.deepEqual(revealed.body.shown, [{ label: 'API_KEY', value: VALUE, kind: 'mono' }]);
  assert.ok(!JSON.stringify(revealed.body.outcome).includes(VALUE));
  assert.equal((await entries('mcp.approve')).length, 1);
  const told = await callRaw(token, 'show_secret_value', { secret: 'market/prod/API_KEY', approval: id });
  assert.equal(told.body.result!.structuredContent!.status, 'approved');
  assert.match(told.body.result!.content[0]!.text!, /shown to the person on coffre .* It was not sent here\./);
  assert.ok(!JSON.stringify(told.body).includes(VALUE));
  assert.ok((await approvals()).every((row) => !JSON.stringify(row).includes(VALUE)));
  // The read is the person's, on their session, as any reveal on the page is.
  const [read] = await entries('secret.read');
  assert.equal(read!.actor, dev);
});
