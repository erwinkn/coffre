// An MCP client connecting as Claude does (docs/design/mcp.md, section 14,
// checks 1 and 6): told to sign in by a 401, it reads both metadata
// documents, registers, sends a person to the consent page, and redeems the
// code. Its token is good at /mcp and nowhere else, nothing else is good
// there, a reused code or refresh token ends the connection, disconnecting
// ends it at the next call, and every step is in the log under the client.
import { createHash, randomBytes } from 'node:crypto';

import { CoffreError } from '@coffre/client';

import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';

import { canary, DEV, personaOn, PROD, PROJECT, valuesIn, type Canaries, type People, type Person } from './people.ts';

const NAME = 'Conformance MCP client';
/** A native client's redirect, on loopback. A custom scheme is left out of a registration (D37). */
const REDIRECT = 'http://127.0.0.1:33418/callback';
/** A `state` the router would read as a number: it must come back as sent. */
const STATE = '1e5';

/** What every 2026-07-28 request carries: its revision and the client's capabilities. */
const ENVELOPE = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} };

type Tokens = { access_token: string; refresh_token: string; scope: string; token_type: string; expires_in: number };

const base64url = (bytes: Buffer) => bytes.toString('base64url');

async function json(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { text };
  }
}

/** A JSON-RPC message to /mcp, with the headers a client sends. */
function mcp(deployment: Deployment, headers: Record<string, string>, method = 'server/discover', params: Record<string, unknown> = {}): Promise<Response> {
  return fetch(`${deployment.origin}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
}

function token(deployment: Deployment, fields: Record<string, string>): Promise<Response> {
  return fetch(`${deployment.origin}/api/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
  });
}

/**
 * The person approves on the consent page, as its Approve does, with what
 * they ticked: by default what the client asked for. The code comes back on
 * the redirect.
 */
async function connect(deployment: Deployment, person: Person, clientId: string, scope = 'read', ticked = scope.split(' ')): Promise<{ code: string; verifier: string }> {
  const verifier = base64url(randomBytes(32));
  const request = {
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: base64url(createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
    state: STATE,
    scope,
    resource: `${deployment.origin}/mcp`,
  };
  const view = await person.api.oauth.describe(request);
  expect(view.status === 'ready', 'the consent page refused a good request', view);
  expect(view.client.registration === 'dcr' && view.client.name === NAME && view.scopes.join(' ') === scope && view.loopbackOnly,
    'the consent page does not show the registered client as it is', view);
  const { redirect } = await person.api.oauth.decide({ request, approve: true, scopes: ticked });
  const back = new URL(redirect);
  expect(`${back.origin}${back.pathname}` === REDIRECT, `the answer went to ${back.origin}${back.pathname}, not the redirect`, redirect);
  expect(back.searchParams.get('state') === STATE && back.searchParams.get('iss') === deployment.origin,
    'the answer does not carry the state as sent and the issuer', redirect);
  const code = back.searchParams.get('code');
  expect(code !== null, 'an approval carried no code', redirect);
  return { code, verifier };
}

async function redeem(deployment: Deployment, clientId: string, { code, verifier }: { code: string; verifier: string }): Promise<Tokens> {
  const answer = await token(deployment, {
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    redirect_uri: REDIRECT,
    client_id: clientId,
    resource: `${deployment.origin}/mcp`,
  });
  const body = await json(answer);
  expect(answer.status === 200 && typeof body.access_token === 'string' && typeof body.refresh_token === 'string',
    `redeeming the code answered ${answer.status}`, body);
  expect(answer.headers.get('cache-control') === 'no-store', 'tokens were answered without cache-control: no-store');
  return body as unknown as Tokens;
}

async function refused(deployment: Deployment, what: string, fields: Record<string, string>): Promise<void> {
  const answer = await token(deployment, fields);
  const body = await json(answer);
  expect(answer.status === 400 && body.error === 'invalid_grant', `${what} answered ${answer.status}, not invalid_grant`, body);
}

/** Whether a connection's access token still reaches /mcp. */
export async function discovers(deployment: Deployment, access: string): Promise<boolean> {
  const answer = await mcp(deployment, { authorization: `Bearer ${access}`, 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'server/discover' }, 'server/discover', { _meta: ENVELOPE });
  if (answer.status === 401) return false;
  const body = await json(answer);
  expect(answer.status === 200 && Array.isArray((body.result as { supportedVersions?: unknown } | undefined)?.supportedVersions),
    `server/discover answered ${answer.status}`, body);
  return true;
}

export async function mcpConnect(deployment: Deployment, people: People): Promise<string> {
  const { origin } = deployment;

  // Without a token: 401, and where to find out how to get one.
  const anonymous = await mcp(deployment, {});
  const challenge = anonymous.headers.get('www-authenticate') ?? '';
  expect(anonymous.status === 401, `/mcp answered ${anonymous.status} without a token, not 401`);
  expect(challenge.includes(`resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`) && challenge.includes('scope="read"'),
    "the 401's challenge does not name the resource metadata and Read", challenge);
  const resource = await json(await fetch(`${origin}/.well-known/oauth-protected-resource/mcp`));
  expect(resource.resource === `${origin}/mcp` && (resource.authorization_servers as unknown[] | undefined)?.[0] === origin,
    'the protected resource metadata does not name /mcp and coffre as its issuer', resource);
  const server = await json(await fetch(`${origin}/.well-known/oauth-authorization-server`));
  expect(server.issuer === origin && server.authorization_endpoint === `${origin}/oauth/authorize`, 'the authorization server metadata is wrong', server);
  for (const [field, value] of [
    ['code_challenge_methods_supported', 'S256'],
    ['token_endpoint_auth_methods_supported', 'none'],
    ['grant_types_supported', 'refresh_token'],
  ] as const) {
    expect((server[field] as unknown[] | undefined)?.includes(value), `the authorization server metadata leaves ${value} out of ${field}`, server);
  }
  expect(server.client_id_metadata_document_supported === true, 'the authorization server metadata does not offer metadata documents', server);

  // A client registers: the custom scheme is left out, the loopback kept.
  const registered = await fetch(`${origin}/api/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: NAME, redirect_uris: [REDIRECT, 'conformance-app://callback'], token_endpoint_auth_method: 'none' }),
  });
  const client = await json(registered);
  expect(registered.status === 201 && typeof client.client_id === 'string', `registering answered ${registered.status}`, client);
  expect(JSON.stringify(client.redirect_uris) === JSON.stringify([REDIRECT]), 'the registration kept a redirect it should have left out', client);
  const clientId = client.client_id as string;

  // The consent page renders for the person; another site cannot answer it for them.
  const page = await people.reader.browser.fetch(`/oauth/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: REDIRECT })}`);
  expect(page.status === 200, `the consent page answered ${page.status}`);
  const forged = await people.reader.browser.fetch('/api/oauth/authorizations', {
    method: 'POST',
    headers: { origin: 'https://attacker.example', 'sec-fetch-site': 'cross-site', 'content-type': 'application/json' },
    body: JSON.stringify({ request: { client_id: clientId, redirect_uri: REDIRECT }, approve: true }),
  });
  expect(forged.status === 403, `another site's approval answered ${forged.status}, not 403`);

  // The first connection: its code redeemed, then its refresh token rotated.
  const first = await redeem(deployment, clientId, await connect(deployment, people.reader, clientId));
  expect(first.access_token.startsWith('coffre_mcp_') && first.refresh_token.startsWith('coffre_mcr_') && first.scope === 'read',
    'the tokens are not the shapes and scope coffre issues', { scope: first.scope });
  expect(await discovers(deployment, first.access_token), 'a fresh access token was refused at /mcp');

  // Audience: the MCP token is no API credential, and no other is good at /mcp.
  const atApi = await fetch(`${origin}/api/me`, { headers: { authorization: `Bearer ${first.access_token}` } });
  expect(atApi.status === 401, `an MCP token at /api answered ${atApi.status}, not 401`);
  const cli = await mcp(deployment, { authorization: `Bearer ${people.leaver.cliToken}` });
  expect(cli.status === 401, `a CLI session at /mcp answered ${cli.status}, not 401`);
  const browser = await people.reader.browser.fetch('/mcp', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server/discover' }),
  });
  expect(browser.status === 401, `a browser's cookie at /mcp answered ${browser.status}, not 401`);
  const foreign = await mcp(deployment, { authorization: `Bearer ${first.access_token}`, origin: 'https://attacker.example' });
  expect(foreign.status === 403, `/mcp answered ${foreign.status} to another site's page, not 403`);

  const rotate = (refresh: string) => token(deployment, { grant_type: 'refresh_token', refresh_token: refresh, client_id: clientId });
  const rotated = await rotate(first.refresh_token);
  const next = (await json(rotated)) as unknown as Tokens;
  expect(rotated.status === 200 && next.refresh_token !== first.refresh_token, `refreshing answered ${rotated.status}, or the same refresh token`);
  expect(await discovers(deployment, next.access_token), 'a refreshed access token was refused');
  // The replaced refresh token, again: the connection ends, and everything under it.
  await refused(deployment, 'a replaced refresh token', { grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: clientId });
  await refused(deployment, 'the current refresh token, after a reuse', { grant_type: 'refresh_token', refresh_token: next.refresh_token, client_id: clientId });
  expect(!(await discovers(deployment, next.access_token)), 'an access token outlived its connection, ended by a reused refresh token');

  // A second: its code, presented twice, ends it.
  const asked = await connect(deployment, people.reader, clientId);
  const second = await redeem(deployment, clientId, asked);
  await refused(deployment, 'a code redeemed already', {
    grant_type: 'authorization_code', code: asked.code, code_verifier: asked.verifier, redirect_uri: REDIRECT, client_id: clientId,
  });
  expect(!(await discovers(deployment, second.access_token)), 'an access token outlived its connection, ended by a reused code');

  // A third, listed under Connected apps, and disconnected there.
  const third = await redeem(deployment, clientId, await connect(deployment, people.reader, clientId));
  const listed = (await people.reader.api.apps.list()).apps;
  expect(listed.length === 1 && listed[0]!.name === NAME && listed[0]!.registration === 'dcr', 'Connected apps does not list the one live connection', listed);
  await people.reader.api.apps.disconnect(listed[0]!.id);
  expect(!(await discovers(deployment, third.access_token)), 'an access token outlived its disconnection');
  expect((await people.reader.api.apps.list()).apps.length === 0, 'a disconnected app is still listed');

  // Every step in the log, under the client.
  const { entries } = await people.admin.api.audit.list({ actor: people.reader.member, detail: '1', limit: 500 });
  const mine = entries.filter((entry) => entry.metadata.clientId === clientId);
  const count = (action: string) => mine.filter((entry) => entry.action === action && entry.decision === 'allow').length;
  const counts = { connect: count('mcp.connect'), token: count('mcp.token'), disconnect: count('mcp.disconnect') };
  expect(counts.connect === 3 && counts.token === 4 && counts.disconnect === 3, 'the log does not hold each connection, token and disconnection', counts);
  const reasons = mine.filter((entry) => entry.action === 'mcp.disconnect').map((entry) => entry.metadata.reason).sort();
  expect(JSON.stringify(reasons) === JSON.stringify(['code_reused', 'person', 'refresh_reused']), 'the disconnections do not say why', reasons);
  return '401 and both metadata documents; registered, approved, redeemed and discovered; only at /mcp, and only its token there; a reused refresh token, a reused code and a disconnection each end the connection, and the log says so';
}

/** A 2026-07-28 request as a client sends it: its headers say what its body does; `capabilities` are the client's. */
async function modern(deployment: Deployment, access: string, method: string, params: Record<string, unknown> = {}, name?: string, capabilities: Record<string, unknown> = {}) {
  const response = await mcp(deployment, {
    authorization: `Bearer ${access}`,
    'mcp-protocol-version': '2026-07-28',
    'mcp-method': method,
    ...(name === undefined ? {} : { 'mcp-name': name }),
  }, method, { ...params, _meta: { ...ENVELOPE, 'io.modelcontextprotocol/clientCapabilities': capabilities } });
  return { response, body: await json(response) };
}

/** A client registered for one check, by the name every check's client has. */
async function register(deployment: Deployment): Promise<string> {
  const registered = await json(await fetch(`${deployment.origin}/api/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: NAME, redirect_uris: [REDIRECT] }),
  }));
  return registered.client_id as string;
}

/** A client registered and connected as the person, with Read, for a check of another's: its access token. */
export async function connectedApp(deployment: Deployment, person: Person): Promise<string> {
  const clientId = await register(deployment);
  return (await redeem(deployment, clientId, await connect(deployment, person, clientId))).access_token;
}

/**
 * The Read tools, as a client calls them (design section 14, checks 1, 4
 * and 5): on 2026-07-28 and through a 2025-11-25 `initialize`, as the
 * reader, who sees dev and not prod. No value appears in any answer, the
 * headers must agree with the body, and every call is in the log under the
 * client, the API's own entries naming the connection.
 */
export async function mcpRead(deployment: Deployment, people: People, canaries: Canaries): Promise<string> {
  const clientId = await register(deployment);
  const { access_token: access } = await redeem(deployment, clientId, await connect(deployment, people.reader, clientId));
  const answers: string[] = [];

  // 2026-07-28: discover, list, call.
  const discovered = await modern(deployment, access, 'server/discover');
  answers.push(JSON.stringify(discovered.body));
  expect(discovered.response.status === 200, `server/discover answered ${discovered.response.status}`, discovered.body);
  const listed = await modern(deployment, access, 'tools/list');
  const result = listed.body.result as { tools?: { name: string; annotations?: { readOnlyHint?: boolean } }[]; cacheScope?: string; ttlMs?: number } | undefined;
  const names = result?.tools?.map((tool) => tool.name) ?? [];
  // The reader's list: their role's tools, and none of an instance owner's; theirs alone to cache, and not for long, so a role's change shows.
  expect(names.includes('list_secrets') && names.includes('run_with_secrets') && !names.includes('admit_member') && result?.cacheScope === 'private' && typeof result.ttlMs === 'number' && result.ttlMs <= 600_000,
    "tools/list does not list the reader's tools alone, cached for them only and briefly", listed.body);
  const callTool = async (tool: string, args: Record<string, unknown>) => {
    const { response, body } = await modern(deployment, access, 'tools/call', { name: tool, arguments: args }, tool);
    answers.push(JSON.stringify(body));
    expect(response.status === 200, `tools/call ${tool} answered ${response.status}`, body);
    return body.result as { structuredContent?: Record<string, unknown>; content?: { text?: string }[]; isError?: boolean };
  };
  const dev = await callTool('list_secrets', { environment: DEV });
  const keys = ((dev.structuredContent?.keys ?? []) as { key: string }[]).map((key) => key.key);
  expect(['API_KEY', 'DATABASE_URL'].every((key) => keys.includes(key)), `list_secrets on ${DEV} does not list its keys`, keys);
  const prod = await callTool('list_secrets', { environment: PROD });
  expect(prod.isError === true, `the reader listed ${PROD}'s keys through MCP, which they cannot`, prod);
  const run = await callTool('run_with_secrets', { environment: DEV, command: 'npm test' });
  expect(run.content?.[0]?.text?.includes(`coffre run ${DEV} -- npm test`) === true, 'run_with_secrets does not say how to run the command', run);
  for (const tool of ['whoami', 'list_projects']) await callTool(tool, {});
  await callTool('secret_history', { secret: `${DEV}/API_KEY` });

  // The headers say what the body does, or the request is refused.
  const mismatched = await mcp(deployment, {
    authorization: `Bearer ${access}`, 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': 'list_projects',
  }, 'tools/call', { name: 'whoami', arguments: {}, _meta: ENVELOPE });
  const mismatch = await json(mismatched);
  expect(mismatched.status === 400 && (mismatch.error as { code?: number } | undefined)?.code === -32020, `a Mcp-Name naming another tool answered ${mismatched.status}`, mismatch);

  // 2025-11-25: initialize, with no session, then the same tools.
  const initialized = await mcp(deployment, { authorization: `Bearer ${access}` }, 'initialize', {
    protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'coffre-conformance', version: '1' },
  });
  const init = await json(initialized);
  expect(initialized.status === 200 && (init.result as { protocolVersion?: string } | undefined)?.protocolVersion === '2025-11-25',
    `initialize for 2025-11-25 answered ${initialized.status}`, init);
  expect(initialized.headers.get('mcp-session-id') === null, 'initialize minted a session: coffre keeps none');
  const legacy = await mcp(deployment, { authorization: `Bearer ${access}`, 'mcp-protocol-version': '2025-11-25' }, 'tools/call', { name: 'list_secrets', arguments: { environment: DEV } });
  const legacyBody = await json(legacy);
  answers.push(JSON.stringify(legacyBody));
  expect(legacy.status === 200 && (legacyBody.result as { isError?: boolean } | undefined)?.isError !== true, `a 2025-11-25 tools/call answered ${legacy.status}`, legacyBody);

  // No value in any answer.
  const leaked = Object.entries(canaries).filter(([, value]) => answers.some((answer) => answer.includes(value))).map(([path]) => path);
  expect(leaked.length === 0, 'a Read tool answered with a secret value', leaked);

  // Every call in the log, under the client; the API's own refusal names the connection.
  const { entries } = await people.admin.api.audit.list({ actor: people.reader.member, detail: '1', limit: 500 });
  const mine = entries.filter((entry) => (entry.metadata.via as { clientId?: string } | undefined)?.clientId === clientId);
  const reads = mine.filter((entry) => entry.action === 'mcp.read').length;
  const refused = mine.filter((entry) => entry.action === 'mcp.call' && entry.decision === 'deny').length;
  expect(reads === 6 && refused === 1, 'the log does not hold each call under the client', { reads, refused });
  const api = mine.filter((entry) => !entry.action.startsWith('mcp.'));
  expect(api.length > 0, "the API's own entries for the calls do not name the connection", mine.map((entry) => entry.action));
  const shown = (await people.admin.api.audit.list({ actor: people.reader.member, limit: 500 })).entries;
  expect(!shown.some((entry) => entry.action === 'mcp.read'), 'read-only calls are not detail');
  return `on 2026-07-28 and 2025-11-25, the Read tools as the reader: ${DEV} listed, ${PROD} refused, no value in any answer; headers held to the body; ${reads} reads as detail and the refusal shown, each under the client`;
}

type ToolAnswer = {
  resultType?: string;
  structuredContent?: { status?: string; approval?: { id: string; url: string } };
  content?: { text?: string }[];
  isError?: boolean;
  inputRequests?: { approve?: { method: string; params: { mode: string; url: string; message: string } } };
  requestState?: string;
};

/**
 * Changes, as a client asks for them (design section 14, checks 2 and 3):
 * Read cannot ask at all, and with Write nothing changes until the person
 * approves on coffre's page. A client without URL elicitation gets the link
 * and calls again; one with it is asked to open the page, and retries with
 * its requestState, which no other call may use. Only the person decides,
 * with the digest the page showed; the page makes the change, once, and its
 * entries name the client and the approval. A value comes from the page.
 */
export async function mcpChanges(deployment: Deployment, people: People, canaries: Canaries): Promise<string> {
  const { admin } = people;
  const place = `${PROJECT}-mcp/dev`;
  await admin.api.projects.create(`${PROJECT}-mcp`, { name: 'MCP changes' });
  await admin.api.environments.create(place, { name: 'Development' });
  const values = { KEEP: canary(), OLD: canary() };
  for (const [key, value] of Object.entries(values)) canaries[`${place}/${key}`] = value;
  await admin.api.secrets.set(place, values);
  const changer = await personaOn(deployment, admin, 'changer', { [`${PROJECT}-mcp`]: 'maintainer' });
  const clientId = await register(deployment);
  const answers: string[] = [];
  const call = async (access: string, tool: string, args: Record<string, unknown>, more: Record<string, unknown> = {}, capabilities: Record<string, unknown> = {}) => {
    const { response, body } = await modern(deployment, access, 'tools/call', { name: tool, arguments: args, ...more }, tool, capabilities);
    answers.push(JSON.stringify(body));
    return { status: response.status, challenge: response.headers.get('www-authenticate') ?? '', result: body.result as ToolAnswer | undefined, error: body.error as { code?: number } | undefined };
  };
  const archived = async (key: string) => (await admin.api.secrets.history(`${place}/${key}`)).archived;

  // Read cannot ask for a change: 403, the step-up's scopes, and for a client that does not step up, how to grant Write; nothing reached the API.
  const reading = (await redeem(deployment, clientId, await connect(deployment, changer, clientId))).access_token;
  const stepUp = await call(reading, 'archive_secret', { secret: `${place}/OLD` });
  expect(stepUp.status === 403 && stepUp.challenge.includes('error="insufficient_scope"') && stepUp.challenge.includes('scope="read write"'),
    `archive_secret with Read answered ${stepUp.status}, not a step-up to Write`, stepUp.challenge);
  expect(stepUp.result?.isError === true && stepUp.result.content?.[0]?.text?.includes("ticking Write on coffre's consent page") === true,
    'archive_secret with Read does not say, as its result, how to grant Write', stepUp.result);
  expect(!(await archived('OLD')), 'archive_secret with Read archived the secret');

  // Write ticked on the consent page, though the client asked for Read only, as Claude does; the token says so.
  const granted = await redeem(deployment, clientId, await connect(deployment, changer, clientId, 'read', ['write']));
  expect(granted.scope === 'read write', `a connection ticked Write answered scope "${granted.scope}", not "read write"`, granted.scope);
  const write = granted.access_token;

  // With Write, and no URL elicitation: the link, and nothing changed.
  const linked = await call(write, 'archive_secret', { secret: `${place}/OLD` });
  const approval = linked.result?.structuredContent?.approval;
  expect(linked.status === 200 && linked.result?.structuredContent?.status === 'pending' && approval?.url === `${deployment.origin}/approvals/${approval?.id}`,
    'a change without URL elicitation was not answered with its approval link', linked.result);
  expect(linked.result?.content?.[0]?.text?.includes(approval!.url) === true, 'the link is not in the text the model reads', linked.result);
  expect(!(await archived('OLD')), 'a change was made before its approval');

  // Only its person decides it, and only the change the page showed.
  const theirs = await people.reader.api.approvals.get(approval!.id).then(() => null, (error: unknown) => error);
  expect(theirs instanceof CoffreError && theirs.status === 403, "another person opened someone else's approval", theirs);
  const page = await changer.browser.fetch(`/approvals/${approval!.id}`);
  expect(page.status === 200, `the approval page answered ${page.status}`);
  const shown = (await changer.api.approvals.get(approval!.id)).approval;
  expect(shown.status === 'pending' && shown.summary === `archive ${place}/OLD` && shown.client.name === NAME, 'the approval page does not show the change asked for', shown);
  const forgedDigest = await changer.api.approvals.decide(approval!.id, { approve: true, digest: '0'.repeat(64) }).then(() => null, (error: unknown) => error);
  expect(forgedDigest instanceof CoffreError && forgedDigest.status === 409, 'a decision on a change the page did not show was taken', forgedDigest);
  const forgedSite = await changer.browser.fetch(`/api/approvals/${approval!.id}`, {
    method: 'POST',
    headers: { origin: 'https://attacker.example', 'sec-fetch-site': 'cross-site', 'content-type': 'application/json' },
    body: JSON.stringify({ approve: true, digest: shown.digest }),
  });
  expect(forgedSite.status === 403, `another site's approval answered ${forgedSite.status}, not 403`);
  expect(!(await archived('OLD')), 'a refused decision changed something');

  const decided = await changer.api.approvals.decide(approval!.id, { approve: true, digest: shown.digest });
  expect(decided.status === 'approved' && (await archived('OLD')), 'Approve did not make the change', decided);
  const again = await changer.api.approvals.decide(approval!.id, { approve: true, digest: shown.digest }).then(() => null, (error: unknown) => error);
  expect(again instanceof CoffreError && again.status === 409, 'an approval was decided twice', again);
  const reported = await call(write, 'archive_secret', { secret: `${place}/OLD` });
  expect(reported.result?.structuredContent?.status === 'approved' && reported.result.isError !== true, 'calling again does not report the approved change', reported.result);

  // With URL elicitation: asked to open the page, and the retry's requestState is that call's only.
  const elicits = { elicitation: { url: {} } };
  const asked = await call(write, 'rename_secret', { secret: `${place}/KEEP`, newKey: 'KEPT' }, {}, elicits);
  const request = asked.result?.inputRequests?.approve;
  expect(asked.result?.resultType === 'input_required' && request?.method === 'elicitation/create' && request.params.mode === 'url' && typeof asked.result.requestState === 'string',
    'a change with URL elicitation was not answered with an input_required URL elicitation', asked.result);
  const id = request!.params.url.split('/').at(-1)!;
  const replayed = await call(write, 'rename_secret', { secret: `${place}/KEEP`, newKey: 'OTHER' }, { requestState: asked.result!.requestState, inputResponses: { approve: { action: 'accept' } } }, elicits);
  expect(replayed.error?.code === -32602, 'a requestState was accepted for another call', replayed);
  const renamedEarly = await admin.api.secrets.list(place);
  expect(renamedEarly.keys.some((key) => key.key === 'KEEP'), 'a change was made before its approval', renamedEarly.keys);
  const second = (await changer.api.approvals.get(id)).approval;
  expect((await changer.api.approvals.decide(id, { approve: true, digest: second.digest })).status === 'approved', 'the second approval was not made');
  const retried = await call(write, 'rename_secret', { secret: `${place}/KEEP`, newKey: 'KEPT' }, { requestState: asked.result!.requestState, inputResponses: { approve: { action: 'accept' } } }, elicits);
  expect(retried.result?.structuredContent?.status === 'approved', 'the retry does not report the approved change', retried.result);

  // A value, from the page only.
  const typed = canary();
  canaries[`${place}/TYPED`] = typed;
  const valueAsked = await call(write, 'request_secret_value', { secret: `${place}/TYPED` });
  const valueId = valueAsked.result!.structuredContent!.approval!.id;
  const valuePage = (await changer.api.approvals.get(valueId)).approval;
  expect(valuePage.asks?.value !== undefined, 'the approval page does not ask for the value');
  await changer.api.approvals.decide(valueId, { approve: true, digest: valuePage.digest, value: typed });
  expect((await admin.api.secrets.reveal(`${place}/TYPED`)).values.TYPED === typed, 'the value typed on the page was not written');
  await call(write, 'request_secret_value', { secret: `${place}/TYPED` });

  // A value coffre makes, approved by the person, reaches nobody.
  const generating = await call(write, 'generate_secret_value', { secret: `${place}/GENERATED`, alphabet: 'hex' });
  const generatedId = generating.result!.structuredContent!.approval!.id;
  const generatedPage = (await changer.api.approvals.get(generatedId)).approval;
  const generated = await changer.api.approvals.decide(generatedId, { approve: true, digest: generatedPage.digest });
  const made = (await admin.api.secrets.reveal(`${place}/GENERATED`)).values.GENERATED ?? '';
  canaries[`${place}/GENERATED`] = made;
  expect(/^[0-9a-f]{64}$/.test(made) && generated.shown.length === 0 && !JSON.stringify(generated).includes(made), 'generate_secret_value did not make a 64-character hex value, shown to no one');
  await call(write, 'generate_secret_value', { secret: `${place}/GENERATED`, alphabet: 'hex' });

  // No value in any answer; each change made once, by the person, via the client and its approval.
  const leaked = Object.entries(canaries).filter(([, value]) => answers.some((answer) => answer.includes(value))).map(([path]) => path);
  expect(leaked.length === 0, 'a change tool answered with a secret value', leaked);
  const { entries } = await admin.api.audit.list({ actor: changer.member, limit: 500 });
  const viaApproval = (action: string) => entries.filter((entry) => entry.action === action && entry.decision === 'allow' && typeof (entry.metadata.via as { approvalId?: unknown } | undefined)?.approvalId === 'string');
  const once = { archive: viaApproval('secret.archive').length, rename: viaApproval('secret.rename').length, write: viaApproval('secret.write').length };
  expect(once.archive === 1 && once.rename === 1 && once.write === 2, 'the changes are not each made once, via the client and its approval', once);
  const decisions = entries.filter((entry) => entry.action === 'mcp.approve').map((entry) => `${entry.decision} ${entry.reason ?? ''}`.trim()).sort();
  expect(JSON.stringify(decisions) === JSON.stringify(['allow', 'allow', 'allow', 'allow', 'deny approved', 'deny changed']), 'the decisions, and the two refused, are not in the log', decisions);
  return `Read stepped up to Write, saying how as its result; Write ticked beyond what was asked; with Write, the link without URL elicitation and an elicitation with it; nothing changed until ${changer.email} approved on coffre's page, another person and another site refused, a replayed requestState refused; each change made once, via the client and its approval; a value typed on the page only, and one coffre made reaching no one`;
}

/**
 * Values (design section 14, checks 2 and 4): Read cannot get one, Reveal
 * values gets what the person may, a value shown on coffre's page goes to
 * the person and not the client, and one a client asks coffre to make
 * reaches no one.
 */
export async function mcpValues(deployment: Deployment, people: People, canaries: Canaries): Promise<string> {
  const { reader } = people;
  const clientId = await register(deployment);
  const answers: string[] = [];
  const call = async (access: string, tool: string, args: Record<string, unknown>) => {
    const { response, body } = await modern(deployment, access, 'tools/call', { name: tool, arguments: args }, tool);
    answers.push(JSON.stringify(body));
    return { status: response.status, challenge: response.headers.get('www-authenticate') ?? '', result: body.result as ToolAnswer & { structuredContent?: { values?: Record<string, string> } } | undefined };
  };
  const dev = valuesIn(canaries, DEV);

  // Read: no value to the model, but one shown to the person on coffre's page.
  const reading = (await redeem(deployment, clientId, await connect(deployment, reader, clientId))).access_token;
  const stepUp = await call(reading, 'reveal_secret_values', { path: DEV });
  expect(stepUp.status === 403 && stepUp.challenge.includes('scope="read reveal"'), `reveal_secret_values with Read answered ${stepUp.status}, not a step-up`, stepUp.challenge);
  const show = await call(reading, 'show_secret_value', { secret: `${DEV}/API_KEY` });
  const id = show.result?.structuredContent?.approval?.id;
  expect(show.result?.structuredContent?.status === 'pending' && id !== undefined, 'show_secret_value did not open an approval', show.result);
  const page = (await reader.api.approvals.get(id!)).approval;
  expect(page.kind === 'reveal', 'the approval page does not say it shows a value', page);
  const shown = await reader.api.approvals.decide(id!, { approve: true, digest: page.digest });
  expect(shown.shown.some((line) => line.value === dev.API_KEY), 'Reveal did not show the person the value');
  const told = await call(reading, 'show_secret_value', { secret: `${DEV}/API_KEY` });
  expect(told.result?.structuredContent?.status === 'approved', 'show_secret_value does not report the value as shown', told.result);
  const readLeaks = Object.entries(canaries).filter(([, value]) => answers.some((answer) => answer.includes(value))).map(([path]) => path);
  expect(readLeaks.length === 0, 'a Read answer held a value', readLeaks);

  // Reveal values: the values the person may read, and no others.
  const revealing = (await redeem(deployment, clientId, await connect(deployment, reader, clientId, 'read reveal'))).access_token;
  const read = await call(revealing, 'reveal_secret_values', { path: DEV });
  expect(JSON.stringify(read.result?.structuredContent?.values) === JSON.stringify(dev), `reveal_secret_values on ${DEV} did not answer its values`);
  expect(read.result?.content?.[0]?.text?.startsWith('These values are now part of this conversation') === true, 'reveal_secret_values does not warn first', read.result?.content);
  const prod = await call(revealing, 'reveal_secret_values', { path: PROD });
  expect(prod.result?.isError === true && !JSON.stringify(prod.result).includes(canaries[`${PROD}/API_KEY`]!), `the reader read ${PROD} through MCP`, prod.result);
  return `Read stepped up for values and showed ${DEV}/API_KEY to ${reader.email} on coffre's page only; Reveal values answered ${DEV}'s values, warning first, and refused ${PROD}`;
}
