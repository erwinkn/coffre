// An MCP client connecting as Claude does (docs/design/mcp.md, section 14,
// checks 1 and 6): told to sign in by a 401, it reads both metadata
// documents, registers, sends a person to the consent page, and redeems the
// code. Its token is good at /mcp and nowhere else, nothing else is good
// there, a reused code or refresh token ends the connection, disconnecting
// ends it at the next call, and every step is in the log under the client.
import { createHash, randomBytes } from 'node:crypto';

import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';
import type { People, Person } from './people.ts';

const NAME = 'Conformance MCP client';
/** A native client's redirect, on loopback. A custom scheme is left out of a registration (D37). */
const REDIRECT = 'http://127.0.0.1:33418/callback';
/** A `state` the router would read as a number: it must come back as sent. */
const STATE = '1e5';

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
function mcp(deployment: Deployment, headers: Record<string, string>, method = 'server/discover'): Promise<Response> {
  return fetch(`${deployment.origin}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: {} }),
  });
}

function token(deployment: Deployment, fields: Record<string, string>): Promise<Response> {
  return fetch(`${deployment.origin}/api/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
  });
}

/** The person approves on the consent page, as its Approve does; the code comes back on the redirect. */
async function connect(deployment: Deployment, person: Person, clientId: string): Promise<{ code: string; verifier: string }> {
  const verifier = base64url(randomBytes(32));
  const request = {
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: base64url(createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
    state: STATE,
    scope: 'browse',
    resource: `${deployment.origin}/mcp`,
  };
  const view = await person.api.oauth.describe(request);
  expect(view.status === 'ready', 'the consent page refused a good request', view);
  expect(view.client.registration === 'dcr' && view.client.name === NAME && view.scopes.join(' ') === 'browse' && view.loopbackOnly,
    'the consent page does not show the registered client as it is', view);
  const { redirect } = await person.api.oauth.decide({ request, approve: true, scopes: [] });
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

async function discovers(deployment: Deployment, access: string): Promise<boolean> {
  const answer = await mcp(deployment, { authorization: `Bearer ${access}` });
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
  expect(challenge.includes(`resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`) && challenge.includes('scope="browse"'),
    "the 401's challenge does not name the resource metadata and Browse", challenge);
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
  expect(first.access_token.startsWith('coffre_mcp_') && first.refresh_token.startsWith('coffre_mcr_') && first.scope === 'browse',
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
