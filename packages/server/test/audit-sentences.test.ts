// The audit page's sentences (`@coffre/ui/audit-sentences`) on entries the
// real vault wrote, read back through `GET /api/audit` as the page reads
// them: one of every action the vault logs (`LOG_ACTIONS`), each made the
// way the app makes it, through its routes where one is served and through
// `vault.change` where none is yet. Every one reads as a sentence, with no
// fallback, and says what happened.
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { after, beforeEach, test } from 'node:test';

import { canonicalClaims, github, signin } from '@coffre/core/identity';
import { LOG_ACTIONS, type KeyWrite } from '@coffre/core/vault';
import { describe, plain, runLabel, type AuditEntry } from '@coffre/ui/audit-sentences';

import {
  adoptFresh,
  binding,
  credential,
  emptyDatabase,
  environment,
  grant,
  identity,
  instance,
  oauthClient,
  principal,
  project,
  role,
  rows,
  signerOf,
  tokenOf,
  user,
  write,
} from '@coffre/vault/testing';

import { processLimits } from '../src/workloads/limits.ts';
import { openApp, PUBLIC_URL, SESSION } from './app-fixture.ts';

const mcp = { limits: processLimits({ perSource: 100_000, perConnection: 100_000, total: 100_000 }) };
const app = await openApp({ auth: signin({ providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })], mcp }), workloads: {} });
const { world } = app;
after(() => app.close());

const [ada, aud, cy, ed] = ['ada', 'aud', 'cy', 'ed'].map(user) as [string, string, string, string];
const GITHUB = 'https://token.actions.githubusercontent.com';
const MAIN = { repository_owner_id: '9919', repository_id: '41532', ref: 'refs/heads/main', event_name: 'push' };
const REDIRECT = 'http://127.0.0.1/callback';
const KEY = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

type Body = Record<string, unknown>;
const call = async (label: string, method: string, path: string, body?: unknown): Promise<[number, Body]> => {
  const got = await app.request(`/api${path}`, { method, headers: { authorization: `Bearer ${label}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return [got.status, (await got.json()) as Body];
};
const ok = async (label: string, method: string, path: string, body?: unknown): Promise<Body> => {
  const [status, answer] = await call(label, method, path, body);
  assert.equal(status, 200, `${method} ${path}: ${JSON.stringify(answer)}`);
  return answer;
};
/** A change no route serves yet, asked of the vault as the app asks it. */
const as = (label: string) => ({ token: tokenOf(label).toString('hex'), proof: null, request: 'req-1', ip: '192.0.2.7' });
const made = async (asked: Promise<{ answer: unknown } | { refused: string }>) => {
  const got = await asked;
  assert.ok('answer' in got, JSON.stringify(got));
  return got.answer as Record<string, unknown>;
};
const asCy = { cookie: `${SESSION}=cy-web`, 'sec-fetch-site': 'same-origin' };
const form = (path: string, fields: Record<string, string>) =>
  app.request(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });

/** The whole log with its detail, newest first, as the Auditor's page reads it. */
async function logged(label = 'aud-cli'): Promise<AuditEntry[]> {
  const [status, page] = await call(label, 'GET', '/audit?detail=1&limit=500');
  assert.equal(status, 200, JSON.stringify(page));
  return (page.entries as AuditEntry[]).filter((entry) => entry.action !== 'test.write');
}
/** An entry's sentence, and the fallbacks a template says where its entry lacks what it reads. */
function said(entry: AuditEntry): string {
  const { parts } = describe([entry]);
  const sentence = plain(parts);
  assert.ok(!sentence.startsWith(`${entry.action} `), `${entry.action} has no sentence: ${sentence}`);
  assert.ok(!parts.includes('coffre'), `${entry.action} names no place: ${sentence}`);
  for (const fallback of ['someone', 'a role', 'an app', 'a tool', 'sign-in account']) assert.ok(!sentence.includes(fallback), `${entry.action} says "${fallback}": ${sentence}`);
  return sentence;
}

let sign: (full?: boolean) => Promise<void>;
beforeEach(async () => {
  await emptyDatabase(world.owner);
  for (const kept of [world.memory.reads, world.memory.callers, world.memory.logged, world.memory.touched, world.refused]) kept.clear();
  world.woken.length = 0;
  ({ sign } = await signerOf(world));
});

/**
 * market: prod, dev, qa (made here). billing: prod. Cy owns the instance,
 * signed in on the CLI and in a browser; Aud reads the whole log; Ada and Ed
 * hold grants. ci is a service account a CI run and a workload sign in as.
 */
async function seed() {
  const [market, billing] = [project('market'), project('billing')];
  const [cys, eds] = [identity(cy), identity(ed)];
  const viewer = JSON.stringify([{ projectId: billing.id, environmentId: null, role: 'viewer' }]);
  await write(
    world,
    ...rows('projects', market, billing),
    ...rows('environments', environment(market, 'prod'), environment(market, 'dev'), environment(billing, 'prod')),
    ...rows('roles',
      role(false, 'viewer', ['secret.read'], []),
      role(false, 'developer', ['secret.read', 'secret.write'], []),
      role(true, 'owner', ['secret.read', 'secret.use', 'secret.write', 'secret.archive', 'environment.manage', 'project.manage', 'grant.manage', 'audit.read']),
      role(true, 'auditor', ['audit.read']),
      role(true, 'member', [])),
    ...rows('principals', principal(ada), principal(aud, { role: 'auditor' }), principal(cy, { role: 'owner' }), principal(ed), principal('token:ci')),
    ...rows('policy', instance()),
    ...rows('grants', grant(ada, 'viewer', { project: market }), grant('token:ci', 'viewer', { project: billing })),
    ...rows('identities', cys, eds),
    ...rows('bindings',
      binding('token:ci', { claims: canonicalClaims(MAIN), scope: viewer, label: 'main' }),
      binding('token:ci', { profile: 'aws', issuer: 'urn:coffre:aws', jwksUri: 'urn:coffre:aws', claims: canonicalClaims({ account: '123456789012', role_id: 'AROAEXAMPLEROLEID01' }), scope: viewer, policy: '{"sessionHours":2}', label: 'aws' })),
    ...rows('credentials', ...[ada, aud, cy, ed].map((who) => credential(`${who.slice(5, who.indexOf('@'))}-cli`, who)), credential('cy-web', cy, { kind: 'browser', identityId: cys.id }),
      // Lapsed two days ago: the upkeep removes it.
      credential('lapsed', ed, { expiresAt: new Date(Date.now() - 2 * 86_400_000) })),
    ...rows('oauthClients', oauthClient('Old', { createdAt: new Date(Date.now() - 8 * 86_400_000) })),
  );
  return { eds };
}

test('every action the vault writes reads as a sentence, with no fallback, and says what happened', async () => {
  const { eds } = await seed();
  // Secrets: written, changed, read, referred to and back, archived and back, restored, filed, renamed, dismissed.
  for (const [method, path, body] of [
    ['PUT', '/projects/market/qa', {}],
    ['PATCH', '/secrets/market/dev', { API_KEY: 'v1', TOKEN: 't1', URL: 'u1' }],
    ['PATCH', '/secrets/market/dev', { API_KEY: 'v2' }],
    ['POST', '/reveals', { path: 'market/dev/API_KEY' }],
    ['POST', '/reveals', { path: 'market/dev' }],
    ['PATCH', '/secrets/market/prod', { LINK: { ref: 'market/dev/TOKEN' } }],
    ['POST', '/reveals', { path: 'market/prod/LINK' }],
    ['DELETE', '/secrets/market/prod/LINK/reference'],
    ['PATCH', '/secrets/market/prod', { OWN: { ref: 'market/dev/TOKEN' } }],
    ['PATCH', '/secrets/market/prod', { OWN: 'mine' }],
    ['PATCH', '/secrets/market/prod', { OWN: { sensitivity: 'sensitive' } }],
    ['PATCH', '/secrets/market/prod', { OWN: { sensitivity: 'secret' } }],
    ['PATCH', '/secrets/market/dev', { URL: null }],
    ['PATCH', '/secrets/market/dev/URL', { archived: false }],
    ['POST', '/secrets/market/dev/API_KEY/restore', { version: 1 }],
    ['PATCH', '/secrets/market/dev/API_KEY', { folder: 'kept' }],
    ['PATCH', '/folders/market/dev/kept', { name: 'filed' }],
    ['PATCH', '/secrets/market/dev/API_KEY', { key: 'RENAMED' }],
    ['PATCH', '/projects/market/prod/dismissals', { Z: true }],
    // Places.
    ['PUT', '/projects/shop', { name: 'Shop' }],
    ['PATCH', '/projects/shop', { folder: 'apps' }],
    ['PATCH', '/folders/apps', { name: 'tools' }],
    ['PATCH', '/projects/shop', { slug: 'store' }],
    ['PATCH', '/projects/store', { archived: true }],
    ['PATCH', '/projects/store', { archived: false }],
    ['PATCH', '/projects/market/qa', { slug: 'uat' }],
    ['PATCH', '/projects/market/uat', { protected: true }],
    ['PATCH', '/projects/market/uat', { protected: false }],
    ['PATCH', '/projects/market/uat', { archived: true }],
    ['PATCH', '/projects/market/uat', { archived: false }],
    ['PATCH', '/projects/market/uat', { archived: true }],
    ['DELETE', '/projects/market/uat'],
    ['PATCH', '/projects/store', { archived: true }],
    ['DELETE', '/projects/store'],
    // Members and access.
    ['PUT', '/members/user:temp@acme.example', {}],
    ['PUT', '/members/user:temp@acme.example', { role: 'auditor' }],
    ['DELETE', '/members/user:temp@acme.example'],
    ['PUT', '/members/user:temp@acme.example', {}],
    ['PATCH', `/access/${ada}`, { 'market/dev': 'viewer' }],
    ['PATCH', `/access/${ada}`, { market: null }],
    ['PUT', '/roles/release', { name: 'Release', description: 'Ships.', permissions: ['secret.use', 'secret.write'], protected: ['secret.use'] }],
    ['PUT', '/settings', { serviceAccounts: { environments: { only: ['dev'] } } }],
    ['POST', '/freezes', { target: 'service:ci', reason: 'the key leaked in a build log' }],
    ['DELETE', '/freezes/token%3Aci'],
  ] as const) await ok('cy-cli', method, path, body);
  await ok('ed-cli', 'DELETE', `/identities/${eds.id}`);
  // Refused where no row was found: said with no place, not the one asked.
  assert.equal((await call('ada-cli', 'PUT', '/projects/nope', {}))[0], 403);
  const token = await ok('cy-cli', 'POST', '/members/token:ci/tokens', { label: 'deploy', expiresInDays: 1 });
  await ok('cy-cli', 'DELETE', `/members/token:ci/tokens/${token.id as string}`);
  await made(app.vault.change({ ...as('cy-cli'), op: 'upstream.freeze', project: 'market', environment: 'prod', upstream: 'stripe' }));
  await made(app.vault.change({ ...as('cy-cli'), op: 'upstream.thaw', project: 'market', environment: 'prod', upstream: 'stripe' }));
  const kube = 'https://kubernetes.acme.example';
  const bound = await made(app.vault.change({
    ...as('cy-cli'), op: 'token.bind', member: 'token:ci',
    binding: { profile: 'custom', issuer: kube, claims: { sub: 'system:serviceaccount:ci:runner' }, keys: { uri: `${kube}/openid/v1/jwks` }, policy: null, scope: null, label: 'pods', replaces: [] },
  }));
  await made(app.vault.change({ ...as('cy-cli'), op: 'token.unbind', member: 'token:ci', binding: (bound.bindings as { id: string }[])[0]!.id }));

  // Signing in: a browser, a second account linked, a CLI's device login approved, used and signed out, and one turned down.
  const account = (subject: string, email: string) => ({ provider: 'github', issuer: 'https://github.com', subject, emails: [email] });
  await made(app.vault.change({ request: 'req-1', ip: '192.0.2.7', op: 'signin', account: account('gh-ed', 'ed@acme.example'), session: { token: tokenOf('ed-web').toString('hex'), minutes: 60, label: null }, replaces: null }));
  await made(app.vault.change({ ...as('cy-web'), op: 'account.link', account: account('gh-cy-work', 'cy@work.example') }));
  const start = async () => (await (await app.request('/api/auth/device', { method: 'POST', body: JSON.stringify({ label: 'laptop' }) })).json()) as { device_code: string; user_code: string };
  const decide = (code: string, approve: boolean) => app.request(`/api/device-logins/${code}`, { method: 'POST', headers: asCy, body: JSON.stringify({ approve }) });
  const device = await start();
  assert.equal((await decide(device.user_code, true)).status, 200);
  const { access_token: cli } = (await (await app.request('/api/auth/device/token', { method: 'POST', body: JSON.stringify({ device_code: device.device_code }) })).json()) as { access_token: string };
  assert.equal((await app.request('/api/auth/logout', { method: 'POST', headers: { authorization: `Bearer ${cli}` } })).status, 200);
  assert.equal((await decide((await start()).user_code, false)).status, 200);

  // An MCP client registered, connected, given tokens, asking for a value shown, a change turned down and one made, then revoked.
  const client = (await (await app.request('/api/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Zed', redirect_uris: [REDIRECT] }) })).json()) as { client_id: string };
  const verifier = randomBytes(32).toString('base64url');
  const consent = { client_id: client.client_id, redirect_uri: REDIRECT, response_type: 'code', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', state: 's', scope: 'read write reveal' };
  const { redirect } = (await (await app.request('/api/oauth/authorizations', { method: 'POST', headers: asCy, body: JSON.stringify({ request: consent, approve: true, scopes: ['read', 'write', 'reveal'] }) })).json()) as { redirect: string };
  const tokens = (await (await form('/api/oauth/token', { grant_type: 'authorization_code', code: new URL(redirect).searchParams.get('code')!, code_verifier: verifier, redirect_uri: REDIRECT, client_id: client.client_id })).json()) as { access_token: string };
  const tool = async (name: string, args: unknown) => {
    const headers = { authorization: `Bearer ${tokens.access_token}`, 'content-type': 'application/json', 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': name };
    const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} };
    const answer = (await (await app.request('/mcp', { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args, _meta: meta } }) })).json()) as { result: { structuredContent: { approval: { id: string } } } };
    return answer.result.structuredContent.approval.id;
  };
  const approve = async (id: string, yes: boolean, value?: string) => {
    const { approval } = (await (await app.request(`/api/approvals/${id}`, { headers: asCy })).json()) as { approval: { digest: string; basis: unknown } };
    return app.request(`/api/approvals/${id}`, { method: 'POST', headers: asCy, body: JSON.stringify({ approve: yes, digest: approval.digest, basis: approval.basis, value }) });
  };
  assert.equal((await approve(await tool('show_secret_value', { secret: 'market/dev/RENAMED' }), true)).status, 200);
  assert.equal((await approve(await tool('request_secret_value', { secret: 'market/dev/ASKED' }), false)).status, 200);
  assert.equal((await approve(await tool('request_secret_value', { secret: 'market/dev/SET' }), true, 'typed')).status, 200);
  assert.equal((await form('/api/oauth/revoke', { token: tokens.access_token, client_id: client.client_id })).status, 200);

  // A CI run's ID token exchanged (the app checked its signature), a workload's session started and renewed.
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const run = `${b64({ alg: 'RS256', kid: 'k1' })}.${b64({ iss: GITHUB, sub: 'repo:acme/api:ref:refs/heads/main', aud: PUBLIC_URL, iat: now - 10, exp: now + 290, jti: 'run-1', run_id: '7001', sha: 'abc123', ...MAIN })}.c2ln`;
  await made(app.vault.change({ request: 'req-1', ip: '192.0.2.7', op: 'token.exchange', service: 'token:ci', token: run, under: { issuer: GITHUB, jwksUri: `${GITHUB}/.well-known/jwks` }, publicUrl: PUBLIC_URL, credential: tokenOf('run-1').toString('hex') }));
  await made(app.vault.change({
    request: 'req-1', ip: '192.0.2.7', op: 'workload.signin', service: 'token:ci', key: KEY, publicUrl: PUBLIC_URL, credential: tokenOf('pod-1').toString('hex'),
    proof: { aws: { account: '123456789012', arn: 'arn:aws:sts::123456789012:assumed-role/deployer/i-0abc', userId: 'AROAEXAMPLEROLEID01:i-0abc' } },
  }));
  await made(app.vault.change({ ...as('pod-1'), proof: KEY, op: 'workload.renew' }));
  // A minute's full run: the lapsed session and the client nobody connected go.
  await sign(true);

  const entries = (await logged()).reverse();
  // The run a CI run's exchange was for, as its issuer stated it.
  const exchange = entries.find((entry) => entry.action === 'token.exchange') as AuditEntry & { run: { claims: Record<string, string | number> } | null };
  assert.equal(runLabel(exchange.run), 'CI run repo:acme/api:ref:refs/heads/main');
  // A place deleted is named by its tombstone, as every entry about it is: the page names places as they are now.
  const sentences = entries.map((entry) => `${entry.action}: ${said(entry)}`.replace(/~deleted-\d{4}-\d{2}-\d{2}/, '~deleted-<date>'));
  assert.deepEqual(sentences, [
    'environment.create: created environment market/uat~deleted-<date>',
    'secret.write: added market/dev: 3 secrets',
    'secret.write: changed market/dev/API_KEY, now version 2',
    'secret.read: revealed market/dev/API_KEY',
    'secret.read: ran market/dev: 3 secrets',
    'secret.write: made market/prod/LINK a reference',
    'secret.read: revealed market/prod/LINK through a reference',
    'reference.break: broke the reference market/prod/LINK',
    'secret.write: made market/prod/OWN a reference',
    'secret.write: gave a value of its own to market/prod/OWN',
    'secret.write: marked market/prod/OWN sensitive, from secret, its value kept',
    'secret.loosen: marked market/prod/OWN secret, from sensitive, its value kept',
    'secret.write: archived market/dev/URL',
    'secret.write: brought back market/dev/URL',
    'secret.write: restored market/dev/API_KEY to version 1, now 3',
    'secret.write: moved market/dev/API_KEY to the folder kept',
    'secret.refile: moved API_KEY in market/dev to the folder filed',
    'secret.rename: renamed market/dev/API_KEY to RENAMED',
    'missing.dismiss: dismissed Z in market/prod as not needed',
    'project.create: created project store~deleted-<date>',
    'project.move: moved project store~deleted-<date> to the folder apps',
    'folder.refile: renamed the folder apps to tools, 1 project',
    'project.update: renamed project store~deleted-<date>, was shop',
    'project.archive: archived project store~deleted-<date>',
    'project.restore: restored project store~deleted-<date>',
    'environment.update: renamed environment market/uat~deleted-<date>, was qa',
    'environment.protect: protected market/uat~deleted-<date>',
    'environment.unprotect: unprotected market/uat~deleted-<date>',
    'environment.archive: archived environment market/uat~deleted-<date>',
    'environment.restore: restored environment market/uat~deleted-<date>',
    'environment.archive: archived environment market/uat~deleted-<date>',
    'environment.delete: deleted environment market/uat~deleted-<date>',
    'project.archive: archived project store~deleted-<date>',
    'project.delete: deleted project store~deleted-<date>',
    'member.add: added temp@acme.example',
    'member.role: made temp@acme.example an Auditor',
    'member.remove: removed temp@acme.example',
    'member.restore: brought back temp@acme.example',
    'access.grant: gave ada@acme.example viewer on market/dev',
    'access.revoke: took viewer on market from ada@acme.example',
    'policy.change: made the Release role',
    'settings.change: set where people set up service accounts: All projects · dev only, was All projects',
    'workload.freeze: froze the workloads of service:ci: the key leaked in a build log',
    'workload.unfreeze: unfroze the workloads of service:ci',
    'account.unlink: unlinked a github account',
    'project.create: tried to create a project: no access',
    'token.create: issued a bearer token to service:ci, reaching viewer on 1 place',
    'token.revoke: revoked a bearer token of service:ci',
    'upstream.freeze: froze the upstream credential stripe in market/prod',
    'upstream.thaw: unfroze the upstream credential stripe in market/prod',
    'token.bind: trusted tokens from https://kubernetes.acme.example to sign in as service:ci, reaching viewer on 1 place',
    'token.unbind: removed a trust binding of service:ci',
    'sign_in: signed in with github',
    'account.link: linked a github account',
    'device.start: was asked for a CLI sign-in',
    'device.approve: approved a CLI sign-in',
    'sign_in: signed in to the CLI',
    'sign_out: signed out',
    'device.start: was asked for a CLI sign-in',
    'device.deny: turned down a CLI sign-in',
    'oauth.register: registered an MCP client',
    'mcp.connect: connected an MCP client',
    'mcp.token: gave its first tokens to an MCP client',
    'mcp.ask: was asked by an MCP client for show_secret_value on market/dev/RENAMED',
    'secret.read: revealed market/dev/RENAMED',
    'mcp.approve: approved show_secret_value',
    'mcp.ask: was asked by an MCP client for request_secret_value on market/dev/ASKED',
    'mcp.deny: turned down request_secret_value',
    'mcp.ask: was asked by an MCP client for request_secret_value on market/dev/SET',
    'secret.write: added market/dev/SET, approved through MCP',
    'mcp.disconnect: disconnected an MCP client',
    'token.exchange: signed in for a CI run',
    'token.exchange: started a workload session',
    'workload.renew: renewed its workload session',
    'upkeep.expire: removed what had lapsed',
  ]);
  // Every action the vault writes, but the adoption, the first entry of a database the vault adopted (below).
  assert.deepEqual([...new Set(entries.map((entry) => entry.action))].sort(), LOG_ACTIONS.filter((action) => action !== 'vault.adopt').sort());
});

test('what an entry says follows what its detail recorded, not what was asked', async () => {
  await seed();
  const keys = (...items: KeyWrite[]) => made(app.vault.change({ ...as('cy-cli'), op: 'secret.write', project: 'market', environment: 'dev', mine: false, keys: items }));
  for (const [method, path, body] of [
    ['PATCH', '/secrets/market/dev', { A: 'a1', B: 'b1' }],
    // A nature marked in place, stricter, then looser by an Owner: its own action.
    ['PATCH', '/secrets/market/dev', { A: { sensitivity: 'sensitive' } }],
    ['PATCH', '/secrets/market/dev', { A: { sensitivity: 'secret' } }],
    // Grants: the place named is the change's, and a request that gives a role but only takes one says so.
    ['PATCH', `/access/${ed}`, { 'market/dev': 'viewer' }],
    ['PATCH', `/access/${ed}`, { 'market/dev': 'viewer', 'market/prod': 'viewer' }],
    ['PATCH', `/access/${ed}`, { 'market/dev': null, 'market/prod': 'viewer' }],
    ['PATCH', `/access/${ed}`, { 'market/dev': 'viewer', 'market/prod': null }],
    ['PATCH', `/access/${ed}`, { 'market/dev': 'viewer' }],
    // Changes that differ, given or taken, are not the first's at other places.
    ['PATCH', `/access/${ed}`, { 'market/dev': 'developer', 'market/prod': 'viewer' }],
    ['PATCH', `/access/${ed}`, { 'market/dev': null, 'market/prod': null }],
    // Dismissals: twice, then one brought back and another dismissed at once.
    ['PATCH', '/projects/market/dev/dismissals', { X: true }],
    ['PATCH', '/projects/market/dev/dismissals', { X: true }],
    ['PATCH', '/projects/market/dev/dismissals', { X: null, Y: true }],
    // A key renamed onto a name dismissed in an environment with no fork: the dismissal ends there, in no fork.
    ['PATCH', '/projects/market/dev/dismissals', { Z: true }],
  ] as const) await ok('cy-cli', method, path, body);
  // A batch that files one key and writes another; then one that files both.
  await keys({ key: 'A', folder: 'two' }, { key: 'B', value: 'b2' });
  await keys({ key: 'A', folder: 'three' }, { key: 'B', folder: 'three' });
  await ok('cy-cli', 'PATCH', '/secrets/market/dev/A', { key: 'Z' });
  // Asked, and nothing changed: a nature a key has already, here and in a personal config (named by the environment it is a config of), and renames and moves onto themselves.
  await ok('cy-cli', 'PATCH', '/secrets/market/dev', { Z: { sensitivity: 'secret' } });
  await ok('cy-cli', 'PATCH', '/secrets/market/dev@me', { P: 'p1' });
  await ok('cy-cli', 'PATCH', '/secrets/market/dev@me', { P: { sensitivity: 'secret' } });
  await ok('cy-cli', 'PATCH', '/secrets/market/dev/Z', { key: 'Z' });
  await ok('cy-cli', 'PATCH', '/folders/market/dev/three', { name: 'three' });
  await ok('cy-cli', 'PATCH', '/projects/market', { folder: 'apps' });
  await ok('cy-cli', 'PATCH', '/projects/market', { folder: 'apps' });
  await ok('cy-cli', 'PATCH', '/folders/apps', { name: 'apps' });
  // A binding is said by its profile: a CI run's, or a platform's workloads.
  const bind = (profile: string, issuer: string, claims: Record<string, unknown>, policy: Record<string, unknown> | null) =>
    made(app.vault.change({ ...as('cy-cli'), op: 'token.bind', member: 'token:ci', binding: { profile, issuer, claims, keys: { uri: `${issuer}/jwks` }, policy, scope: null, label: profile, replaces: [] } }));
  await bind('github', GITHUB, { ...MAIN, ref: 'refs/heads/release', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/release' }, null);
  await bind('kubernetes', 'https://kubernetes.acme.example', { sub: 'system:serviceaccount:ci:runner', 'kubernetes.io.serviceaccount.uid': '0c6a2b9e-4f1d-4e3a-9b7c-5d8e2f1a3b4c' }, { sessionHours: 2 });
  await sign();
  assert.deepEqual((await logged()).reverse().map((entry) => `${entry.action}: ${said(entry)}`), [
    'secret.write: added market/dev: 2 secrets',
    'secret.write: marked market/dev/A sensitive, from secret, its value kept',
    'secret.loosen: marked market/dev/A secret, from sensitive, its value kept',
    'access.grant: gave ed@acme.example viewer on market/dev',
    'access.grant: gave ed@acme.example viewer on market/prod',
    'access.grant: took viewer on market/dev from ed@acme.example',
    'access.grant: gave ed@acme.example viewer on market/dev, and 1 other change',
    'access.grant: set the access of ed@acme.example on market/dev, unchanged',
    'access.grant: gave ed@acme.example developer on market/dev, was viewer, and 1 other change',
    'access.revoke: took developer on market/dev from ed@acme.example, and 1 other change',
    'missing.dismiss: dismissed X in market/dev as not needed',
    'missing.dismiss: set which missing keys are dismissed in market/dev, unchanged',
    'missing.dismiss: dismissed Y in market/dev as not needed, and restored X to the missing keys',
    'missing.dismiss: dismissed Z in market/dev as not needed',
    'secret.write: changed market/dev: 2 secrets',
    'secret.write: moved market/dev: 2 secrets to the folder three',
    'secret.rename: renamed market/dev/A to Z',
    'secret.write: marked keys in market/dev, unchanged',
    'secret.write: added market/dev/P, in their personal config',
    'secret.write: marked keys in market/dev, in their personal config, unchanged',
    'secret.rename: renamed market/dev/Z to Z, unchanged',
    'secret.refile: moved B and Z in market/dev to the folder three, unchanged',
    'project.move: moved project market to the folder apps',
    'project.move: moved project market to the folder apps, unchanged',
    'folder.refile: renamed the folder apps to apps, 1 project, unchanged',
    'token.bind: trusted CI runs to sign in as service:ci, reaching viewer on 1 place',
    'token.bind: trusted kubernetes workloads to sign in as service:ci, reaching viewer on 1 place',
  ]);
});

/**
 * A refused change is logged once a minute per caller and action (D236): one
 * entry stands for every refusal of that kind, each asking its own key, kind
 * or direction. So it says who, what kind of change, where its own rows put
 * it, and why, and nothing any one request named.
 */
test('a refused change says what kind of change was refused, where and why, and nothing one request asked', async () => {
  await seed();
  // What Ed, a member who holds nothing, is refused: made first, by Cy.
  for (const [method, path, body] of [
    ['PATCH', '/secrets/market/dev', { A: 'a1' }],
    ['PATCH', '/secrets/market/dev/A', { folder: 'kept' }],
    ['PATCH', '/secrets/market/prod', { LINK: { ref: 'market/dev/A' } }],
    ['PATCH', '/projects/billing', { archived: true }],
    ['PUT', '/projects/market/old', {}],
    ['PATCH', '/projects/market/old', { archived: true }],
    // Ada writes in market/dev, where S is sensitive: making it a secret in place is an Owner's.
    ['PATCH', `/access/${ada}`, { 'market/dev': 'developer' }],
    ['PATCH', '/secrets/market/dev', { S: 's1' }],
    ['PATCH', '/secrets/market/dev', { S: { sensitivity: 'sensitive' } }],
  ] as const) await ok('cy-cli', method, path, body);
  assert.equal((await call('ada-cli', 'PATCH', '/secrets/market/dev', { S: { sensitivity: 'secret' } }))[0], 409);
  const token = await ok('cy-cli', 'POST', '/members/token:ci/tokens', { label: 'deploy', expiresInDays: 1 });
  for (const [method, path, body] of [
    ['PATCH', '/secrets/market/dev', { A: 'mine' }],
    ['PATCH', '/secrets/market/dev/A', { key: 'B' }],
    ['PATCH', '/folders/market/dev/kept', { name: 'filed' }],
    ['DELETE', '/secrets/market/prod/LINK/reference'],
    ['PATCH', '/projects/market/dev/dismissals', { X: null }],
    ['PUT', '/projects/shop', { name: 'Shop' }],
    ['PATCH', '/projects/market', { slug: 'mart' }],
    ['PATCH', '/projects/market', { archived: true }],
    ['PATCH', '/projects/billing', { archived: false }],
    ['PATCH', '/projects/market', { folder: 'apps' }],
    ['DELETE', '/projects/market'],
    ['PATCH', '/folders/apps', { name: 'tools' }],
    ['PUT', '/projects/market/qa', { from: 'dev' }],
    ['PATCH', '/projects/market/dev', { slug: 'development' }],
    ['PATCH', '/projects/market/dev', { archived: true }],
    ['PATCH', '/projects/market/old', { archived: false }],
    ['DELETE', '/projects/market/dev'],
    ['PATCH', '/projects/market/dev', { protected: true }],
    ['PATCH', '/projects/market/prod', { protected: false }],
    ['PUT', `/members/${ada}`, { role: 'auditor' }],
    ['DELETE', `/members/${ada}`],
    ['PATCH', `/access/${ada}`, { 'market/dev': 'developer' }],
    ['PATCH', `/access/${ada}`, { market: null }],
    ['PUT', '/roles/developer', { name: 'Developer', description: 'Writes.', permissions: ['secret.read', 'secret.use'], protected: [] }],
    ['PUT', '/settings', { serviceAccounts: { environments: { only: ['dev'] } } }],
    ['POST', '/freezes', { target: 'service:ci', reason: 'drill' }],
    ['DELETE', '/freezes/token%3Aci'],
    ['POST', '/members/token:ci/tokens', { label: 'mine', expiresInDays: 1 }],
    ['DELETE', `/members/token:ci/tokens/${token.id as string}`],
    ['DELETE', `/identities/${randomUUID()}`],
  ] as const) assert.notEqual((await call('ed-cli', method, path, body))[0], 200, `${method} ${path}`);
  const refused = async (asked: Promise<{ answer: unknown } | { refused: string }>) => assert.ok('refused' in (await asked));
  for (const op of ['upstream.freeze', 'upstream.thaw'] as const) await refused(app.vault.change({ ...as('ed-cli'), op, project: 'market', environment: 'prod', upstream: 'stripe' }));
  const kube = 'https://kubernetes.acme.example';
  await refused(app.vault.change({ ...as('ed-cli'), op: 'token.bind', member: 'token:ci', binding: { profile: 'custom', issuer: kube, claims: { sub: 'pods' }, keys: { uri: `${kube}/jwks` }, policy: null, scope: null, label: null, replaces: [] } }));
  await refused(app.vault.change({ ...as('ed-cli'), op: 'token.unbind', member: 'token:ci', binding: randomUUID() }));
  await refused(app.vault.change({ ...as('ed-cli'), op: 'account.link', account: { provider: 'github', issuer: 'https://github.com', subject: 'gh-ed-2', emails: ['ed@acme.example'] } }));
  await refused(app.vault.change({ ...as('ed-cli'), op: 'device.decide', userCode: 'BCDF-GHJK', approve: true }));
  await refused(app.vault.change({ ...as('ed-cli'), op: 'device.decide', userCode: 'BCDF-GHJK', approve: false }));
  await refused(app.vault.change({ ...as('ed-cli'), op: 'mcp.decide', approval: randomUUID(), approve: true, digest: 'a'.repeat(64) }));
  await refused(app.vault.change({ ...as('ed-cli'), op: 'mcp.decide', approval: randomUUID(), approve: false, digest: 'a'.repeat(64) }));
  await refused(app.vault.change({ ...as('ed-cli'), op: 'workload.renew' }));
  const challenge = createHash('sha256').update('verifier').digest('base64url');
  await refused(app.vault.change({ ...as('ed-cli'), op: 'mcp.connect', client: { id: randomUUID(), name: 'Zed', host: null, registration: 'dcr', redirectUri: REDIRECT }, scopes: ['read'], code: 'a'.repeat(64), challenge }));
  await sign();

  const entries = (await logged()).filter((entry) => entry.decision === 'deny').reverse();
  for (const entry of entries) {
    const { parts } = describe([entry]);
    // Its places are the entry's own rows', and no word of it is a value its detail recorded.
    assert.deepEqual(parts.filter((part) => typeof part !== 'string'), entry.project === null ? [] : [{ place: [entry.project, entry.environment].filter(Boolean).join('/') }]);
    const words = parts.filter((part) => typeof part === 'string').join('');
    const asked = Object.entries(entry.metadata).filter(([name, value]) => name !== 'refused' && typeof value === 'string').map(([, value]) => value as string);
    for (const value of asked) assert.ok(!new RegExp(`\\b${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(words), `${entry.action} says "${value}": ${plain(parts)}`);
  }
  assert.deepEqual(entries.map((entry) => `${entry.action}: ${plain(describe([entry]).parts)}`), [
    'secret.loosen: tried to make a sensitive value secret in place at market/dev: only an Owner of the project does it in place',
    'secret.write: tried to write secrets at market/dev: no access',
    'secret.rename: tried to rename a key at market/dev: no access',
    'secret.refile: tried to move keys between folders at market/dev: no access',
    'reference.break: tried to break a reference at market/prod: no access',
    'missing.dismiss: tried to change which missing keys are dismissed at market/dev: no access',
    'project.create: tried to create a project: no access',
    'project.update: tried to change a project at market: no access',
    'project.archive: tried to archive a project at market: no access',
    'project.restore: tried to restore a project at billing: no access',
    'project.move: tried to move a project between folders at market: no access',
    'project.delete: tried to delete a project at market: no access',
    'folder.refile: tried to change a folder: no access',
    'environment.create: tried to create an environment at market/dev: no access',
    'environment.update: tried to change an environment at market/dev: no access',
    'environment.archive: tried to archive an environment at market/dev: no access',
    'environment.restore: tried to restore an environment at market/old: no access',
    'environment.delete: tried to delete an environment at market/dev: no access',
    'environment.protect: tried to protect an environment at market/dev: no access',
    'environment.unprotect: tried to unprotect an environment at market/prod: no access',
    'member.add: tried to change a membership: no access',
    'member.remove: tried to remove a member: no access',
    'access.grant: tried to change access at market/dev: no access',
    'access.revoke: tried to take away access at market: no access',
    'policy.change: tried to change a role: no access',
    'settings.change: tried to change where people set up service accounts: no access',
    'workload.freeze: tried to freeze workloads: no access',
    'workload.unfreeze: tried to unfreeze workloads: no access',
    'token.create: tried to issue a credential: no access',
    'token.revoke: tried to end a credential: unknown credential',
    'account.unlink: tried to unlink a sign-in account: unknown identity',
    'upstream.freeze: tried to freeze an upstream credential at market/prod: no access',
    'upstream.thaw: tried to unfreeze an upstream credential at market/prod: no access',
    'token.bind: tried to change a trust binding: no access',
    'token.unbind: tried to remove a trust binding: no access',
    'account.link: tried to link a sign-in account: no access',
    'device.approve: tried to approve a CLI sign-in: unknown code',
    'device.deny: tried to turn down a CLI sign-in: unknown code',
    'mcp.approve: tried to approve a change asked through MCP: no access',
    'mcp.deny: tried to turn down a change asked through MCP: no access',
    'workload.renew: tried to renew a workload session: unauthenticated',
    'mcp.connect: tried to connect an MCP client: unknown client',
  ]);
  // A batch that holds a refusal says and counts what was done, and the refusal after it.
  const done = (await logged()).find((entry) => entry.action === 'secret.write' && entry.decision !== 'deny')!;
  const denied = entries.find((entry) => entry.action === 'secret.write')!;
  assert.equal(plain(describe([denied, done]).parts), `${plain(describe([done]).parts)}, 1 refused: no access`);
  // Every action a caller who stands can be refused: the others are never refused one, or logged.
  // A refused use is not logged (D236); every membership refused is logged as an addition; nobody who stands is refused their own sign-out.
  const never = ['secret.read', 'member.restore', 'member.role', 'sign_in', 'sign_out', 'device.start', 'token.exchange', 'oauth.register', 'mcp.token', 'mcp.ask', 'mcp.disconnect', 'upkeep.expire', 'vault.adopt'];
  assert.deepEqual([...new Set(entries.map((entry) => entry.action))].sort(), LOG_ACTIONS.filter((action) => !never.includes(action)).sort());
});

test("a database the vault adopted begins its log with the adoption's entry", async () => {
  await adoptFresh(world, ['cy@acme.example']);
  await write(world, ...rows('credentials', credential('cy-cli', cy)));
  await sign();
  const entries = await logged('cy-cli');
  assert.deepEqual(entries.map((entry) => `${entry.action}: ${said(entry)}`), ['vault.adopt: started the log']);
});
