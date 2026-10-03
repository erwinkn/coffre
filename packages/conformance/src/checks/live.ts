// What can be checked of an instance that is already running, from outside
// and without writing anything: as no one, and with a service token the
// operator set up for it, which reads one canary. The local run takes the
// same checks against the deployment it booted, so they run in CI too.
//
// Each run with a token adds a few entries to the instance's audit log,
// which is append-only, so they stay: the canary's read, and the reads it
// was refused. It changes nothing else.
import { CoffreError, type AuthInfo, type CoffreClient } from '@coffre/client';

import { bearer } from '../browser.ts';
import { expect, refused, Skip, type Report } from '../report.ts';
import { everyRoute, getCalls, getUrls } from '../routes.ts';
import { headers, reachable } from './surface.ts';

/** The page anyone may open. Every other page sends no one to /login. */
const OPEN_PAGES = ['/login'];
/** The pages behind sign-in, whatever the instance holds. */
const CLOSED_PAGES = [
  '/',
  '/account',
  '/access',
  '/audit',
  '/auth/device',
  '/settings',
  '/projects',
  '/users',
  '/tokens',
  '/unregistered',
];

/** A made-up place and member, which no instance has. */
const NOWHERE = { project: 'conformance-nowhere', environment: 'none' };
const NOBODY = 'token:conformance-nobody';

/** A secret the operator set up, and its value, for the token to read and to look for. */
export type Canary = { project: string; environment: string; key: string; value: string };

/** Parse `<project>/<environment>/<KEY>=<value>`, or the path alone with the value given apart. */
export function parseCanary(text: string, value?: string): Canary {
  const at = text.indexOf('=');
  const path = at === -1 ? text : text.slice(0, at);
  const given = at === -1 ? value : text.slice(at + 1);
  const parts = path.split('/');
  if (parts.length !== 3 || parts.some((part) => part === '')) {
    throw new Error(`the canary is <project>/<environment>/<KEY>, not "${path}"`);
  }
  if (given === undefined || given === '') throw new Error('the canary has no value: pass it after =, on stdin, or in COFFRE_CONFORMANCE_CANARY');
  const [project, environment, key] = parts as [string, string, string];
  return { project, environment, key, value: given };
}

/** The checks anyone can run: no sign-in, nothing written. `health` false when the caller checked it already. */
export async function anonymousChecks(report: Report, origin: string, options: { health: boolean }): Promise<void> {
  if (options.health) await report.check('health', {}, () => reachable(origin));
  await report.check('headers', {}, () => headers(origin));
  await report.check('anonymous api', {}, () => anonymousApi(origin));
  await report.check('forged cross-site', {}, () => forgedCrossSite(origin));
  await report.check('sign-in info', {}, () => signinInfo(origin));
  await report.check('anonymous answers', {}, () => anonymousAnswers(origin));
}

/** The checks with a service token that reads the canary, and audits its project. `prefix` names them apart, run twice. */
export async function tokenChecks(report: Report, origin: string, setup: { token?: string; canary?: Canary }, prefix = ''): Promise<void> {
  const api = setup.token === undefined ? undefined : bearer(origin, setup.token);
  const token = await report.check(`${prefix}token`, { api, canary: setup.canary }, ({ api, canary }) => whoIsToken(origin, api, canary));
  const needs = { api, canary: setup.canary, token, secret: setup.token };
  await report.check(`${prefix}token reveal`, needs, ({ api, canary, token }) => tokenReveal(api, canary, token));
  await report.check(`${prefix}token scan`, needs, ({ canary, secret }) => tokenScan(origin, secret, canary));
  await report.check(`${prefix}token scope`, needs, ({ api, canary }) => tokenScope(api, canary));
  await report.check(`${prefix}token verification`, { api }, ({ api }) => tokenVerification(api));
}

// --- as no one ----------------------------------------------------------------

/** Every route, whatever its method, turns away a caller with no credential, and says nothing else. */
async function anonymousApi(origin: string): Promise<string> {
  const routes = everyRoute(origin);
  for (const { key, method, url } of routes) {
    const response = await fetch(url, {
      method,
      headers: { 'content-type': 'application/json' },
      body: method === 'GET' ? undefined : '{}',
    });
    const text = await response.text();
    expect(response.status === 401, `${key} answered ${response.status} to no one`, text);
    expect(onlyRefusal(text), `${key} refused no one with more than a refusal`, text);
  }
  return `${routes.length} routes, every method: 401, and nothing but the refusal`;
}

/**
 * A change sent with a session cookie from another site's page is refused
 * before the cookie is even looked at, so a made-up one shows it: a real
 * cookie would get the same answer. Behind Cloudflare Access the same holds
 * for its cookie and assertion.
 */
async function forgedCrossSite(origin: string): Promise<string> {
  const changes = everyRoute(origin).filter((route) => route.method !== 'GET');
  const forged = {
    cookie: 'coffre_session=conformance-forged; __Host-coffre_session=conformance-forged; CF_Authorization=conformance-forged',
    'cf-access-jwt-assertion': 'conformance-forged',
    origin: 'https://attacker.example',
    'sec-fetch-site': 'cross-site',
    'content-type': 'application/json',
  };
  for (const { key, method, url } of [...changes, { key: 'POST /auth/signout', method: 'POST', url: `${origin}/auth/signout` }]) {
    const response = await fetch(url, { method, headers: forged, body: '{}', redirect: 'manual' });
    const text = await response.text();
    expect(response.status === 403, `${key} from another site answered ${response.status}`, text);
  }
  return `${changes.length + 1} changes, sign-out included, from another site with a session cookie: 403`;
}

/** `GET /api/auth` names how to sign in, and nothing more. */
async function signinInfo(origin: string): Promise<string> {
  const response = await fetch(`${origin}/api/auth`);
  expect(response.ok, `/api/auth answered ${response.status}`);
  const info = (await response.json()) as AuthInfo;
  expect(sameKeys(info, ['access', 'signin']), '/api/auth says more than how to sign in', info);
  expect((info.signin === null) !== (info.access === null), '/api/auth names neither or both ways in', info);
  if (info.access !== null) {
    expect(sameKeys(info.access, ['assertion']) && info.access.assertion === false, '/api/auth says more of Access than whether it vouched', info);
    return 'Cloudflare Access, and nothing more';
  }
  const signin = info.signin!;
  expect(sameKeys(signin, ['note', 'providers', 'title']), '/api/auth says more of its sign-in than a page needs', signin);
  for (const provider of signin.providers) {
    expect(sameKeys(provider, ['brand', 'id', 'label']), `/api/auth says more of ${provider.id} than its button`, provider);
  }
  return `coffre's sign-in through ${signin.providers.map((provider) => provider.id).join(', ')}, and nothing more`;
}

/**
 * Nothing that could be a stored value in what no one is shown. Without a
 * canary this is a best effort: the API's refusals are checked to be only
 * refusals above, every closed page must send no one to /login with an
 * empty body, and the open pages must carry no credential coffre issues.
 */
async function anonymousAnswers(origin: string): Promise<string> {
  const pages = [...CLOSED_PAGES, `/projects/${NOWHERE.project}`, `/projects/${NOWHERE.project}/${NOWHERE.environment}`];
  for (const path of pages) {
    // Followed by hand, on this origin only, each hop without a body.
    let at = path;
    for (let hop = 0; at !== '/login'; hop++) {
      const response = await fetch(`${origin}${at}`, { redirect: 'manual' });
      const text = await response.text();
      const to = new URL(response.headers.get('location') ?? at, origin);
      expect(
        hop < 3 && response.status >= 300 && response.status < 400 && to.origin === origin,
        `${at} answered no one ${response.status}${response.headers.has('location') ? ` to ${to.href}` : ''}, not a redirect on to /login`,
        text.slice(0, 2000),
      );
      expect(text.trim().length < 512, `${at} sent no one a body with its redirect`, text.slice(0, 2000));
      at = to.pathname;
    }
  }
  for (const path of OPEN_PAGES) {
    const response = await fetch(`${origin}${path}`, { redirect: 'manual' });
    const text = await response.text();
    expect(response.status === 200, `${path} answered ${response.status}`);
    const issued = /coffre_(svc|cli|web)_[A-Za-z0-9_-]{20,}/.exec(text);
    expect(issued === null, `${path} carries a credential coffre issues`, issued?.[0]);
  }
  return `best effort, without a canary: ${pages.length} closed pages send no one to /login with nothing else; /login carries no credential`;
}

// --- with a token ---------------------------------------------------------------

type Token = { member: string };

/** The token is a service's, and reads the canary's environment. */
async function whoIsToken(origin: string, api: CoffreClient, canary: Canary): Promise<{ detail: string; value: Token }> {
  const auth = (await (await fetch(`${origin}/api/auth`)).json()) as AuthInfo;
  if (auth.signin === null) throw new Skip("behind Cloudflare Access, coffre issues no service tokens: the token's checks need coffre's own sign-in");
  const me = await api.me();
  expect(me.principal.type === 'service', `the token is ${me.principal.type}:${me.principal.id}'s, not a service's`);
  const member = `token:${me.principal.id}`;
  const place = `${canary.project}/${canary.environment}`;
  const reads = me.environments.find((env) => `${env.project}/${env.environment}` === place);
  expect(reads?.permissions.includes('secret.read'), `${member} cannot read ${place}`, me.environments);
  const { keys } = await api.secrets.list(place);
  expect(keys.some((key) => key.key === canary.key), `${place} holds no ${canary.key}`, keys.map((key) => key.key));
  return { detail: `${member}, reading ${place}`, value: { member } };
}

/** Reveal the canary once, and find its `secret.read` in the audit log, by the reveal's request. */
async function tokenReveal(api: CoffreClient, canary: Canary, token: Token): Promise<string> {
  const path = `${canary.project}/${canary.environment}`;
  const { operationId, values } = await api.secrets.reveal(`${path}/${canary.key}`);
  expect(values[canary.key] === canary.value, `${path}/${canary.key} is not the value given as the canary`);
  let entries;
  try {
    ({ entries } = await api.audit.list({ path, actor: token.member, limit: 50 }));
  } catch (error) {
    if (error instanceof CoffreError && error.status === 403) {
      throw new Skip(`the token holds no audit.read on ${canary.project}, so the reveal's entry cannot be looked for`);
    }
    throw error;
  }
  const read = entries.filter((entry) => entry.operationId === operationId);
  expect(read.length === 1, `the reveal is logged ${read.length} times, not once`, entries.slice(0, 5));
  const [entry] = read as [(typeof read)[number]];
  expect(
    entry.action === 'secret.read' && entry.decision === 'allow' && entry.key === canary.key && entry.requestId !== null,
    "the reveal's entry is not an allowed read of the canary, under a request",
    entry,
  );
  return `one secret.read of ${canary.key}, entry ${entry.seq}, under request ${entry.requestId}`;
}

/**
 * The canary's value, in any answer to a GET route as the token or as no
 * one, or in any page. The reveal is the only answer allowed to carry it.
 */
async function tokenScan(origin: string, token: string, canary: Canary): Promise<string> {
  const api = bearer(origin, token);
  const me = await api.me();
  const member = `token:${me.principal.id}`;
  const listed = me.environments.map(({ project, environment }) => ({ project, environment }));
  const places = [...listed, NOWHERE];
  const calls = getCalls({
    places,
    secrets: [{ project: canary.project, environment: canary.environment, key: canary.key }, { ...NOWHERE, key: 'NONE' }],
    members: [member, NOBODY, 'user:nobody@conformance.example'],
    services: [member, NOBODY],
  });
  const forms = [canary.value, Buffer.from(canary.value).toString('base64'), Buffer.from(canary.value).toString('hex')];
  const leaks: string[] = [];
  const callers: [string, Record<string, string>][] = [
    ['the token', { authorization: `Bearer ${token}` }],
    ['no one', {}],
  ];
  let answers = 0;
  const look = async (what: string, url: string, headers: Record<string, string>) => {
    const text = await (await fetch(url, { headers, redirect: 'manual' })).text();
    answers++;
    if (forms.some((form) => text.includes(form))) leaks.push(what);
  };
  for (const { key, url } of getUrls(origin, calls)) {
    for (const [name, headers] of callers) await look(`${key} as ${name}`, url, headers);
  }
  const pages = [
    ...OPEN_PAGES,
    ...CLOSED_PAGES,
    ...listed.flatMap(({ project, environment }) => [`/projects/${project}`, `/projects/${project}/${environment}`]),
  ];
  for (const path of new Set(pages)) {
    for (const [name, headers] of callers) await look(`the page ${path} as ${name}`, `${origin}${path}`, headers);
  }
  expect(leaks.length === 0, "the canary's value was found outside its reveal", leaks);
  return `${answers} answers from ${Object.keys(calls).length} GET routes and ${new Set(pages).size} pages, as the token and as no one: no value`;
}

/** The token reaches the canary's project and nothing else: not another environment, project or member. */
async function tokenScope(api: CoffreClient, canary: Canary): Promise<string> {
  const { projects } = await api.projects.list();
  const seen = projects.map((project) => project.slug);
  expect(seen.length === 1 && seen[0] === canary.project, `the token sees ${seen.join(', ') || 'no project'}, not only ${canary.project}`);
  const me = await api.me();
  const own = `${canary.project}/${canary.environment}`;
  const reads = me.environments.filter((env) => env.permissions.includes('secret.read')).map((env) => `${env.project}/${env.environment}`);
  expect(reads.length === 1 && reads[0] === own, `the token reads ${reads.join(', ')}, not only ${own}`);
  const more = [...new Set(me.environments.flatMap((env) => env.permissions))].filter(
    (permission) => permission !== 'secret.read' && permission !== 'audit.read',
  );
  expect(more.length === 0, `the token holds more than reading: ${more.join(', ')}`);

  const others = projects[0]!.environments.map((env) => `${canary.project}/${env.slug}`).filter((path) => path !== own);
  const nowhere = `${NOWHERE.project}/${NOWHERE.environment}`;
  let refusals = 0;
  for (const path of [...others, nowhere]) {
    await refused(`the token listed ${path}`, api.secrets.list(path));
    await refused(`the token revealed ${path}`, api.secrets.reveal(path));
    await refused(`the token read ${path}'s syncs`, api.syncs.list(path));
    refusals += 3;
  }
  // Its project's log is the token's to read, as `audit.read` there; another's is not.
  await refused(`the token read ${nowhere}'s audit`, api.audit.list({ path: nowhere, limit: 1 }));
  await refused('the token listed the members', api.members.list());
  await refused(`the token read ${NOBODY}`, api.members.get(NOBODY));
  refusals += 3;
  try {
    const { entries } = await api.audit.list({ limit: 500 });
    const outside = entries.filter((entry) => entry.project !== null && entry.project !== canary.project);
    expect(outside.length === 0, `the token reads audit entries about ${[...new Set(outside.map((entry) => entry.project))].join(', ')}`);
  } catch (error) {
    if (!(error instanceof CoffreError && error.status === 403)) throw error;
  }
  const elsewhere = others.length === 0 ? 'no other environment' : `${others.length} other environment${others.length === 1 ? '' : 's'}`;
  return `only ${own}; ${refusals} reads elsewhere refused: ${elsewhere} of ${canary.project}, a made-up place, the members`;
}

async function tokenVerification(api: CoffreClient): Promise<string> {
  let verified;
  try {
    verified = await api.audit.verify();
  } catch (error) {
    if (error instanceof CoffreError && error.status === 403) {
      throw new Skip('verification is for owners and root admins, which this token is not: not checked');
    }
    throw error;
  }
  expect(verified.ok, 'the audit log does not verify', verified);
  return `${verified.entries} entries verify, through entry ${verified.through}`;
}

// --- helpers --------------------------------------------------------------------

/** `{ error, message }` and nothing else. */
function onlyRefusal(text: string): boolean {
  try {
    return sameKeys(JSON.parse(text), ['error', 'message']);
  } catch {
    return false;
  }
}

function sameKeys(value: unknown, keys: string[]): boolean {
  return typeof value === 'object' && value !== null && JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
}
