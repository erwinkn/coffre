// What anyone on the network sees of an instance, checked as no one: that
// it is up, its headers, every route refusing a caller with no credential
// and saying nothing more, a change from another site's page refused, and
// no page showing anything. `coffre verify instance` runs these first.
import { Unreachable, type AuthInfo } from '@coffre/client';
import { everyRoute } from '@coffre/client/routes';

import { expect, type Checks } from './checks.ts';

/** The page anyone may open. Every other page sends no one to /login. */
export const OPEN_PAGES = ['/login'];
/** The pages behind sign-in, whatever the instance holds. */
export const CLOSED_PAGES = [
  '/',
  '/account',
  '/audit',
  '/auth/device',
  '/settings',
  '/projects',
  '/users',
  '/service-accounts',
  '/unregistered',
];

/** A made-up place and member, which no instance has. */
export const NOWHERE = { project: 'conformance-nowhere', environment: 'none' };
export const NOBODY = 'token:conformance-nobody';

/** The checks anyone can run: no sign-in, nothing written. */
export async function anonymousChecks(report: Checks, origin: string): Promise<void> {
  // One this machine cannot reach: health says why, and the rest would only say it again.
  let instance: string | undefined = origin;
  await report.check('health', {}, () =>
    reachable(origin).catch((error: unknown) => {
      if (error instanceof Unreachable) instance = undefined;
      throw error;
    }),
  );
  await report.check('headers', { instance }, () => headers(origin));
  await report.check('anonymous api', { instance }, () => anonymousApi(origin));
  await report.check('forged cross-site', { instance }, () => forgedCrossSite(origin));
  await report.check('sign-in info', { instance }, () => signinInfo(origin));
  await report.check('anonymous answers', { instance }, () => anonymousAnswers(origin));
}

// --- as no one ----------------------------------------------------------------

/** An instance someone else runs: up, and its scheduled job beating. */
export async function reachable(origin: string): Promise<string> {
  const live = await fetch(`${origin}/livez`).catch((error: unknown) => {
    throw new Unreachable(origin, error);
  });
  expect(live.ok, `/livez answered ${live.status}`);
  const ready = await fetch(`${origin}/readyz`);
  expect(ready.ok, `/readyz answered ${ready.status}: is the scheduled job running?`, await ready.text());
  return '/livez and /readyz';
}

export async function headers(origin: string): Promise<string> {
  const anonymous = await fetch(`${origin}/api/me`);
  expect(anonymous.status === 401, `/api/me answered ${anonymous.status} to no one`);
  securityHeaders(anonymous, 'a refusal');

  const login = await fetch(`${origin}/login`);
  expect(login.status === 200, `/login answered ${login.status}`);
  const csp = securityHeaders(login, '/login');
  const html = await login.text();
  const nonce = /'nonce-([^']+)'/.exec(csp)![1];
  expect(html.includes(`nonce="${nonce}"`), "/login's scripts do not carry the policy's nonce");
  const again = securityHeaders(await fetch(`${origin}/login`), '/login');
  expect(!again.includes(`'nonce-${nonce}'`), 'two pages were served with the same nonce');
  const asset = /\/_coffre\/assets\/[\w.-]+\.js/.exec(html)?.[0];
  expect(asset !== undefined, '/login loads no script from /_coffre/assets/', html.slice(0, 2000));
  const script = await fetch(`${origin}${asset}`);
  expect(
    script.ok && /javascript/.test(script.headers.get('content-type') ?? ''),
    `${asset} answered ${script.status} ${script.headers.get('content-type')}`,
  );

  // No other site's page may read an answer: no CORS for anyone.
  const foreign = await fetch(`${origin}/api/me`, { headers: { origin: 'https://attacker.example' } });
  const allowed = foreign.headers.get('access-control-allow-origin');
  expect(allowed === null, `the API allows another origin to read it: ${allowed}`);
  return `a fresh CSP nonce per page, frames refused, nosniff; no CORS; ${asset} served`;
}

function securityHeaders(response: Response, what: string): string {
  const csp = response.headers.get('content-security-policy') ?? '';
  expect(/script-src 'self' 'nonce-[^']+'/.test(csp), `${what}: no nonce-based script-src`, csp);
  expect(csp.includes("frame-ancestors 'none'"), `${what}: frames not refused`, csp);
  expect(response.headers.get('x-content-type-options') === 'nosniff', `${what}: no nosniff`);
  expect(response.headers.get('x-frame-options') === 'DENY', `${what}: no x-frame-options DENY`);
  expect(response.headers.get('cross-origin-resource-policy') === 'same-origin', `${what}: other sites may embed it`);
  expect(/no-store/.test(response.headers.get('cache-control') ?? ''), `${what}: may be cached`);
  if (response.url.startsWith('https:')) {
    const hsts = response.headers.get('strict-transport-security') ?? '';
    expect(/max-age=\d{7,}/.test(hsts), `${what}: no strict-transport-security for months or more`, hsts);
  }
  return csp;
}

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
