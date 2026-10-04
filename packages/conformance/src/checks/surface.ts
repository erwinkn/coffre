// Health: up, and ready only once the scheduled job has beaten and the
// vault has checkpointed it. What else anyone on the network sees, its
// headers among it, `coffre verify instance` checks, here as anywhere.
import { clientFiles, serverCodeIn } from '../bundle.ts';
import type { Deployment } from '../harness.ts';
import type { Person } from './people.ts';
import { expect, until } from '../report.ts';

export async function health(deployment: Deployment): Promise<string> {
  const { origin } = deployment;
  const live = await fetch(`${origin}/livez`);
  expect(live.ok, `/livez answered ${live.status}`);
  // Readiness follows the audit heartbeat and the vault's checkpoint of it,
  // which only the scheduled job writes: not ready until it has run.
  if (deployment.beforeFirstBeat) {
    const early = await fetch(`${origin}/readyz`);
    expect(early.status === 503, `/readyz answered ${early.status} before any heartbeat`, await early.text());
    await deployment.scheduled();
  }
  await until('/readyz', async () => (await fetch(`${origin}/readyz`)).ok, 20);
  const ready = (await (await fetch(`${origin}/readyz`)).json()) as { checkpointed?: unknown };
  expect(ready.checkpointed === true, '/readyz passed without a checkpoint covering the heartbeat', ready);
  return deployment.beforeFirstBeat ? '/livez, and /readyz only once the heartbeat ran and was checkpointed' : '/livez and /readyz';
}

/** The headers coffre sets on everything it answers, but the policy, whose nonce is each response's own. */
const SECURED: Record<string, string> = {
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
};

/**
 * coffre's security headers on every kind of response the app gives, each
 * with a policy whose nonce is its own: pages, signed out and signed in, a
 * page's redirect to sign in, a page not found, the API's answers and its
 * refusals, a refusal of a body it never reads, sign-in's redirect to the
 * provider, and health. What answers each, Start's render or one of coffre's
 * server routes, all go through coffre's middleware; one it missed would
 * lack them.
 */
export async function headers(deployment: Deployment, admin: Person): Promise<string> {
  const anonymous = (path: string, init: RequestInit = {}) => fetch(`${deployment.origin}${path}`, { redirect: 'manual', ...init });
  const kinds: [string, () => Promise<Response>][] = [
    ['the sign-in page', () => anonymous('/login')],
    ['a signed-in page', () => admin.browser.fetch('/projects')],
    ["a page's redirect to sign in", () => anonymous('/projects')],
    ['a page not found', () => anonymous('/no-such-page')],
    ['an API read', () => admin.browser.fetch('/api/me')],
    ['an API refusal', () => anonymous('/api/me')],
    ['a path under /api that is not one', () => anonymous('/api/no-such-thing')],
    ['a refused method, its body unread', () => anonymous('/livez', { method: 'POST', body: 'x'.repeat(64 * 1024) })],
    ["sign-in's redirect to the provider", () => anonymous('/auth/signin/github')],
    ['a path under /auth that is not one', () => anonymous('/auth/no-such-step')],
    ['/livez', () => anonymous('/livez')],
    ['/readyz', () => anonymous('/readyz')],
  ];
  const nonces = new Set<string>();
  for (const [kind, request] of kinds) {
    const response = await request();
    await response.body?.cancel();
    const seen = Object.fromEntries(response.headers);
    for (const [name, value] of Object.entries(SECURED)) {
      expect(response.headers.get(name) === value, `${kind} (${response.status}) has ${name}: ${response.headers.get(name) ?? 'none'}, not ${value}`, seen);
    }
    expect(response.headers.has('cache-control'), `${kind} (${response.status}) has no cache-control`, seen);
    const nonce = /script-src 'self' 'nonce-([^']+)'/.exec(response.headers.get('content-security-policy') ?? '')?.[1];
    expect(nonce !== undefined, `${kind} (${response.status}) has no nonce-based Content-Security-Policy`, seen);
    expect(!nonces.has(nonce), `${kind} (${response.status}) has the nonce of an earlier response`, seen);
    nonces.add(nonce);
  }
  return `${kinds.length} kinds of response, each with coffre's headers and a nonce of its own`;
}

/**
 * Nothing of the server in what the browser loads: the database layer, a
 * driver, a table only the server knows, a `COFFRE_*` read. Read from the
 * client files the app's own build wrote, as the browser gets them.
 */
export async function browserBundle(deployment: Deployment): Promise<string> {
  const files = clientFiles(deployment.clientDir);
  expect(files.length > 0, `no client files in ${deployment.clientDir}`);
  const found = serverCodeIn(files);
  expect(found.length === 0, 'what the browser loads holds server code: a page imports something of the server', found.join('\n'));
  return `${files.length} files the browser loads, none with server code in it`;
}
