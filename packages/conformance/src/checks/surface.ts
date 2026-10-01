// What anyone on the network sees: health, and the headers that keep a
// page from being framed, sniffed or made to run someone else's script.
// These need no sign-in, so `probe` runs them against any instance.
import type { Deployment } from '../harness.ts';
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

/** An instance someone else runs: up, and its scheduled job beating. */
export async function reachable(origin: string): Promise<string> {
  const live = await fetch(`${origin}/livez`);
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
