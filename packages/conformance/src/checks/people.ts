// Who the checks act as, and the project they act on. Each value set here
// is a canary: random, and never to be seen again outside a reveal.
import { randomBytes } from 'node:crypto';

import type { CoffreClient } from '@coffre/client';

import { bearer, Browser } from '../browser.ts';
import type { Deployment } from '../harness.ts';
import { expect } from '../report.ts';

export const PROJECT = 'conformance';
export const DEV = `${PROJECT}/dev`;
export const PROD = `${PROJECT}/prod`;
export const BULK = `${PROJECT}/bulk`;
export const SERVICE = 'token:conformance-ci';
/** Where the live checks' token reads, as an operator would set it up. */
export const LIVE = `${PROJECT}/live`;
export const LIVE_SERVICE = 'token:conformance-live';

export type Person = { email: string; member: string; browser: Browser; api: CoffreClient };

export type People = {
  admin: Person;
  /** A viewer on dev, and nothing else. */
  reader: Person;
  /** A developer on dev, signed in in a browser and in the CLI; offboarded along the way. */
  leaver: Person & { cli: CoffreClient; cliToken: string };
  /** A service, viewer on dev, with a token; offboarded along the way. */
  service: { member: string; token: string; api: CoffreClient };
  /** Never admitted. */
  stranger: { email: string; browser: Browser };
  /** A viewer on bulk, where there are more values than the bulk limit allows at once. */
  bulk: Person;
};

/** Every value set, by `project/environment/KEY`. */
export type Canaries = Record<string, string>;

export function canary(): string {
  return `coffre-canary-${randomBytes(12).toString('hex')}`;
}

/**
 * Sign in the way a browser does: to the stand-in GitHub, which asks for no
 * password, and back. The error is the one coffre sent the browser back to
 * /login with.
 */
export async function signIn(
  deployment: Deployment,
  browser: Browser,
  email: string,
): Promise<{ ok: true } | { ok: false; error: string; location: string }> {
  const leave = await browser.fetch('/auth/signin/github');
  const authorize = new URL(leave.headers.get('location') ?? '', deployment.origin);
  expect(
    leave.status === 302 && authorize.origin === deployment.idp.origin,
    'sign-in did not send the browser to GitHub',
    `${leave.status} ${leave.headers.get('location')}`,
  );
  const form = new URLSearchParams(authorize.searchParams);
  form.set('email', email);
  const approve = await fetch(authorize.origin + authorize.pathname, { method: 'POST', body: form, redirect: 'manual' });
  const callback = approve.headers.get('location') ?? '';
  expect(
    approve.status === 302 && callback.startsWith(`${deployment.origin}/auth/callback/github?`),
    'GitHub did not send the browser back',
    callback,
  );
  const back = await browser.fetch(callback);
  expect(back.status === 302 || back.status === 303, `the callback answered ${back.status}`, await back.text());
  const location = new URL(back.headers.get('location') ?? '/', deployment.origin);
  const error = location.searchParams.get('error');
  return error === null ? { ok: true } : { ok: false, error, location: `${location.pathname}${location.search}` };
}

export async function signInAdmin(deployment: Deployment) {
  const browser = new Browser(deployment.origin);
  const signed = await signIn(deployment, browser, deployment.rootAdmin);
  expect(signed.ok, `the root admin was refused: ${'error' in signed ? signed.error : ''}`);
  const api = browser.client();
  const me = await api.me();
  expect(me.principal.id === deployment.rootAdmin && me.isRootAdmin, 'signed in as someone else', me);
  const admin: Person = { email: deployment.rootAdmin, member: `user:${deployment.rootAdmin}`, browser, api };
  return { detail: `${admin.email}, root admin, through GitHub`, value: admin };
}

export async function setUp(admin: Person) {
  await admin.api.projects.create(PROJECT, { name: 'Conformance' });
  for (const [path, name] of [
    [DEV, 'Development'],
    [PROD, 'Production'],
    [BULK, 'Bulk'],
  ] as const) {
    await admin.api.environments.create(path, { name });
  }
  const canaries: Canaries = {
    [`${DEV}/API_KEY`]: canary(),
    [`${DEV}/DATABASE_URL`]: canary(),
    [`${PROD}/API_KEY`]: canary(),
  };
  for (const path of [DEV, PROD]) await admin.api.secrets.set(path, valuesIn(canaries, path));
  return { detail: `${PROJECT}: dev and prod, ${Object.keys(canaries).length} values, and bulk`, value: canaries };
}

/**
 * What `probe --token` asks an operator for: an environment holding one
 * canary, and a service that reads it there and audits the project. Its
 * value joins the others, for the scans that follow.
 */
export async function setUpLive(admin: Person, canaries: Canaries) {
  await admin.api.environments.create(LIVE, { name: 'Live' });
  const value = canary();
  await admin.api.secrets.set(LIVE, { CANARY: value });
  canaries[`${LIVE}/CANARY`] = value;
  await admin.api.members.add(LIVE_SERVICE);
  await admin.api.access.set(LIVE_SERVICE, { [LIVE]: 'viewer', [PROJECT]: 'auditor' });
  const { token } = await admin.api.tokens.issue(LIVE_SERVICE, { label: 'conformance live', expiresInDays: 1 });
  return {
    detail: `${LIVE}/CANARY, and ${LIVE_SERVICE}: viewer there, auditor on ${PROJECT}`,
    value: { token, canary: { project: PROJECT, environment: 'live', key: 'CANARY', value } },
  };
}

/** The canaries in one environment, by key. */
export function valuesIn(canaries: Canaries, environment: string): Record<string, string> {
  return Object.fromEntries(
    Object.entries(canaries)
      .filter(([path]) => path.startsWith(`${environment}/`))
      .map(([path, value]) => [path.slice(environment.length + 1), value]),
  );
}

/** A person the admin admits with this access, signed in in a browser of their own. */
export async function personaOn(deployment: Deployment, admin: Person, name: string, access: Record<string, 'viewer' | 'developer' | 'maintainer'>): Promise<Person> {
  const email = `${name}@conformance.example`;
  const member = `user:${email}`;
  await admin.api.members.add(member);
  await admin.api.access.set(member, access);
  const browser = new Browser(deployment.origin);
  const signed = await signIn(deployment, browser, email);
  expect(signed.ok, `${email} was refused: ${'error' in signed ? signed.error : ''}`);
  return { email, member, browser, api: browser.client() };
}

export async function personas(deployment: Deployment, admin: Person) {
  const person = (name: string, access: Record<string, 'viewer' | 'developer'>) => personaOn(deployment, admin, name, access);

  const reader = await person('reader', { [DEV]: 'viewer' });
  const leaver = await person('leaver', { [DEV]: 'developer' });
  const bulk = await person('bulk', { [BULK]: 'viewer' });

  await admin.api.members.add(SERVICE);
  await admin.api.access.set(SERVICE, { [DEV]: 'viewer' });
  const issued = await admin.api.tokens.issue(SERVICE, { label: 'conformance', expiresInDays: 1 });
  const cliToken = await deviceLogin(deployment, leaver.browser);

  const people: People = {
    admin,
    reader,
    leaver: { ...leaver, cli: bearer(deployment.origin, cliToken), cliToken },
    service: { member: SERVICE, token: issued.token, api: bearer(deployment.origin, issued.token) },
    stranger: { email: 'stranger@conformance.example', browser: new Browser(deployment.origin) },
    bulk,
  };
  return {
    detail: 'a reader, a leaver in a browser and the CLI, a bulk reader, a service with a token, and a stranger',
    value: people,
  };
}

/** `coffre login`: a device code, approved in a signed-in browser, for a CLI session. */
async function deviceLogin(deployment: Deployment, browser: Browser): Promise<string> {
  const json = { 'content-type': 'application/json' };
  const started = await fetch(`${deployment.origin}/api/auth/device`, {
    method: 'POST',
    headers: json,
    body: JSON.stringify({ client_label: 'coffre-conformance' }),
  });
  expect(started.ok, `the device login did not start: ${started.status}`, await started.clone().text());
  const device = (await started.json()) as { device_code: string; user_code: string };
  await browser.client().deviceLogins.decide(device.user_code, true);
  const polled = await fetch(`${deployment.origin}/api/auth/device/token`, {
    method: 'POST',
    headers: json,
    body: JSON.stringify({ device_code: device.device_code }),
  });
  const session = (await polled.json()) as { access_token?: string };
  expect(polled.ok && session.access_token, `the approved device login gave no token: ${polled.status}`, session);
  return session.access_token;
}

/**
 * A page's worth of API calls at once, as the pages fire them on a load,
 * right after sign-in, while the vault is fresh: every one answers. A call
 * that waited on another's work in the vault would be cancelled on
 * Cloudflare as hung, and the page would read the 503 or 401 as signed out.
 */
export async function pageLoad(person: Person): Promise<string> {
  const paths = ['/api/me', '/api/sessions', '/api/projects', '/api/members', '/api/audit', '/api/identities', '/api/me', '/api/projects'];
  const statuses = await Promise.all(paths.map(async (path) => [path, (await person.browser.fetch(path)).status] as const));
  const failed = statuses.filter(([, status]) => status !== 200);
  expect(failed.length === 0, 'a call of the page load did not answer 200', failed.map(([path, status]) => `${path}: ${status}`).join(', '));
  return `${paths.length} calls at once, each answered`;
}
