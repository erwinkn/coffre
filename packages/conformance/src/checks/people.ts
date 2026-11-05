// Who the checks act as, and the project they act on. Each value set here
// is a canary: random, and never to be seen again outside a reveal.
import { randomBytes } from 'node:crypto';

import { CoffreError, type CoffreClient } from '@coffre/client';

import { SoftAuthenticator } from '../authenticator.ts';
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
  start = '/auth/signin/github',
): Promise<{ ok: true } | { ok: false; error: string; location: string }> {
  const leave = await browser.fetch(start);
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
  if (location.pathname === '/auth/passkey') return passkeyStep(deployment, browser, email);
  const error = location.searchParams.get('error');
  return error === null ? { ok: true } : { ok: false, error, location: `${location.pathname}${location.search}` };
}

/** Each person's passkey, once coffre had them add one: the same browser's authenticator, whichever browser signs in. */
const passkeys = new Map<string, SoftAuthenticator>();

/** Whose passkey each browser signed in with. */
const holders = new WeakMap<Browser, string>();

/** A touch an act carries (docs/design/passkeys.md, section 4.2), as coffre's pages send it. */
export type Touch = { state: string; response: Record<string, unknown> };

/**
 * An act that takes a touch of its own (docs/design/passkeys.md, section 4.2: approving a terminal, an MCP client's
 * change or its connection), done as coffre's pages do it: sent, and refused `403 touch_required`, sent again with a
 * touch of the passkey the browser signed in with, for the challenge the refusal carries. A person who holds none is
 * asked nothing.
 */
export async function touching<T>(browser: Browser, send: (touch?: Touch) => Promise<T>): Promise<T> {
  try {
    return await send();
  } catch (error) {
    if (!(error instanceof CoffreError) || error.code !== 'touch_required' || error.touch === undefined) throw error;
    const key = passkeys.get(holders.get(browser) ?? '');
    expect(key !== undefined, 'coffre asked a touch of a browser that signed in with no passkey');
    const { challenge } = error.touch.options as { challenge: string };
    const response = await key!.assert({ rpId: new URL(browser.origin).hostname, origin: browser.origin, challenge: new Uint8Array(Buffer.from(challenge, 'base64url')) });
    return send({ state: error.touch.state, response: response as unknown as Record<string, unknown> });
  }
}

/**
 * The passkey a sign-in waits for after the provider (docs/design/passkeys.md, section 3.1), as coffre's page asks the
 * browser for it: a new one, kept, for a person who must add one (an Owner under `optional`); else a touch of theirs.
 */
async function passkeyStep(deployment: Deployment, browser: Browser, email: string): Promise<{ ok: true } | { ok: false; error: string; location: string }> {
  const asked = await browser.fetch('/api/auth/passkey');
  expect(asked.ok, 'the passkey page had nothing to ask', await asked.clone().text());
  const { purpose, options, state } = (await asked.json()) as { purpose: string; options: { challenge: string; user?: { id: string } }; state?: string };
  const ceremony = { rpId: new URL(deployment.origin).hostname, origin: deployment.origin, challenge: new Uint8Array(Buffer.from(options.challenge, 'base64url')) };
  let response;
  if (purpose === 'enroll') {
    const key = await SoftAuthenticator.create('ES256');
    response = await key.register({ ...ceremony, userHandle: new Uint8Array(Buffer.from(options.user!.id, 'base64url')) });
    passkeys.set(email, key);
  } else {
    const key = passkeys.get(email);
    expect(key !== undefined, `${email} holds a passkey conformance never added`);
    response = await key!.assert(ceremony);
  }
  // A new passkey goes back with its sealed `state`, the user handle its options were drawn with.
  const answered = await browser.send('POST', '/api/auth/passkey', { response, ...(state === undefined ? {} : { state }) });
  if (answered.ok) {
    holders.set(browser, email);
    browser.confirm = () => stepUp(deployment, browser, email);
    return { ok: true };
  }
  const { error } = (await answered.json()) as { error: string };
  return { ok: false, error, location: '/auth/passkey' };
}

/**
 * `person` signed in again to add a first passkey, as coffre's dialog sends someone who holds none (`?passkey=add`,
 * docs/design/passkeys.md, section 3.4): what an act a fresh check guards takes of a person who is not an Owner, under
 * `optional`. It ends every other credential of theirs no passkey confirmed (section 3.3).
 */
export async function withPasskey(deployment: Deployment, person: Person): Promise<void> {
  const signed = await signIn(deployment, person.browser, person.email, '/auth/signin/github?passkey=add');
  expect(signed.ok, `${person.email} could not add a passkey: ${'error' in signed ? signed.error : ''}`);
  expect(passkeys.has(person.email), `${person.email} signed in again and was asked for no new passkey`);
}

/**
 * A fresh check, as coffre's dialog asks it (docs/design/passkeys.md, section 3.4): a touch of `email`'s passkey at the
 * step-up's door, whose answer replaces the browser's session with one confirmed now.
 */
async function stepUp(deployment: Deployment, browser: Browser, email: string): Promise<void> {
  const asked = await browser.fetch('/api/auth/passkey?step-up=1&next=/projects');
  expect(asked.ok, 'the step-up had nothing to ask', await asked.clone().text());
  const { options, state } = (await asked.json()) as { options: { challenge: string }; state: string };
  const key = passkeys.get(email);
  expect(key !== undefined, `${email} holds a passkey conformance never added`);
  const response = await key!.assert({ rpId: new URL(deployment.origin).hostname, origin: deployment.origin, challenge: new Uint8Array(Buffer.from(options.challenge, 'base64url')) });
  const answered = await browser.send('POST', '/api/auth/passkey', { state, response });
  expect(answered.ok, 'the step-up refused the touch', await answered.clone().text());
}

export async function signInAdmin(deployment: Deployment) {
  const browser = new Browser(deployment.origin);
  const signed = await signIn(deployment, browser, deployment.owner);
  expect(signed.ok, `the bootstrap Owner was refused: ${'error' in signed ? signed.error : ''}`);
  const api = browser.client();
  const me = await api.me();
  // Signing in first, with no Owner yet, made them the instance's Owner.
  expect(me.principal.id === deployment.owner && me.instanceRole === 'owner' && me.runsInstance, 'signed in as someone else, or not as the Owner', me);
  const admin: Person = { email: deployment.owner, member: `user:${deployment.owner}`, browser, api };
  return { detail: `${admin.email}, the bootstrap Owner, through GitHub`, value: admin };
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
export async function deviceLogin(deployment: Deployment, browser: Browser): Promise<string> {
  const json = { 'content-type': 'application/json' };
  const started = await fetch(`${deployment.origin}/api/auth/device`, {
    method: 'POST',
    headers: json,
    body: JSON.stringify({ client_label: 'coffre-conformance' }),
  });
  expect(started.ok, `the device login did not start: ${started.status}`, await started.clone().text());
  const device = (await started.json()) as { device_code: string; user_code: string };
  await touching(browser, (touch) => browser.client().deviceLogins.decide(device.user_code, true, touch));
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
