// A browser at a deployment of coffre's, through its own routes, as passkeys.md's flows go (sections 3.1 and 6.5): to a
// provider of the test's own and back, the passkey page's question and its answer, made by a software authenticator.
// Shared by the suites of signing in with a passkey and of the fresh check.
import assert from 'node:assert/strict';

import { SoftAuthenticator, type Tweak } from '@coffre/conformance/authenticator';
import { defineSignin, SigninError, type PasskeysOptions, type SigninProvider } from '@coffre/core/identity';
import type { Vault } from '@coffre/core/vault';

import { SigninService } from '../src/api/signin.ts';
import { coffreRoute } from '../src/app.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import { waitUntil, type FixtureDeps } from './api-fixture.ts';

export const ORIGIN = 'https://secrets.acme.example';

/** A provider of the test's own: it asks nothing, and vouches for the email the callback names. */
export function provider(issuer = 'https://idp.acme.example'): SigninProvider {
  return {
    id: 'acme',
    issuer,
    label: 'Acme',
    brand: 'oidc',
    start: async () => ({ url: new URL(`${issuer}/authorize`), pending: { state: 'state', codeVerifier: 'verifier', nonce: null } }),
    finish: async (callback) => {
      const email = callback.searchParams.get('email');
      if (email === null) throw new SigninError('provider_denied', 'no email');
      return { subject: email, emails: [email], name: callback.searchParams.get('name') ?? email.split('@')[0]! };
    },
  };
}

/** The deployment of `deps` under `passkeys`: its runtime, which answers coffre's own routes. */
export function signinDeployment(deps: FixtureDeps, passkeys: PasskeysOptions, issuer?: string, vault: Vault = deps.vault) {
  const config = defineSignin({ publicUrl: ORIGIN, providers: [provider(issuer)], passkeys });
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault, signin: config });
  return {
    db: deps.db, vault, chainKey: deps.chainKey, previousChainKeys: [], signin, workloads: null, mcp: null,
    auth: { mode: 'signin', signin: config }, publicUrl: ORIGIN, verifier: signin, waitUntil,
    schema: { migrated: true }, appKey: { settled: true }, rotateAfterDays: 365, plugins: [],
  } as unknown as CoffreRuntime;
}

/** A browser at the deployment: its cookies, and its requests, which coffre's routes answer. */
export class Browser {
  readonly jar = new Map<string, string>();
  runtime: CoffreRuntime;

  constructor(runtime: CoffreRuntime) {
    this.runtime = runtime;
  }

  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.jar.size > 0) headers.set('cookie', [...this.jar].map(([name, value]) => `${name}=${value}`).join('; '));
    if (init.method === 'POST') headers.set('origin', ORIGIN);
    const response = await coffreRoute(new Request(new URL(path, ORIGIN), { ...init, headers }), this.runtime, null);
    assert.ok(response !== null, `${path} is coffre's`);
    for (const cookie of response.headers.getSetCookie()) {
      const [pair = ''] = cookie.split(';');
      const at = pair.indexOf('=');
      if (/max-age=0/i.test(cookie) || pair.slice(at + 1) === '') this.jar.delete(pair.slice(0, at));
      else this.jar.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return response;
  }

  get session(): string | undefined {
    return this.jar.get('__Host-coffre_session');
  }

  /** To the provider and back: where the callback sends the browser. */
  async provider(email: string): Promise<string> {
    const leave = await this.fetch('/auth/signin/acme?next=/projects/market');
    assert.equal(leave.status, 302);
    const back = await this.fetch(`/auth/callback/acme?email=${encodeURIComponent(email)}`);
    assert.equal(back.status, 302, await back.clone().text());
    return back.headers.get('location')!;
  }

  /** What the passkey page asks for. */
  async step(query = ''): Promise<{ status: number; body: any }> {
    const response = await this.fetch(`/api/auth/passkey${query}`);
    return { status: response.status, body: await response.json() };
  }

  /** The page's answer. */
  async answer(body: unknown): Promise<{ status: number; body: any }> {
    const response = await this.fetch('/api/auth/passkey', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }
}

export const RP = { rpId: 'secrets.acme.example', origin: ORIGIN };
export const bytes = (value: string) => new Uint8Array(Buffer.from(value, 'base64url'));

/** `create()` of a step's options, answered by `key`: the page's answer, with the step's sealed user handle. */
export async function register(key: SoftAuthenticator, step: any, tweak?: Tweak) {
  const response = await key.register({ ...RP, challenge: bytes(step.options.challenge), userHandle: bytes(step.options.user.id) }, tweak);
  return { response, state: step.state };
}

/** `get()`, answered by `key`. */
export function assertion(key: SoftAuthenticator, options: any, tweak?: Tweak) {
  return key.assert({ ...RP, challenge: bytes(options.challenge) }, tweak);
}

/** Sign in as `email`, adding `key` as their first passkey on the way: the browser, with its session. */
export async function enroll(runtime: CoffreRuntime, email: string, key: SoftAuthenticator): Promise<Browser> {
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(email), '/auth/passkey');
  const step = await browser.step();
  assert.equal(step.body.purpose, 'enroll');
  const done = await browser.answer(await register(key, step.body));
  assert.deepEqual(done, { status: 200, body: { next: '/projects/market' } });
  return browser;
}

/** Sign in as `email` with a touch of `key`. */
export async function touch(runtime: CoffreRuntime, email: string, key: SoftAuthenticator): Promise<Browser> {
  const browser = new Browser(runtime);
  assert.equal(await browser.provider(email), '/auth/passkey');
  const step = await browser.step();
  assert.equal(step.body.purpose, 'signin');
  assert.deepEqual(await browser.answer({ response: await assertion(key, step.body.options) }), { status: 200, body: { next: '/projects/market' } });
  return browser;
}

/** What `/api/me` answers the browser: 200, or the error's code. */
export async function me(browser: Browser): Promise<string> {
  const response = await browser.fetch('/api/me');
  return response.ok ? 'ok' : ((await response.json()) as { error: string }).error;
}
