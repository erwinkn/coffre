import { DEVICE_TTL_SECONDS } from '@coffre/core/access';
import {
  ACCESS_JWT_HEADER,
  generateToken,
  hashToken,
  seal,
  SigninError,
  unseal,
  type AuthConfig,
  type PendingSignin,
  type SigninConfig,
  type SigninProfile,
  type SigninProvider,
} from '@coffre/core/identity';
import { emailAddress } from '@coffre/core/schemas';
import type { Account, Answers, Asked, Change, Refused } from '@coffre/core/vault';
import { z } from 'zod';

import { ApiError, noteTampered, notFound, refusal } from './api/errors.ts';
import { readCookie, sessionCookie, sessionCookieName, presented } from './auth.ts';
import type { Admission } from './behind-access.ts';
import { waitingDeviceLogins } from './db/queries/signin.ts';
import { apiCredential, isSameOrigin } from './fetch-api.ts';
import { errorResponse, jsonResponse, readJson } from './http.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';

/**
 * Sign-in's paths outside the API (docs/design/0.16.md, "Signing in from
 * the server"): the browser's round trip through a provider under `/auth`,
 * signing out, the device login's two calls under `/api/auth`, and what
 * the sign-in page reads first. The app does what only it can: run the
 * provider's flow, draw tokens and codes, set cookies, and count the device
 * logins strangers start. Each decision is the vault's, in the one change
 * a request asks of it.
 */

export function callbackUrl(config: SigninConfig, providerId: string): string {
  return `${config.publicUrl}/auth/callback/${providerId}`;
}

function secure(auth: AuthConfig): boolean {
  // Behind Access every request is HTTPS.
  return auth.mode === 'cloudflare' || auth.signin.publicUrl.startsWith('https:');
}

export function pendingCookieName(auth: AuthConfig): string {
  return secure(auth) ? '__Host-coffre_signin' : 'coffre_signin';
}

export function cookieHeader(
  auth: AuthConfig,
  name: string,
  value: string,
  maxAgeSeconds: number,
): string {
  return [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    // Lax, not Strict: the provider's redirect back is a cross-site
    // top-level navigation, and it must carry the pending-state cookie.
    'SameSite=Lax',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
    ...(secure(auth) ? ['Secure'] : []),
  ].join('; ');
}

export function clearCookieHeader(auth: AuthConfig, name: string): string {
  return cookieHeader(auth, name, '', 0);
}

/**
 * A path on this origin, or `/projects`. `next` arrives in a query string,
 * so anything that could leave the origin (`//evil`, `/\evil`, a full URL)
 * is refused rather than repaired, before the URL parser resolves its dot
 * segments and after: `/.//evil` comes out `//evil`, another host to a browser.
 */
export function safeNext(raw: string | null, publicUrl: string): string {
  if (raw === null || !raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) {
    return '/projects';
  }
  try {
    const url = new URL(raw, publicUrl);
    if (url.origin !== new URL(publicUrl).origin || url.pathname.startsWith('//')) return '/projects';
    if (url.pathname === '/login' || url.pathname.startsWith('/auth/signin/')) return '/projects';
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/projects';
  }
}

export function redirectResponse(location: string, cookies: string[] = [], status = 302): Response {
  const headers = new Headers({ location, 'cache-control': 'no-store' });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(null, { status, headers });
}

/** "Firefox on macOS", from a User-Agent, for the session list. Best effort by design. */
export function describeUserAgent(userAgent: string | null): string | null {
  if (userAgent === null || userAgent === '') return null;
  const browser =
    /Edg\//.test(userAgent) ? 'Edge'
    : /Firefox\//.test(userAgent) ? 'Firefox'
    : /Chrome\//.test(userAgent) ? 'Chrome'
    : /Safari\//.test(userAgent) ? 'Safari'
    : null;
  const system =
    /Windows/.test(userAgent) ? 'Windows'
    : /iPhone|iPad/.test(userAgent) ? 'iOS'
    : /Mac OS X/.test(userAgent) ? 'macOS'
    : /Android/.test(userAgent) ? 'Android'
    : /Linux/.test(userAgent) ? 'Linux'
    : null;
  if (browser === null && system === null) return userAgent.slice(0, 60);
  return [browser ?? 'Browser', system].filter(Boolean).join(' on ');
}

/** Configured providers as the pages show them: no client ids, no secrets. */
export function publicProviders(config: SigninConfig) {
  return config.providers.map(({ id, label, brand }) => ({ id, label, brand }));
}

/** `access`: behind Cloudflare Access, the session the request was admitted with (`admit`). */
type Path = (request: Request, runtime: CoffreRuntime, sourceIp: string | null, track?: unknown, access?: Admission) => Promise<Response>;

/** A session's lifetime as the vault takes it, in whole minutes: the configuration's may be a fraction of an hour or a day. */
const minutesOf = (minutes: number) => Math.max(1, Math.round(minutes));

/** A token as the vault knows it: its SHA-256, lowercase hex. */
const hashed = (token: string) => hashToken(token).toString('hex');

/** A change of the vault's, by the path that asks it: its answer, or its refusal. */
async function ask<O extends Change['op']>(runtime: CoffreRuntime, change: Asked<O>): Promise<{ answer: Answers[O] } | Refused> {
  return runtime.vault.change<O>(change);
}

/**
 * A refusal a path does not word itself, answered as the API answers it,
 * with `cookies` set on it: a fault, `tampered` (said once in the server's
 * log) or `adopting`, or a refusal no request of this path could cause.
 */
function refused(route: string, request: string | null, code: string, cookies: string[] = []): Response {
  const error = refusal(code);
  noteTampered(error, route, request);
  const response = errorResponse(error);
  for (const cookie of cookies) response.headers.append('set-cookie', cookie);
  return response;
}

/**
 * GET /api/auth: how this instance signs people in, which the sign-in
 * page, the account page and the CLI read before anyone is signed in.
 * Exactly one is set.
 */
export type AuthInfo = {
  signin: { title: string; note: string | null; providers: ReturnType<typeof publicProviders> } | null;
  access: { assertion: boolean } | null;
};

export const describeSignin: Path = async (request, runtime) => {
  const { auth } = runtime;
  const info: AuthInfo = {
    signin: auth.mode === 'signin' ? { title: auth.signin.page.title, note: auth.signin.page.note, providers: publicProviders(auth.signin) } : null,
    access: auth.mode === 'cloudflare' ? { assertion: (request.headers.get(ACCESS_JWT_HEADER) ?? '').trim() !== '' } : null,
  };
  return jsonResponse(info);
};

/** What rides in the sealed cookie between leaving for the provider and coming back. */
type Pending = PendingSignin & {
  /** The provider it left for: the callback must come back from the same one. */
  provider: string;
  /** Where to land afterwards: a path on this origin. */
  next: string;
  /** Linking: the SHA-256 of the session that asked to add this account, which must be the one that comes back. */
  link: string | null;
};

/** How long a sign-in may stay at its provider. */
const PENDING_TTL_SECONDS = 10 * 60;

/** The paths of a provider's round trip: `/auth/signin/github`, `/auth/callback/github`. */
export const PROVIDER_PATH = /^\/auth\/(signin|callback)\/([a-z0-9-]{1,32})$/;

/**
 * GET /auth/signin/:provider: leave for the provider. `?next=` is where to
 * land afterwards; `?link=1` adds the account to the signed-in person
 * instead of signing in with it, on the session that asked, which the
 * callback holds it to.
 */
export async function startSignin(request: Request, runtime: CoffreRuntime, providerId: string): Promise<Response> {
  const { auth } = runtime;
  if (auth.mode !== 'signin') return redirectResponse('/login');
  const url = new URL(request.url);
  const linking = url.searchParams.get('link') === '1';
  const back = linking ? '/account' : '/login';
  const provider = auth.signin.providers.find((candidate) => candidate.id === providerId);
  if (provider === undefined) return redirectResponse(`${back}?error=unknown_provider`);
  let link: string | null = null;
  if (linking) {
    const session = sessionCookie(request, auth);
    if (session === null) return redirectResponse('/login?next=/account');
    link = hashed(session);
  }
  let started;
  try {
    started = await provider.start(callbackUrl(auth.signin, provider.id));
  } catch (error) {
    if (!(error instanceof SigninError)) console.error('sign-in start failed', logged(error));
    return redirectResponse(`${back}?error=provider_unavailable`);
  }
  const pending: Pending = {
    state: started.pending.state,
    codeVerifier: started.pending.codeVerifier,
    nonce: started.pending.nonce,
    provider: provider.id,
    next: linking ? '/account' : safeNext(url.searchParams.get('next'), auth.signin.publicUrl),
    link,
  };
  return redirectResponse(started.url.href, [cookieHeader(auth, pendingCookieName(auth), seal(runtime.signinKey, pending, PENDING_TTL_SECONDS), PENDING_TTL_SECONDS)]);
}

/**
 * GET /auth/callback/:provider: back from the provider. Every way out clears
 * the pending cookie, so a callback cannot be replayed, and every refusal
 * lands on a page that says it in words (`?error=`), but a fault's.
 *
 * One call to the vault, and no statement of the app's: `account.link` on
 * the session that asked, when the pending cookie says link; `signin`
 * otherwise, which ends the session the browser showed, if any, in the
 * same change (`replaces`).
 */
export async function finishSignin(request: Request, runtime: CoffreRuntime, sourceIp: string | null, providerId: string): Promise<Response> {
  const { auth } = runtime;
  if (auth.mode !== 'signin') return redirectResponse('/login');
  const clearPending = clearCookieHeader(auth, pendingCookieName(auth));
  const pending = unseal<Pending>(runtime.signinKey, readCookie(request, pendingCookieName(auth)));
  const back = pending?.link != null ? '/account' : '/login';
  const fail = (code: string) => redirectResponse(`${back}?${new URLSearchParams({ error: code })}`, [clearPending]);

  if (pending === null || pending.provider !== providerId) return fail('state_mismatch');
  const provider = auth.signin.providers.find((candidate) => candidate.id === providerId);
  if (provider === undefined) return fail('unknown_provider');
  let account: Account;
  try {
    account = accountOf(provider, await provider.finish(new URL(request.url), callbackUrl(auth.signin, provider.id), pending));
  } catch (error) {
    // The person sees a sentence; the operator needs the reason. Provider messages name the step that failed and never carry tokens or codes.
    if (error instanceof SigninError) {
      if (error.code === 'provider_unavailable' || error.code === 'invalid_response') console.warn(`sign-in with ${provider.id} failed: ${error.message}`, logged(error.cause) ?? '');
      return fail(error.code);
    }
    console.error('sign-in callback failed', logged(error));
    return fail('provider_unavailable');
  }

  // The provider has spent its code: a fault from here on clears the pending cookie too, as every other way out does.
  try {
    const route = `GET /auth/callback/${provider.id}`;
    const session = sessionCookie(request, auth);
    if (pending.link !== null) {
      // The session that asked, and no other: one signed out and back in as someone else meanwhile links nothing.
      if (session === null || hashed(session) !== pending.link) return fail('link_session');
      const shown = presented(session, sourceIp);
      const linked = await ask<'account.link'>(runtime, { ...shown, op: 'account.link', account });
      if (!('refused' in linked)) return redirectResponse(`/account?${new URLSearchParams({ linked: provider.id })}`, [clearPending]);
      if (linked.refused === 'unauthenticated' || linked.refused === 'no_access') return fail('link_session');
      if (linked.refused === 'already_linked') return fail('already_linked');
      return refused(route, shown.request, linked.refused, [clearPending]);
    }

    const token = generateToken('browser');
    const trace = { request: crypto.randomUUID(), ip: sourceIp };
    const signedIn = await ask<'signin'>(runtime, {
      ...trace,
      op: 'signin',
      account,
      session: { token: hashed(token), minutes: minutesOf(auth.signin.browserSessionHours * 60), label: describeUserAgent(request.headers.get('user-agent')) },
      // Signing in again on the same browser ends the session it had, rather than leaving it alive until it expires.
      replaces: session === null ? null : hashed(session),
    });
    if ('refused' in signedIn) {
      const code = signedIn.refused;
      if (code === 'not_registered') return fail(account.emails.length === 0 ? 'no_verified_email' : code);
      if (code === 'deactivated' || code === 'account_mismatch') return fail(code);
      return refused(route, trace.request, code, [clearPending]);
    }
    const maxAge = (Date.parse(signedIn.answer.expiresAt) - Date.now()) / 1000;
    return redirectResponse(pending.next, [clearPending, cookieHeader(auth, sessionCookieName(auth), token, maxAge)]);
  } catch (error) {
    const response = errorResponse(error);
    response.headers.append('set-cookie', clearPending);
    return response;
  }
}

/** The most addresses an account is sent with, its primary first: what the vault takes. */
const MAX_EMAILS = 20;

/**
 * What the provider vouched for, as the vault takes it: under the id coffre
 * knows the provider by, so a provider cannot pass its accounts off as
 * another's, and its issuer as 0.14 kept it, hashed, so an account bound
 * before the upgrade is the same account after it. The profile is checked
 * as well, since a deployment's own provider is typed, not trusted.
 */
function accountOf(provider: SigninProvider, profile: SigninProfile): Account {
  const { subject, emails } = profile ?? {};
  if (typeof subject !== 'string' || subject.length === 0 || subject.length > 255 || !Array.isArray(emails)) {
    throw new SigninError('invalid_response', `sign-in provider ${provider.id} returned a malformed profile`);
  }
  const addresses = emails
    .filter((email): email is string => typeof email === 'string')
    .map((email) => email.trim().toLowerCase())
    .filter((email) => emailAddress.safeParse(email).success);
  return { provider: provider.id, issuer: hashed(provider.issuer), subject, emails: [...new Set(addresses)].slice(0, MAX_EMAILS) };
}

/**
 * POST /auth/signout: end this browser's session, and clear its cookie. A
 * POST from coffre's own pages, so a link or an image elsewhere cannot sign
 * anyone out. A session that no longer stands is signed out already.
 * Behind Access it ends coffre's session, then sends the browser on to
 * Access's logout, which ends Access's: without it, the next request would
 * sign in again.
 */
export const signOut: Path = async (request, runtime, sourceIp, _track, access) => {
  const { auth } = runtime;
  const behindAccess = auth.mode === 'cloudflare';
  // Behind Access the check's cookies are the response's (`respond`): ending them clears both, whatever it set.
  access?.ended();
  const clear = behindAccess ? [] : [clearCookieHeader(auth, sessionCookieName(auth))];
  const session = behindAccess ? (access?.session ?? null) : sessionCookie(request, auth);
  if (session !== null) {
    const shown = presented(session, sourceIp);
    const ended = await ask<'credential.end'>(runtime, { ...shown, op: 'credential.end', credential: null, of: null });
    if ('refused' in ended && ended.refused !== 'unauthenticated') return refused('POST /auth/signout', shown.request, ended.refused, clear);
  }
  return redirectResponse(behindAccess ? '/cdn-cgi/access/logout' : '/login', clear, 303);
};

/**
 * POST /api/auth/logout: end the credential the request carries, `coffre
 * logout`: a bearer token, or the browser's session from coffre's own
 * pages. One that no longer stands is signed out already. Behind Access,
 * the browser's session alone (`apiCredential`).
 */
export const logout: Path = async (request, runtime, sourceIp, _track, access) => {
  try {
    const credential = apiCredential(request, runtime.auth, access);
    if (credential === null) throw new ApiError('unauthenticated', access?.why ?? 'sign in first');
    if (credential.ambient && !isSameOrigin(request, runtime.publicUrl)) throw new ApiError('cross_origin', 'a change sent with a browser session must come from coffre itself');
    // Behind Access, both cookies cleared, in place of any the check set (`ended`).
    access?.ended();
    const shown = presented(credential.token, sourceIp);
    const ended = await ask<'credential.end'>(runtime, { ...shown, op: 'credential.end', credential: null, of: null });
    if ('refused' in ended && ended.refused !== 'unauthenticated') return refused('POST /api/auth/logout', shown.request, ended.refused);
    return jsonResponse({ signedOut: true });
  } catch (error) {
    return errorResponse(error);
  }
};

/** A device login's body carries a short label or a device code, nothing more: read in at most this many bytes, as anyone may call it. */
const DEVICE_BODY_BYTES = 4 * 1024;
// A label is text the vault keeps: well-formed, no NUL (`text` in @coffre/vault).
const deviceStart = z.object({ client_label: z.string().trim().max(120).refine((label) => Buffer.from(label).toString() === label && !label.includes('\0'), 'the label is not text').optional() });
const devicePoll = z.object({ device_code: z.string().min(1).max(128) });

/** How often the CLI polls (RFC 8628's `interval`), in seconds. */
const DEVICE_POLL_SECONDS = 5;
/** The most device logins that wait for a decision at once, from one address and from all: a flood makes `coffre login` wait, and never grows the table without bound. */
const DEVICE_WAITING_PER_IP = 5;
const DEVICE_WAITING = 200;
/** Codes drawn again when the vault finds one taken, before the app gives up: a collision is all but impossible. */
const DEVICE_DRAWS = 4;

/** No vowels, so a code never spells a word; no 0/O or 1/I lookalikes (`USER_CODE` in @coffre/core/access). */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

function userCode(): string {
  const chars: string[] = [];
  while (chars.length < 8) {
    for (const byte of crypto.getRandomValues(new Uint8Array(16))) {
      // 240 is the largest multiple of 20 below 256: no modulo bias.
      if (byte < 240 && chars.length < 8) chars.push(USER_CODE_ALPHABET[byte % 20]!);
    }
  }
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
}

/** Accept a user code as a person types it: any case, with or without the dash. Null for one that cannot be a code. */
export function normalizeUserCode(input: string): string | null {
  const letters = input.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length !== 8 || [...letters].some((c) => !USER_CODE_ALPHABET.includes(c))) return null;
  return `${letters.slice(0, 4)}-${letters.slice(4)}`;
}

/**
 * POST /api/auth/device: start a device login (RFC 8628), `coffre login`.
 * The CLI gets a code for a person to approve in a signed-in browser, and
 * a device code to poll with. Anyone may call it, so before it asks the
 * vault to write anything it counts the logins waiting, in one statement:
 * 5 from one address and 200 in all at most. The count takes no lock, so
 * a burst of simultaneous requests can overshoot it by a few.
 */
export const startDevice: Path = async (request, runtime, sourceIp) => {
  const { auth } = runtime;
  if (auth.mode !== 'signin') return errorResponse(notFound('device login needs signin mode'));
  try {
    const input = deviceStart.parse(await readJson(request, DEVICE_BODY_BYTES, {}));
    const waiting = await waitingDeviceLogins(runtime.db, sourceIp, new Date());
    if (waiting.here >= DEVICE_WAITING_PER_IP || waiting.all >= DEVICE_WAITING) {
      return jsonResponse({ error: 'slow_down', message: 'too many sign-in requests are waiting; try again in a few minutes' }, 429);
    }
    const trace = { request: crypto.randomUUID(), ip: sourceIp };
    for (let draw = 0; draw < DEVICE_DRAWS; draw += 1) {
      const deviceCode = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
      const code = userCode();
      const started = await ask<'device.start'>(runtime, { ...trace, op: 'device.start', code: hashed(deviceCode), userCode: code, label: input.client_label || null });
      if ('refused' in started) {
        if (started.refused === 'taken') continue;
        return refused('POST /api/auth/device', trace.request, started.refused);
      }
      const verificationUri = `${auth.signin.publicUrl}/auth/device`;
      return jsonResponse({
        device_code: deviceCode,
        user_code: code,
        verification_uri: verificationUri,
        verification_uri_complete: `${verificationUri}?code=${code}`,
        expires_in: DEVICE_TTL_SECONDS,
        interval: DEVICE_POLL_SECONDS,
      });
    }
    throw new ApiError('unavailable', 'coffre could not draw a free code; try again');
  } catch (error) {
    return errorResponse(error);
  }
};

/** RFC 8628's words for a poll that collects nothing yet, or never will. */
const POLLED: Record<string, string> = { pending: 'authorization_pending', denied: 'access_denied', expired: 'expired_token' };

/**
 * POST /api/auth/device/token: the CLI's poll. Its errors are RFC 8628's,
 * so any device-flow client understands them; once a person approved it,
 * the CLI collects a session of theirs, once.
 */
export const pollDevice: Path = async (request, runtime, sourceIp) => {
  const { auth } = runtime;
  if (auth.mode !== 'signin') return errorResponse(notFound('device login needs signin mode'));
  try {
    const { device_code } = devicePoll.parse(await readJson(request, DEVICE_BODY_BYTES));
    const token = generateToken('cli');
    const trace = { request: crypto.randomUUID(), ip: sourceIp };
    const redeemed = await ask<'device.redeem'>(runtime, { ...trace, op: 'device.redeem', code: hashed(device_code), session: { token: hashed(token), minutes: minutesOf(auth.signin.cliSessionDays * 24 * 60) } });
    if ('refused' in redeemed) {
      const polled = POLLED[redeemed.refused];
      return polled === undefined ? refused('POST /api/auth/device/token', trace.request, redeemed.refused) : jsonResponse({ error: polled }, 400);
    }
    const { principal, expiresAt } = redeemed.answer;
    return jsonResponse({ access_token: token, token_type: 'Bearer', expires_at: expiresAt, principal: { type: 'user', id: principal.slice(principal.indexOf(':') + 1) } });
  } catch (error) {
    return errorResponse(error);
  }
};
