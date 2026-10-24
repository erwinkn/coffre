import { SigninError, verifyProof, type SigninProfile } from '@coffre/core/identity';
import { emailAddress } from '@coffre/core/schemas';
import { z } from 'zod';

import { ApiError, notFound } from './api/errors.ts';
import type { SignedInAccount } from './api/signin.ts';
import { ExchangeRefused, type WorkloadService } from './api/workloads.ts';
import {
  accessTokenForRequest,
  authenticateRequest,
  bearerToken,
  readCookie,
  sessionCookieName,
  type AuthenticatedIdentity,
} from './auth.ts';
import { dpopToken, SessionRefused, signedUrl, standingSession } from './workload-sessions.ts';
import { apiCaller } from './fetch-api.ts';
import { errorResponse, jsonResponse, readJson, readLimitedJson } from './http.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';
import {
  callbackUrl,
  clearCookieHeader,
  cookieHeader,
  describeUserAgent,
  pendingCookieName,
  redirectResponse,
  safeNext,
} from './signin.ts';

// Sign-in's own routes: the device flow under `/api/auth`, and the browser's
// round trips under `/auth`. `app.ts` routes to them and checks the method,
// and the origin of every browser post.

/**
 * Who a browser request is from, if anyone: the sign-in routes that need a
 * session (linking an account, signing out) check it themselves. A session
 * that is expired or revoked counts as none.
 */
async function browserIdentity(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
): Promise<AuthenticatedIdentity | null> {
  const token = accessTokenForRequest(request, runtime.auth);
  if (token === null) return null;
  const identity = await authenticateRequest(request, runtime, crypto.randomUUID(), token, sourceIp);
  return identity instanceof Response ? null : identity;
}

/** A device-login body carries a short label or a device code, nothing more: it is read in at most this many bytes, as anyone may call it. */
const DEVICE_BODY_BYTES = 4 * 1024;
const deviceStart = z.object({ client_label: z.string().trim().max(120).optional() });

/**
 * POST /api/auth/device: start a device login (RFC 8628). The CLI gets a
 * code for the person to approve in a signed-in browser, and a device code
 * to poll with.
 */
export async function startDevice(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  if (runtime.signin === null) return errorResponse(notFound('device login needs signin mode'));
  try {
    const input = deviceStart.parse(await readJson(request, DEVICE_BODY_BYTES, {}));
    const started = await runtime.signin.startDevice({ clientLabel: input.client_label ?? null, sourceIp });
    return jsonResponse({
      device_code: started.deviceCode,
      user_code: started.userCode,
      verification_uri: started.verificationUri,
      verification_uri_complete: started.verificationUriComplete,
      expires_in: started.expiresIn,
      interval: started.interval,
    });
  } catch (error) {
    if (error instanceof ApiError && error.code === 'too_many_requests') {
      return jsonResponse({ error: 'slow_down', message: error.message }, 429);
    }
    return errorResponse(error);
  }
}

const devicePoll = z.object({ device_code: z.string().min(1).max(128) });

/**
 * POST /api/auth/device/token: the CLI's poll. Errors use RFC 8628's names
 * so any device-flow client understands them; success returns a CLI session
 * token, once.
 */
export async function pollDevice(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  if (runtime.signin === null) return errorResponse(notFound('device login needs signin mode'));
  try {
    const { device_code } = devicePoll.parse(await readJson(request, DEVICE_BODY_BYTES));
    const polled = await runtime.signin.pollDevice(device_code, { requestId: crypto.randomUUID(), sourceIp });
    switch (polled.status) {
      case 'pending':
        return jsonResponse({ error: 'authorization_pending' }, 400);
      case 'denied':
        return jsonResponse({ error: 'access_denied' }, 400);
      case 'expired':
        return jsonResponse({ error: 'expired_token' }, 400);
      case 'approved':
        return jsonResponse({
          access_token: polled.credential.token,
          token_type: 'Bearer',
          expires_at: polled.credential.expiresAt,
          principal: polled.principal,
        });
    }
  } catch (error) {
    return errorResponse(error);
  }
}

/** An exchange's body: the service and the token, and nothing else, in at most this many bytes. */
const EXCHANGE_BODY_BYTES = 16 * 1024;
const exchangeBody = z.object({ service: z.string().max(120), token: z.string().max(8 * 1024) }).strict();

const REFUSED_CODE = { 401: 'unauthenticated', 429: 'too_many_requests', 503: 'unavailable' } as const;

/** An exchange refused, as its client reads it: 401 with the reason, or 429 and 503 with when to come back (`Retry-After`). */
function refuseExchange(error: ExchangeRefused, headers: Record<string, string> = {}): Response {
  const later = error.reason === 'full' ? '30' : '60';
  return jsonResponse(
    { error: REFUSED_CODE[error.status], reason: error.reason, message: error.message },
    error.status,
    error.status === 401 ? headers : { ...headers, 'retry-after': later },
  );
}

/**
 * Both exchanges' admission, before anything else: one limit per source
 * address and one for all. A limiter that fails refuses, and never lets a
 * request through. Null when admitted.
 */
async function admission(workloads: WorkloadService, sourceIp: string | null): Promise<Response | null> {
  try {
    const [source, total] = await Promise.all([
      workloads.limits.perSource.limit({ key: `source:${sourceIp ?? 'unknown'}` }),
      workloads.limits.total.limit({ key: 'total' }),
    ]);
    return source.success && total.success ? null : refuseExchange(new ExchangeRefused('busy', 'too many exchanges: try again in a minute', 429));
  } catch (error) {
    console.error('workload limiter failed', logged(error));
    return refuseExchange(new ExchangeRefused('busy', 'coffre cannot count exchanges right now: try again shortly', 503));
  }
}

/** Whether this instance leaves services nothing but key-bound sessions (`useOnly`, docs/design/workload-access.md, section 6.3). */
function useOnly(runtime: CoffreRuntime): boolean {
  return runtime.auth.mode === 'signin' && runtime.auth.signin.workloads?.useOnly === true;
}

/**
 * POST /api/auth/oidc: a CI run's ID token, for a five-minute credential of
 * the service it names (docs/design/oidc.md). `{ service, token }` answers
 * `{ token, expiresAt }`.
 *
 * Admission comes before anything else: both limits, one per source address
 * and one for all, then the body, read only to its limit. A limiter that
 * fails refuses, and never lets a request through. `asked` says what the
 * body asks for, for a plugin whose clients write it in their own words, a
 * Vault login's `{ role, jwt }` (`PluginContext.exchange`): read past
 * admission too, and checked as the route's own.
 */
export async function exchangeWorkloadToken(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  asked: (body: unknown) => unknown = (body) => body,
) {
  const workloads = runtime.workloads;
  if (workloads === null) return errorResponse(notFound('this instance trusts no workloads'));
  // A strict instance issues no bearer credential to a service: its workloads sign in with a key.
  if (useOnly(runtime)) {
    return jsonResponse({ error: 'gone', reason: 'use_only', message: 'this instance signs services in at /api/auth/workload, with a key (useOnly): it issues no bearer credential' }, 410);
  }
  const refused = await admission(workloads, sourceIp);
  if (refused !== null) return refused;
  try {
    const body = exchangeBody.parse(asked(await readLimitedJson(request, EXCHANGE_BODY_BYTES)));
    return jsonResponse(await workloads.exchange(body, { requestId: crypto.randomUUID(), sourceIp }));
  } catch (error) {
    if (error instanceof ExchangeRefused) return refuseExchange(error);
    return errorResponse(error);
  }
}

/** A workload's sign-in body: the service, and one proof by its kind, in at most this many bytes. */
const sessionBody = z.object({
  service: z.string().max(120),
  proof: z.record(z.string().max(32), z.unknown()).refine((proof) => Object.keys(proof).length === 1, 'a proof names one kind: { "oidc": "<token>" }'),
}).strict();

/** How far a sign-in's proof's `iat` may be from now: it carries no nonce, so its clock bounds it (section 4.1). */
const EXCHANGE_SKEW_SECONDS = 60;

/**
 * POST /api/auth/workload: a workload's proof, an ID token, a signed
 * `GetCallerIdentity` or an enrollment code, for a session bound to the
 * key its DPoP proof names (docs/design/workload-access.md, section 4.1).
 * `{ service, proof: { <kind>: … } }` answers `{ token, tokenType: 'DPoP',
 * expiresAt, notAfter, places }`, or 202 `{ pending, approve }` for a
 * session that waits for a person's approval, with the gate's nonce.
 *
 * Admission first, as for `/api/auth/oidc`; then the body, read only to
 * its limit; its shape; and its `DPoP` header: signed by the key, for this
 * method and URL, within a minute. No nonce, no `ath`: the platform proof
 * is spent or names the key, and the key is the caller's own. Then the
 * proof, by its kind (`WorkloadService.signIn`).
 */
export async function exchangeWorkloadSession(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const workloads = runtime.workloads;
  if (workloads === null) return errorResponse(notFound('this instance trusts no workloads'));
  const refused = await admission(workloads, sourceIp);
  if (refused !== null) return refused;
  try {
    const body = sessionBody.parse(await readLimitedJson(request, EXCHANGE_BODY_BYTES));
    const header = request.headers.get('dpop');
    if (header === null) return refuseExchange(new ExchangeRefused('dpop', "a DPoP header, a proof signed by the key the session will be bound to, comes with the sign-in"));
    const proof = await verifyProof(header, { method: request.method, url: signedUrl(request, runtime.publicUrl), skewSeconds: EXCHANGE_SKEW_SECONDS });
    if (!proof.ok) return refuseExchange(new ExchangeRefused('dpop', `the DPoP proof does not hold: ${proof.message}`));
    const made = await workloads.signIn(body, { requestId: crypto.randomUUID(), sourceIp, jkt: proof.jkt });
    const nonce = await gateNonce(runtime, body.service);
    return jsonResponse(made, 'pending' in made ? 202 : 200, nonce === null ? {} : { 'dpop-nonce': nonce });
  } catch (error) {
    if (error instanceof ExchangeRefused) return refuseExchange(error);
    return errorResponse(error);
  }
}

/** The gate's current nonce for a service, for an answer that admits no proof; null when it cannot say, which costs the workload one retry. */
async function gateNonce(runtime: CoffreRuntime, service: string): Promise<string | null> {
  if (runtime.gates == null) return null;
  try {
    return await runtime.gates(service.startsWith('token:') ? service : `token:${service}`).nonce();
  } catch (error) {
    console.error('the workload gate failed', logged(error));
    return null;
  }
}

/**
 * POST /api/auth/workload/renew: a session's expiry moved on, by a proof
 * of its key, `{ expiresAt }` (section 5.4). Its session as every request
 * checks it, in one statement and with no vault call; never a `narrow`
 * child's, which ends with its parent or its own expiry.
 */
export async function renewWorkloadSession(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const workloads = runtime.workloads;
  const token = dpopToken(request);
  if (workloads === null || token === null) return errorResponse(new ApiError('unauthenticated', "this takes a workload's session, Authorization: DPoP coffre_wl_…, with its key's proof"));
  try {
    const session = await standingSession(request, runtime, token, sourceIp, { place: null, credential: null });
    return jsonResponse(await workloads.renew(session, { requestId: crypto.randomUUID(), sourceIp }), 200, { 'dpop-nonce': session.nonce });
  } catch (error) {
    if (error instanceof SessionRefused) return error.response;
    if (error instanceof ExchangeRefused) return refuseExchange(error);
    return errorResponse(error);
  }
}

/**
 * POST /api/auth/logout: revoke the credential this request carries, `coffre
 * logout`: a bearer token, or a workload's session with its key's proof (a
 * `narrow` child's too), which its SDK sends on `SIGTERM`.
 */
export async function logout(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const session = dpopToken(request);
  if (session !== null) {
    try {
      await standingSession(request, runtime, session, sourceIp, { place: null, credential: null, children: true });
      if (runtime.signin !== null) await runtime.signin.signOut(session, { requestId: crypto.randomUUID(), sourceIp });
      return jsonResponse({ signedOut: true });
    } catch (error) {
      if (error instanceof SessionRefused) return error.response;
      return errorResponse(error);
    }
  }
  try {
    const identity = await apiCaller(request, runtime, sourceIp);
    if (identity instanceof Response) return identity;
    const token = bearerToken(request);
    if (runtime.signin !== null && token !== null) await runtime.signin.signOut(token, identity);
    return jsonResponse({ signedOut: true });
  } catch (error) {
    return errorResponse(error);
  }
}

/**
 * GET /auth/signin/:provider: leave for the provider. `?next=` is where to
 * land afterwards; `?link=1` adds the account to the signed-in person
 * instead of signing in with it.
 */
export async function startSignin(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  provider: string,
) {
  const signin = runtime.signin;
  if (signin === null) return redirectResponse('/login');

  const url = new URL(request.url);
  const linking = url.searchParams.get('link') === '1';
  const back = linking ? '/account' : '/login';
  const config = signin.config.providers.find((candidate) => candidate.id === provider);
  if (config === undefined) return redirectResponse(`${back}?error=unknown_provider`);

  let link: string | null = null;
  if (linking) {
    const identity = await browserIdentity(request, runtime, sourceIp);
    if (identity?.principal.type !== 'user' || !identity.registered) {
      return redirectResponse('/login?next=/account');
    }
    link = identity.principal.id;
  }

  let started;
  try {
    started = await config.start(callbackUrl(signin.config, config.id));
  } catch (error) {
    if (!(error instanceof SigninError)) console.error('sign-in start failed', logged(error));
    return redirectResponse(`${back}?error=provider_unavailable`);
  }

  const sealed = signin.sealPending({
    state: started.pending.state,
    codeVerifier: started.pending.codeVerifier,
    nonce: started.pending.nonce,
    provider: config.id,
    next: linking ? '/account' : safeNext(url.searchParams.get('next'), signin.config.publicUrl),
    link,
  });
  return redirectResponse(started.url.href, [
    cookieHeader(runtime.auth, pendingCookieName(runtime.auth), sealed.value, sealed.maxAge),
  ]);
}

/**
 * GET /auth/callback/:provider: back from the provider. Every way out clears
 * the pending-state cookie, so a callback URL cannot be replayed, and every
 * failure lands on a page that can say what went wrong in words.
 */
export async function finishSignin(
  request: Request,
  runtime: CoffreRuntime,
  sourceIp: string | null,
  provider: string,
) {
  const auth = runtime.auth;
  const signin = runtime.signin;
  if (signin === null) return redirectResponse('/login');

  const clearPending = clearCookieHeader(auth, pendingCookieName(auth));
  const pending = signin.openPending(readCookie(request, pendingCookieName(auth)));
  const back = pending?.link ? '/account' : '/login';
  const fail = (code: string, query: Record<string, string> = {}) =>
    redirectResponse(`${back}?${new URLSearchParams({ error: code, ...query })}`, [clearPending]);

  if (pending === null || pending.provider !== provider) return fail('state_mismatch');
  const config = signin.config.providers.find((candidate) => candidate.id === provider);
  if (config === undefined) return fail('unknown_provider');

  let profile: SignedInAccount;
  try {
    profile = signedIn(config.id, await config.finish(new URL(request.url), callbackUrl(signin.config, config.id), pending));
  } catch (error) {
    // The person sees a sentence; the operator needs the reason. Provider
    // messages name the step that failed and never carry tokens or codes.
    if (error instanceof SigninError) {
      if (error.code === 'provider_unavailable' || error.code === 'invalid_response') {
        console.warn(`sign-in with ${config.id} failed: ${error.message}`, logged(error.cause) ?? '');
      }
      return fail(error.code);
    }
    console.error('sign-in callback failed', logged(error));
    return fail('provider_unavailable');
  }

  const meta = { requestId: crypto.randomUUID(), sourceIp };

  if (pending.link !== null) {
    const identity = await browserIdentity(request, runtime, sourceIp);
    if (identity === null || !identity.registered || identity.principal.id !== pending.link) {
      return fail('link_session');
    }
    const linked = await signin.linkIdentity(identity, profile);
    return linked.ok ? redirectResponse(`/account?linked=${config.id}`, [clearPending]) : fail(linked.reason);
  }

  const result = await signin.completeSignin(profile, {
    ...meta,
    label: describeUserAgent(request.headers.get('user-agent')),
  });
  if (!result.ok) {
    // Which providers the email already signs in with, and the one just tried, for the page to name.
    const which: Record<string, string> = result.providers === undefined ? {} : { with: result.providers.join(','), via: config.id };
    return fail(result.reason === 'not_registered' && profile.emails.length === 0 ? 'no_verified_email' : result.reason, which);
  }

  // Signing in again on the same browser replaces the session rather than
  // leaving the old one alive until it expires.
  const sessionName = sessionCookieName(auth);
  const previous = readCookie(request, sessionName);
  if (previous !== null) await signin.signOut(previous, meta).catch(() => {});

  const maxAge = (Date.parse(result.credential.expiresAt) - Date.now()) / 1000;
  return redirectResponse(pending.next, [
    clearPending,
    cookieHeader(auth, sessionName, result.credential.token, maxAge),
  ]);
}

/**
 * What the provider vouched for, under the id coffre knows it by: a provider
 * cannot pass its accounts off as another's. The profile is checked as well,
 * since a deployment's own provider is typed, not trusted.
 */
function signedIn(provider: string, profile: SigninProfile): SignedInAccount {
  const { subject, emails, name } = profile ?? {};
  if (
    typeof subject !== 'string' ||
    subject.length === 0 ||
    subject.length > 255 ||
    !Array.isArray(emails) ||
    !(name === null || typeof name === 'string')
  ) {
    throw new SigninError('invalid_response', `sign-in provider ${provider} returned a malformed profile`);
  }
  const addresses = emails
    .filter((email): email is string => typeof email === 'string')
    .map((email) => email.trim().toLowerCase())
    .filter((email) => emailAddress.safeParse(email).success);
  return { provider, subject, emails: [...new Set(addresses)], name };
}

/**
 * POST /auth/signout: end this browser's session. A POST, so a link or an
 * image elsewhere cannot sign anyone out.
 */
export async function signOut(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const auth = runtime.auth;
  // The session is Access's; its logout endpoint ends it.
  if (auth.mode === 'cloudflare') return redirectResponse('/cdn-cgi/access/logout', [], 303);

  const name = sessionCookieName(auth);
  const token = readCookie(request, name);
  if (token !== null && runtime.signin !== null) {
    await runtime.signin.signOut(token, { requestId: crypto.randomUUID(), sourceIp });
  }
  return redirectResponse('/login', [clearCookieHeader(auth, name)], 303);
}
