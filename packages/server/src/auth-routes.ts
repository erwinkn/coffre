import { EXCHANGE_SKEW_SECONDS, SigninError, verifyProof, type SigninProfile } from '@coffre/core/identity';
import { emailAddress } from '@coffre/core/schemas';
import type { Confirmation } from '@coffre/core/vault';
import { z } from 'zod';

import { unknownKeyAlert } from './alerts.ts';
import { ApiError, badRequest, notFound, UNAVAILABLE_RETRY_AFTER } from './api/errors.ts';
import type { SignedInAccount, SigninResult } from './api/signin.ts';
import { CEREMONY_TTL_SECONDS } from './api/ceremony.ts';
import { freshEnough, freshPass } from './api/fresh-routes.ts';
import { ExchangeRefused, UnknownKey, type WorkloadService } from './api/workloads.ts';
import {
  accessTokenForRequest,
  authenticateRequest,
  bearerToken,
  readCookie,
  sessionCookieName,
  type AuthenticatedIdentity,
} from './auth.ts';
import { dpopToken, SessionRefused, signedUrl, standingSession } from './workload-sessions.ts';
import { SOURCE_RETRY_AFTER } from './workloads/limits.ts';
import { apiCaller } from './fetch-api.ts';
import { errorResponse, jsonResponse, readJson, readLimitedJson, SIGN_IN_BODY_BYTES, validate } from './http.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';
import {
  callbackUrl,
  clearCookieHeader,
  COOKIE_BYTES,
  cookieHeader,
  describeUserAgent,
  passkeyCookieName,
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

/** Where a link to a provider's account starts: the one place a step-up may go on to that is not a page (`stepUpNext`). */
function linkStart(provider: string): string {
  return `/auth/signin/${encodeURIComponent(provider)}?link=1`;
}

/**
 * Whether the browser's session may link another account: `holder`, fresh if its person holds a passkey
 * (`FRESH_ROUTES`); and if so, what confirmed it, which the link's entry names (passkeys.md, section 11). Null if not.
 */
function linksFresh(runtime: CoffreRuntime, identity: AuthenticatedIdentity): { confirmed: Confirmation | null } | null {
  const { stands, confirmed } = freshPass({ signin: runtime.signin, ...identity }, 'holder');
  return freshEnough('holder', stands) ? { confirmed } : null;
}

/**
 * Where a step-up goes on to: a page of coffre's (`safeNext`), or the start of a link to one of the deployment's
 * providers, which its holder check sent there (`startSignin`), exactly as it sent it.
 */
function stepUpNext(raw: string | null, config: { providers: readonly { id: string }[]; publicUrl: string }): string {
  if (raw !== null && config.providers.some((provider) => raw === linkStart(provider.id))) return raw;
  return safeNext(raw, config.publicUrl);
}

/** A device login's start: the label its terminal gives itself, if any. Its body, as every one before sign-in, is read to `SIGN_IN_BODY_BYTES`. */
const deviceStart = z.object({ client_label: z.string().trim().optional() });

/**
 * POST /api/auth/device: start a device login (RFC 8628). The CLI gets a
 * code for the person to approve in a signed-in browser, and a device code
 * to poll with.
 */
export async function startDevice(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  if (runtime.signin === null) return errorResponse(notFound('device login needs signin mode'));
  try {
    const input = validate(deviceStart, await readJson(request, SIGN_IN_BODY_BYTES, {}));
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

const devicePoll = z.object({ device_code: z.string().min(1) });

/**
 * POST /api/auth/device/token: the CLI's poll. Errors use RFC 8628's names
 * so any device-flow client understands them; success returns a CLI session
 * token, once.
 */
export async function pollDevice(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  if (runtime.signin === null) return errorResponse(notFound('device login needs signin mode'));
  try {
    const { device_code } = validate(devicePoll, await readJson(request, SIGN_IN_BODY_BYTES));
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

/** An exchange's body: the service and the token, and nothing else, read to `SIGN_IN_BODY_BYTES`, which bounds the token too. */
const exchangeBody = z.object({ service: z.string(), token: z.string() }).strict();

const REFUSED_CODE = { 401: 'unauthenticated', 429: 'too_many_requests', 503: 'unavailable' } as const;


/** An exchange refused, as its client reads it: 401 with the reason, or 429 and 503 with when to come back (`Retry-After`). */
function refuseExchange(error: ExchangeRefused, headers: Record<string, string> = {}): Response {
  // A 503 is coffre, or what it asked, not answering for a moment (`errorResponse`): a limiter that could not count, STS.
  const later = error.retryAfter ?? (error.status === 503 ? UNAVAILABLE_RETRY_AFTER : error.reason === 'full' ? '30' : '60');
  return jsonResponse(
    { error: REFUSED_CODE[error.status], reason: error.reason, message: error.message },
    error.status,
    error.status === 401 ? headers : { ...headers, 'retry-after': later },
  );
}

/**
 * A sign-in's admission, before anything else: the requests its source
 * address made to this entry point (`exchange`, `/api/auth/oidc` and a
 * plugin's login made of it; `workload`, `/api/auth/workload`), counted
 * apart from every other's (W331, D177). Refused, it is asked again when
 * the limiter's window has moved on: 10 s (`processLimits`, and the
 * examples' binding). A limiter that fails refuses, and never lets a
 * request through. Null when admitted.
 */
async function admission(workloads: WorkloadService, entry: 'exchange' | 'workload', sourceIp: string | null): Promise<Response | null> {
  try {
    const { success } = await workloads.limits.perSource.limit({ key: `${entry}:${sourceIp ?? 'unknown'}` });
    return success ? null : refuseExchange(new ExchangeRefused('busy', 'too many sign-ins from this address: try again in a few seconds', 429, SOURCE_RETRY_AFTER));
  } catch (error) {
    console.error('workload limiter failed', logged(error));
    return refuseExchange(new ExchangeRefused('busy', 'coffre cannot count exchanges right now: try again shortly', 503));
  }
}

/** Whether this instance leaves services nothing but key-bound sessions (`useOnly`, docs/design/workload-access.md, section 6.3). */
function useOnly(runtime: CoffreRuntime): boolean {
  return runtime.auth.mode === 'signin' && runtime.auth.signin.useOnly;
}

/**
 * POST /api/auth/oidc: a CI run's ID token, for a five-minute credential of
 * the service it names (docs/design/oidc.md). `{ service, token }` answers
 * `{ token, expiresAt }`.
 *
 * Admission comes before anything else, its source address's limit
 * (`admission`), then the body, read only to its limit. A limiter that
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
  const refused = await admission(workloads, 'exchange', sourceIp);
  if (refused !== null) return refused;
  const requestId = crypto.randomUUID();
  try {
    const body = validate(exchangeBody, asked(await readLimitedJson(request, SIGN_IN_BODY_BYTES)));
    return jsonResponse(await workloads.exchange(body, { requestId, sourceIp }));
  } catch (error) {
    if (error instanceof UnknownKey) await unknownKeyAlert(runtime, error, sourceIp, requestId);
    if (error instanceof ExchangeRefused) return refuseExchange(error);
    return errorResponse(error);
  }
}

/** A workload's sign-in body: the service, and one proof by its kind, read to `SIGN_IN_BODY_BYTES`. */
const sessionBody = z.object({
  service: z.string(),
  proof: z.record(z.string(), z.unknown()).refine((proof) => Object.keys(proof).length === 1, 'a proof names one kind: { "oidc": "<token>" }'),
}).strict();


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
 * proof, by its kind (`WorkloadService.signIn`). A token signed by a key
 * the service's uploaded keys lack alerts, once an hour per service at
 * most (`unknownKeyAlert`), as it does at `/api/auth/oidc`.
 */
export async function exchangeWorkloadSession(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const workloads = runtime.workloads;
  if (workloads === null) return errorResponse(notFound('this instance trusts no workloads'));
  // No gate, no session that could be used: nothing is spent for one.
  if (runtime.gates === undefined) return errorResponse(new ApiError('unavailable', 'this deployment runs no workload gate, so it takes no workload session', 'no_gate'));
  const refused = await admission(workloads, 'workload', sourceIp);
  if (refused !== null) return refused;
  const requestId = crypto.randomUUID();
  try {
    const body = validate(sessionBody, await readLimitedJson(request, SIGN_IN_BODY_BYTES));
    const header = request.headers.get('dpop');
    if (header === null) return refuseExchange(new ExchangeRefused('dpop', "a DPoP header, a proof signed by the key the session will be bound to, comes with the sign-in"));
    const proof = await verifyProof(header, { method: request.method, url: signedUrl(request, runtime.publicUrl), skewSeconds: EXCHANGE_SKEW_SECONDS });
    if (!proof.ok) return refuseExchange(new ExchangeRefused('dpop', `the DPoP proof does not hold: ${proof.message}`));
    const made = await workloads.signIn(body, { requestId, sourceIp, jkt: proof.jkt, dpop: header });
    const nonce = await gateNonce(runtime, body.service);
    return jsonResponse(made, 'pending' in made ? 202 : 200, nonce === null ? {} : { 'dpop-nonce': nonce });
  } catch (error) {
    if (error instanceof UnknownKey) await unknownKeyAlert(runtime, error, sourceIp, requestId);
    if (error instanceof ExchangeRefused) return refuseExchange(error);
    return errorResponse(error);
  }
}

/** The gate's current nonce for a service, for an answer that admits no proof; null when it cannot say, which costs the workload one retry. */
async function gateNonce(runtime: CoffreRuntime, service: string): Promise<string | null> {
  if (runtime.gates === undefined) return null;
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
    const requestId = crypto.randomUUID();
    const session = await standingSession(request, runtime, token, sourceIp, requestId, { place: null, credential: null });
    return jsonResponse(await workloads.renew(session, { requestId, sourceIp }), 200, { 'dpop-nonce': session.nonce });
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
      // Its key's proof is all it takes to end one's own session: no pending approval or moved address keeps it alive.
      const requestId = crypto.randomUUID();
      await standingSession(request, runtime, session, sourceIp, requestId, { place: null, credential: null, children: true, ending: true });
      if (runtime.signin !== null) await runtime.signin.signOut(session, { requestId, sourceIp });
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
    // Another account that signs in as them (passkeys.md, section 4.5): a fresh session if they hold a passkey, before
    // leaving for the provider. The step-up confirms it, and comes back here.
    if (linksFresh(runtime, identity) === null) {
      return redirectResponse(`/auth/passkey?${new URLSearchParams({ 'step-up': '1', next: linkStart(config.id) })}`);
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
    // `?passkey=add`: to add a passkey as they sign in, which an act that takes one asked them to (`afterProvider`).
    ...(!linking && url.searchParams.get('passkey') === 'add' ? { addPasskey: true as const } : {}),
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
    // Fresh still: a window that ran out at the provider links nothing, and the page says to link again.
    const fresh = linksFresh(runtime, identity);
    if (fresh === null) return fail('link_stale');
    const linked = await signin.linkIdentity({ ...identity, confirmed: fresh.confirmed }, profile);
    return linked.ok ? redirectResponse(`/account?linked=${config.id}`, [clearPending]) : fail(linked.reason);
  }

  const result = await signin.afterProvider(profile, { ...meta, label: describeUserAgent(request.headers.get('user-agent')) }, pending.next, { addPasskey: pending.addPasskey === true });
  // A passkey to touch, or to add, before any session exists (passkeys.md, section 3.1): what the provider vouched for
  // waits in a sealed cookie of its own, and nothing is written until the passkey answers.
  if (result.ok === 'passkey') {
    const waiting = cookieHeader(auth, passkeyCookieName(auth), signin.ceremonies.seal(result.state), CEREMONY_TTL_SECONDS);
    // ASCII throughout (the seal is base64url), so its length is its bytes; a browser would drop it unsaid.
    if (waiting.length > COOKIE_BYTES) return fail('profile_too_long');
    return redirectResponse('/auth/passkey', [clearPending, waiting]);
  }
  if (!result.ok) {
    // Which providers the email already signs in with, and the one just tried, for the page to name.
    const which: Record<string, string> = result.providers === undefined ? {} : { with: result.providers.join(','), via: config.id };
    return fail(result.reason === 'not_registered' && profile.emails.length === 0 ? 'no_verified_email' : result.reason, which);
  }
  return redirectResponse(pending.next, [clearPending, ...(await signedInCookies(request, runtime, result, meta))]);
}

/**
 * A browser's new session: its cookie, set, and the session it signed in on before, if any, signed out, rather than
 * left alive until it expires: here, after the new one, unless the sign-in's own transaction ended it (`replaced`, a
 * touch's, passkeys.md, section 6.5).
 */
async function signedInCookies(
  request: Request,
  runtime: CoffreRuntime,
  result: Extract<SigninResult, { ok: true }>,
  meta: { requestId: string; sourceIp: string | null },
): Promise<string[]> {
  const sessionName = sessionCookieName(runtime.auth);
  const previous = readCookie(request, sessionName);
  if (previous !== null && result.replaced !== true) await runtime.signin!.signOut(previous, meta).catch(() => {});
  const maxAge = (Date.parse(result.credential.expiresAt) - Date.now()) / 1000;
  return [cookieHeader(runtime.auth, sessionName, result.credential.token, maxAge)];
}

/** What the passkey step answers a refusal with: a code the page says in words (`signinErrorMessage`). */
const PASSKEY_REFUSED: Partial<Record<string, number>> = { passkey_failed: 401, session_ended: 401, passkey_required: 401, last_passkey: 409 };

/**
 * GET /api/auth/passkey: what the passkey page asks the browser for (passkeys.md, section 3.1), `{ purpose, email,
 * options }`, `options` in WebAuthn's JSON form: a touch for the sign-in waiting in this browser's passkey cookie, or a
 * new passkey for it, with its sealed `state`, the user handle this GET drew. `?step-up=1`: a touch for the browser's session, which a person's passkey no longer stands behind
 * (section 6.2), with its sealed `state` too. 404 `state_mismatch` when there is nothing to ask: the sign-in expired,
 * or the session is no step-up's, and signing in again is the way. `?remove=<id>`: what removing that passkey of the
 * session's person asks (section 3.6), `{ purpose: 'remove', email, name, options, state }`, `options` null under `off`,
 * where it asks no touch; 409 `last_passkey` for their last one under `required`, and 409 `tampered` when one of the
 * person's passkey rows fails its MAC.
 *
 * POST /api/auth/passkey: the browser's answer, `{ response }` (or `{ state, response }` for a new passkey, a step-up or
 * a removal, `{ state }` alone for a removal under `off`), from coffre's own page: on success the session cookie, and
 * `{ next }`, where to go.
 */
export async function passkeyStep(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const signin = runtime.signin;
  if (signin === null) return errorResponse(notFound('passkeys need signin mode'));
  const auth = runtime.auth;
  const url = new URL(request.url);
  const nothing = () => jsonResponse({ error: 'state_mismatch', message: 'this sign-in expired or was finished elsewhere: sign in again' }, 404);
  // GET, or HEAD, which `coffreRoute` lets in as GET and hands on as itself (review r8 of #500): only a POST answers.
  if (request.method !== 'POST') {
    const removing = url.searchParams.get('remove');
    if (removing !== null) {
      const token = readCookie(request, sessionCookieName(auth));
      const step = token === null ? null : await signin.removeStep(token, removing);
      // Both refusals, a last passkey under `required` and a passkey row failing its MAC, are 409s, as the passkeys API's.
      if (step !== null && 'refused' in step) return jsonResponse({ error: step.refused }, 409);
      return step === null ? nothing() : jsonResponse(step, 200, { 'cache-control': 'no-store' });
    }
    if (url.searchParams.get('step-up') === '1') {
      const token = readCookie(request, sessionCookieName(auth));
      const step = token === null ? null : await signin.stepUpStep(token, stepUpNext(url.searchParams.get('next'), signin.config));
      return step === null ? nothing() : jsonResponse(step, 200, { 'cache-control': 'no-store' });
    }
    const state = signin.ceremonies.open(readCookie(request, passkeyCookieName(auth)), ['signin', 'enroll']);
    const step = state === null ? null : await signin.passkeyStep(state);
    return step === null ? nothing() : jsonResponse(step, 200, { 'cache-control': 'no-store' });
  }

  // Who may be answering, before a byte of the body is read: a browser holding a session, for a step-up, or one whose
  // passkey cookie opens, which only a person the provider vouched for within five minutes holds (section 3.1).
  const token = readCookie(request, sessionCookieName(auth));
  const state = signin.ceremonies.open(readCookie(request, passkeyCookieName(auth)), ['signin', 'enroll']);
  const clear = clearCookieHeader(auth, passkeyCookieName(auth));
  const meta = { requestId: crypto.randomUUID(), sourceIp, label: describeUserAgent(request.headers.get('user-agent')) };
  const refused = (reason: string, cookies: string[] = []) => withCookies(jsonResponse({ error: reason }, PASSKEY_REFUSED[reason] ?? 400), cookies);
  if (state === null && token === null) return refused('state_mismatch', [clear]);

  let body: { response?: Record<string, unknown>; state?: string };
  try {
    // Read before the session or the ceremony it answers is checked, so to the bound of every body before sign-in.
    body = validate(passkeyAnswer, await readLimitedJson(request, SIGN_IN_BODY_BYTES)) as typeof body;
  } catch (error) {
    return errorResponse(error);
  }
  const answered = async (result: SigninResult, next: string, cookies: string[]) => {
    if (result.ok !== true) return refused(result.reason, cookies);
    return withCookies(jsonResponse({ next }), [...cookies, ...(await signedInCookies(request, runtime, result, meta))]);
  };

  // A `state` is a step-up's or a removal's, or, for an enrollment, the user handle its `create()` was given (`CreateState`).
  const remove = body.state === undefined ? null : signin.ceremonies.open(body.state, ['remove']);
  if (remove !== null) {
    if (token === null) return refused('session_ended');
    // Back to the Passkeys tab, on the session the removal issued.
    const result = await signin.removePasskey(body.state!, token, body.response, meta);
    // A tampered row refuses a removal with 409, as the GET and the API do; a sign-in's own `tampered` stays 400.
    if (result.ok !== true && result.reason === 'tampered') return jsonResponse({ error: 'tampered' }, 409);
    return answered(result, '/account/passkeys', []);
  }
  // Every other answer is a passkey's.
  if (body.response === undefined) return errorResponse(badRequest('response: the passkey\'s answer is required'));
  const stepUp = body.state === undefined ? null : signin.ceremonies.open(body.state, ['step-up']);
  if (stepUp !== null || (body.state !== undefined && state?.purpose !== 'enroll')) {
    if (token === null || stepUp === null) return refused('session_ended');
    return answered(await signin.stepUp(body.state!, token, body.response, meta), stepUp.next, []);
  }
  if (state === null) return refused('state_mismatch', [clear]);
  const result = await signin.finishPasskey(state, body.response, meta, token, body.state ?? null);
  // A passkey that did not answer may be tried again, another one too, while the sign-in lasts; anything else starts over.
  return answered(result, state.next, result.ok !== true && result.reason === 'passkey_failed' ? [] : [clear]);
}

/** A response with these cookies set: `jsonResponse` takes its headers as a record, which holds one `set-cookie`. */
function withCookies(response: Response, cookies: readonly string[]): Response {
  for (const cookie of cookies) response.headers.append('set-cookie', cookie);
  return response;
}

/** A step-up's or a new passkey's state is the server's own seal, which `open` checks; the body's size bounds its length. */
const passkeyAnswer = z.object({ response: z.record(z.string(), z.unknown()).optional(), state: z.string().optional() }).strict();

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

/** The schemas of the bodies read before sign-in, by route: what `scripts/sign-in-cost.ts` measures. */
export const SIGN_IN_SCHEMAS = { deviceStart, devicePoll, exchangeBody, sessionBody, passkeyAnswer };
