import { SigninError, type SigninProfile } from '@coffre/core/identity';
import { emailAddress } from '@coffre/core/schemas';
import { z } from 'zod';

import { ApiError, notFound } from './api/errors.ts';
import {
  accessTokenForRequest,
  authenticateRequest,
  bearerToken,
  DEV_TOKEN_COOKIE,
  readCookie,
  sessionCookieName,
  type AuthenticatedIdentity,
} from './auth.ts';
import { apiCaller } from './fetch-api.ts';
import { errorResponse, jsonResponse, readJson } from './http.ts';
import type { CoffreRuntime } from './runtime.ts';
import {
  callbackUrl,
  clearCookieHeader,
  cookieHeader,
  describeUserAgent,
  pendingCookieName,
  redirectResponse,
  safeNext,
  signinProvider,
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

const deviceStart = z.object({ client_label: z.string().trim().max(120).optional() });

/**
 * POST /api/auth/device: start a device login (RFC 8628). The CLI gets a
 * code for the person to approve in a signed-in browser, and a device code
 * to poll with.
 */
export async function startDevice(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  if (runtime.signin === null) return errorResponse(notFound('device login needs signin mode'));
  try {
    const input = deviceStart.parse(await readJson(request, {}));
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
    const { device_code } = devicePoll.parse(await readJson(request));
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

/** POST /api/auth/logout: revoke the bearer token this request carries, `coffre logout`. */
export async function logout(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
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

const DEV_SESSION_SECONDS = 8 * 60 * 60;

const devSignin = z.object({ email: emailAddress });

/**
 * POST /auth/dev: sign in as anyone, in dev mode only. The dev IdP mints an
 * Access-shaped token for the email, and it becomes this browser's cookie.
 */
export async function signInDev(request: Request, runtime: CoffreRuntime) {
  const auth = runtime.auth;
  if (auth.mode !== 'dev') return errorResponse(notFound('dev sign-in is off'));
  try {
    const { email } = devSignin.parse(await readJson(request));

    const url = new URL('/dev/mint', auth.devIdpUrl);
    url.searchParams.set('email', email);
    url.searchParams.set('aud', auth.access.audience);
    url.searchParams.set('expires_in', String(DEV_SESSION_SECONDS));

    let minted: Response;
    try {
      minted = await fetch(url);
    } catch {
      throw new ApiError('unavailable', 'the dev IdP is unreachable');
    }
    if (!minted.ok) throw new ApiError('unavailable', 'the dev IdP refused to mint a token');

    const { token } = (await minted.json()) as { token: string };
    return new Response(null, {
      status: 204,
      headers: {
        'cache-control': 'no-store',
        'set-cookie': cookieHeader(auth, DEV_TOKEN_COOKIE, token, DEV_SESSION_SECONDS),
      },
    });
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
    started = await signinProvider(config).start(callbackUrl(signin.config, config.id));
  } catch (error) {
    if (!(error instanceof SigninError)) console.error('sign-in start failed', error);
    return redirectResponse(`${back}?error=provider_unavailable`);
  }

  const sealed = signin.sealPending({
    ...started.pending,
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
  const fail = (code: string) => redirectResponse(`${back}?error=${code}`, [clearPending]);

  if (pending === null || pending.provider !== provider) return fail('state_mismatch');
  const config = signin.config.providers.find((candidate) => candidate.id === provider);
  if (config === undefined) return fail('unknown_provider');

  let profile: SigninProfile;
  try {
    profile = await signinProvider(config).finish(new URL(request.url), callbackUrl(signin.config, config.id), pending);
  } catch (error) {
    // The person sees a sentence; the operator needs the reason. Provider
    // messages name the step that failed and never carry tokens or codes.
    if (error instanceof SigninError) {
      if (error.code === 'provider_unavailable' || error.code === 'invalid_response') {
        console.warn(`sign-in with ${config.id} failed: ${error.message}`, error.cause ?? '');
      }
      return fail(error.code);
    }
    console.error('sign-in callback failed', error);
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
    return fail(
      result.reason === 'not_registered' && profile.emails.length === 0 ? 'no_verified_email' : result.reason,
    );
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
 * POST /auth/signout: end this browser's session. A POST, so a link or an
 * image elsewhere cannot sign anyone out.
 */
export async function signOut(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const auth = runtime.auth;
  // The session is Access's; its logout endpoint ends it.
  if (auth.mode === 'cloudflare') return redirectResponse('/cdn-cgi/access/logout', [], 303);
  if (auth.mode === 'dev') return redirectResponse('/login', [clearCookieHeader(auth, DEV_TOKEN_COOKIE)], 303);

  const name = sessionCookieName(auth);
  const token = readCookie(request, name);
  if (token !== null && runtime.signin !== null) {
    await runtime.signin.signOut(token, { requestId: crypto.randomUUID(), sourceIp });
  }
  return redirectResponse('/login', [clearCookieHeader(auth, name)], 303);
}
