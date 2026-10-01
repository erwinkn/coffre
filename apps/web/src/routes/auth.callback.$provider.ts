import { createFileRoute } from '@tanstack/react-router';

import {
  readCookie,
  requestIdentityContextFor,
  sessionCookieName,
  trustedSourceIp,
} from '../server/auth.ts';
import { methodNotAllowed } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import {
  callbackUrl,
  clearCookieHeader,
  cookieHeader,
  describeUserAgent,
  pendingCookieName,
  redirectResponse,
  signinProvider,
} from '../server/signin.ts';
import {
  SigninError,
  type SigninProfile,
} from '../../../../packages/core/src/identity/signin/types.ts';

/**
 * Back from the provider. Every way out clears the pending-state cookie, so
 * a callback URL cannot be replayed, and every failure lands on a page that
 * can say what went wrong in words.
 */
export const Route = createFileRoute('/auth/callback/$provider')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        const runtime = getRuntime();
        const auth = runtime.auth;
        const signin = runtime.signin;
        if (signin === null) return redirectResponse('/login');

        const clearPending = clearCookieHeader(auth, pendingCookieName(auth));
        const pending = signin.openPending(readCookie(request, pendingCookieName(auth)));
        const back = pending?.link ? '/account' : '/login';
        const fail = (code: string) => redirectResponse(`${back}?error=${code}`, [clearPending]);

        if (pending === null || pending.provider !== params.provider) return fail('state_mismatch');
        const config = signin.config.providers.find((provider) => provider.id === params.provider);
        if (config === undefined) return fail('unknown_provider');

        let profile: SigninProfile;
        try {
          profile = await signinProvider(config).finish(
            new URL(request.url),
            callbackUrl(signin.config, config.id),
            pending,
          );
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

        const identity = requestIdentityContextFor(request);
        const meta = {
          requestId: identity?.requestId ?? crypto.randomUUID(),
          sourceIp: trustedSourceIp(request, auth),
        };

        if (pending.link !== null) {
          if (
            identity?.principal == null ||
            !identity.registered ||
            identity.principal.id !== pending.link
          ) {
            return fail('link_session');
          }
          const linked = await signin.linkIdentity(identity, profile);
          return linked.ok
            ? redirectResponse(`/account?linked=${config.id}`, [clearPending])
            : fail(linked.reason);
        }

        const result = await signin.completeSignin(profile, {
          ...meta,
          label: describeUserAgent(request.headers.get('user-agent')),
        });
        if (!result.ok) {
          return fail(
            result.reason === 'not_registered' && profile.emails.length === 0
              ? 'no_verified_email'
              : result.reason,
          );
        }

        // Signing in again on the same browser replaces the session rather
        // than leaving the old one alive until it expires.
        const sessionName = sessionCookieName(auth);
        const previous = readCookie(request, sessionName);
        if (previous !== null) await signin.signOut(previous, meta).catch(() => {});

        const maxAge = (Date.parse(result.credential.expiresAt) - Date.now()) / 1000;
        return redirectResponse(pending.next, [
          clearPending,
          cookieHeader(auth, sessionName, result.credential.token, maxAge),
        ]);
      },
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
