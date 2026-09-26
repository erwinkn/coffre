import { createFileRoute } from '@tanstack/react-router';

import { requestIdentityContextFor } from '../server/auth.ts';
import { methodNotAllowed } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import {
  callbackUrl,
  cookieHeader,
  pendingCookieName,
  redirectResponse,
  safeNext,
  signinProvider,
} from '../server/signin.ts';
import { SigninError } from '../../../../packages/core/src/identity/signin/types.ts';

/**
 * Leave for the provider. `?next=` is where to land afterwards; `?link=1`
 * adds the account to the signed-in person instead of signing in with it.
 */
export const Route = createFileRoute('/auth/signin/$provider')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        const runtime = getRuntime();
        const signin = runtime.signin;
        if (signin === null) return redirectResponse('/login');

        const url = new URL(request.url);
        const linking = url.searchParams.get('link') === '1';
        const back = linking ? '/account' : '/login';
        const config = signin.config.providers.find((provider) => provider.id === params.provider);
        if (config === undefined) return redirectResponse(`${back}?error=unknown_provider`);

        let link: string | null = null;
        if (linking) {
          const identity = requestIdentityContextFor(request);
          if (identity?.principal?.type !== 'user' || !identity.registered) {
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
      },
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
