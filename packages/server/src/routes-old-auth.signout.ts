import { createFileRoute } from '@tanstack/react-router';

import {
  DEV_TOKEN_COOKIE,
  readCookie,
  sessionCookieName,
  trustedSourceIp,
} from '../server/auth.ts';
import { requestIdentityContextFor } from '../server/request-identity.ts';
import { methodNotAllowed } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { clearCookieHeader, redirectResponse } from '../server/signin.ts';

/**
 * End this browser's session. A POST, so a link or an image elsewhere
 * cannot sign anyone out; Start's CSRF middleware checks the origin of the
 * form post.
 */
export const Route = createFileRoute('/auth/signout')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const runtime = getRuntime();
        const auth = runtime.auth;

        if (auth.mode === 'cloudflare') {
          // The session is Access's; its logout endpoint ends it.
          return redirectResponse('/cdn-cgi/access/logout', [], 303);
        }
        if (auth.mode === 'dev') {
          return redirectResponse('/login', [clearCookieHeader(auth, DEV_TOKEN_COOKIE)], 303);
        }

        const name = sessionCookieName(auth);
        const token = readCookie(request, name);
        if (token !== null && runtime.signin !== null) {
          await runtime.signin.signOut(token, {
            requestId: requestIdentityContextFor(request)?.requestId ?? crypto.randomUUID(),
            sourceIp: trustedSourceIp(request, auth),
          });
        }
        return redirectResponse('/login', [clearCookieHeader(auth, name)], 303);
      },
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
