import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { ApiError, notFound } from '../server/api/errors.ts';
import { DEV_TOKEN_COOKIE } from '../server/auth.ts';
import { errorResponse, methodNotAllowed, readJson } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { cookieHeader } from '../server/signin.ts';
import { emailAddress } from '../shared/schemas.ts';

const DEV_SESSION_SECONDS = 8 * 60 * 60;

const body = z.object({ email: emailAddress });

/**
 * Sign in as anyone, in dev mode only: the dev IdP mints an Access-shaped
 * token for the email, and it becomes this browser's cookie. Start's CSRF
 * middleware checks the post comes from coffre's own sign-in page.
 */
export const Route = createFileRoute('/auth/dev')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const auth = getRuntime().auth;
        if (auth.mode !== 'dev') return errorResponse(notFound('dev sign-in is off'));
        try {
          const { email } = body.parse(await readJson(request));

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
      },
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
