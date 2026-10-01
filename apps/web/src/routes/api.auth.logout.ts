import { createFileRoute } from '@tanstack/react-router';

import { bearerToken } from '../server/auth.ts';
import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

/** Revoke the bearer token this request carries: `coffre logout`. */
export const Route = createFileRoute('/api/auth/logout')({
  server: {
    handlers: {
      POST: ({ request, context }) =>
        apiResponse(async () => {
          const runtime = getRuntime();
          const ctx = requestContext(context);
          const token = bearerToken(request);
          if (runtime.signin !== null && token !== null) {
            await runtime.signin.signOut(token, ctx);
          }
          return { signedOut: true };
        }),
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
