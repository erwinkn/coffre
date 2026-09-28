import { createFileRoute } from '@tanstack/react-router';

import { bearerToken } from '../server/auth.ts';
import { apiCaller } from '../server/fetch-api.ts';
import { errorResponse, jsonResponse, methodNotAllowed } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

/** Revoke the bearer token this request carries: `coffre logout`. */
export const Route = createFileRoute('/api/auth/logout')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        try {
          const runtime = getRuntime();
          const identity = await apiCaller(request, runtime);
          if (identity instanceof Response) return identity;
          const token = bearerToken(request);
          if (runtime.signin !== null && token !== null) {
            await runtime.signin.signOut(token, identity);
          }
          return jsonResponse({ signedOut: true });
        } catch (error) {
          return errorResponse(error);
        }
      },
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
