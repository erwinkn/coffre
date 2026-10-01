import { createFileRoute } from '@tanstack/react-router';

import { serveApi } from '../server/api/router.ts';
import { errorResponse, requestContext } from '../server/http.ts';
import { apiContext, getRuntime } from '../server/runtime.ts';

/**
 * Every `/api` call but sign-in's own, served from one route table; see
 * `server/api/routes.ts`. The request middleware has already loaded the caller.
 */
export const Route = createFileRoute('/api/$')({
  server: {
    handlers: {
      ANY: async ({ request, context }) => {
        try {
          return await serveApi(request, apiContext(getRuntime(), requestContext(context)));
        } catch (error) {
          return errorResponse(error);
        }
      },
    },
  },
});
