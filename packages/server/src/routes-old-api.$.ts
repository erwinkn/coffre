import { createFileRoute } from '@tanstack/react-router';

import { fetchApi } from '../server/fetch-api.ts';
import { getRuntime } from '../server/runtime.ts';

/**
 * Every `/api` call but sign-in's own, served from one route table; see
 * `server/api/routes.ts`. `fetchApi` authenticates the caller itself.
 */
export const Route = createFileRoute('/api/$')({
  server: {
    handlers: {
      ANY: ({ request }) => fetchApi(request, getRuntime()),
    },
  },
});
