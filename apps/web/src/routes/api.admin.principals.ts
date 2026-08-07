import { createFileRoute } from '@tanstack/react-router';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

export const Route = createFileRoute('/api/admin/principals')({
  server: {
    handlers: {
      GET: ({ context }) => apiResponse(async () => ({
        principals: await getRuntime().admin.listPrincipals(requestContext(context)),
      })),
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
