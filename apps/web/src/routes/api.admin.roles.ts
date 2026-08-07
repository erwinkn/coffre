import { createFileRoute } from '@tanstack/react-router';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

export const Route = createFileRoute('/api/admin/roles')({
  server: {
    handlers: {
      GET: ({ context }) => apiResponse(async () => {
        requestContext(context);
        return { roles: await getRuntime().admin.listRoles() };
      }),
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
