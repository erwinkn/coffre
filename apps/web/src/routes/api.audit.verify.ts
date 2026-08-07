import { createFileRoute } from '@tanstack/react-router';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

export const Route = createFileRoute('/api/audit/verify')({
  server: {
    handlers: {
      GET: ({ context }) => apiResponse(() =>
        getRuntime().audit.verify(requestContext(context))),
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
