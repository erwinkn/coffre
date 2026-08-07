import { createFileRoute } from '@tanstack/react-router';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getMe } from '../server/queries/me.ts';
import { getRuntime } from '../server/runtime.ts';

export const Route = createFileRoute('/api/me')({
  server: {
    handlers: {
      GET: ({ context }) =>
        apiResponse(() => getMe(getRuntime(), requestContext(context))),
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
