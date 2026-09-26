import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { syncId } from '../shared/schemas.ts';

const paramsSchema = z.object({ sync: syncId });

export const Route = createFileRoute('/api/syncs/$sync/run')({
  server: {
    handlers: {
      POST: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().syncs.runNow(requestContext(context), parsed.sync);
      }),
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
