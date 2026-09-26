import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { syncId } from '../shared/schemas.ts';

const paramsSchema = z.object({ sync: syncId });

export const Route = createFileRoute('/api/syncs/$sync')({
  server: {
    handlers: {
      PATCH: ({ context, params, request }) => apiResponse(async () => {
        const parsed = paramsSchema.parse(params);
        const body = await parseJson(request, (input) => z.object({ paused: z.boolean() }).parse(input));
        return getRuntime().syncs.setPaused(requestContext(context), parsed.sync, body.paused);
      }),
      // Archives: coffre stops pushing, and what it pushed stays at the destination.
      DELETE: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().syncs.archive(requestContext(context), parsed.sync);
      }),
      ANY: () => methodNotAllowed(['PATCH', 'DELETE']),
    },
  },
});
