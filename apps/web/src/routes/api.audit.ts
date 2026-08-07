import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

const querySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(100),
  actorId: z.string().optional(),
  decision: z.enum(['allow', 'deny']).optional(),
});

export const Route = createFileRoute('/api/audit')({
  server: {
    handlers: {
      GET: ({ context, request }) => apiResponse(async () => {
        const query = querySchema.parse(Object.fromEntries(new URL(request.url).searchParams));
        return { entries: await getRuntime().audit.list(requestContext(context), query) };
      }),
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
