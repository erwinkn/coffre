import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime, principalReport } from '../server/runtime.ts';
import { principalId, principalType } from '../shared/schemas.ts';

const paramsSchema = z.object({
  principalType,
  principalId,
});

export const Route = createFileRoute('/api/admin/directory/$principalType/$principalId')({
  server: {
    handlers: {
      GET: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return principalReport(
          getRuntime(), requestContext(context), parsed.principalType, parsed.principalId,
        );
      }),
      DELETE: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().admin.removeDirectoryPrincipal(
          requestContext(context), parsed.principalType, parsed.principalId,
        );
      }),
      ANY: () => methodNotAllowed(['GET', 'DELETE']),
    },
  },
});
