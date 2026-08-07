import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { principalId, principalType } from '../shared/schemas.ts';

const paramsSchema = z.object({
  principalType,
  principalId,
});

export const Route = createFileRoute('/api/admin/principals/$principalType/$principalId')({
  server: {
    handlers: {
      DELETE: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().admin.removePrincipal(
          requestContext(context), parsed.principalType, parsed.principalId,
        );
      }),
      ANY: () => methodNotAllowed(['DELETE']),
    },
  },
});
