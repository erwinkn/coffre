import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { instanceRole, principalId, principalType } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/directory')({
  server: {
    handlers: {
      GET: ({ context }) => apiResponse(async () => ({
        principals: await getRuntime().admin.listDirectory(requestContext(context)),
      })),
      POST: ({ context, request }) => apiResponse(async () => {
        const body = await parseJson(request, (input) => z.object({
          principalType,
          principalId,
          instanceRole: instanceRole.default('user'),
        }).parse(input));
        return getRuntime().admin.addDirectoryPrincipal(requestContext(context), body);
      }, 201),
      ANY: () => methodNotAllowed(['GET', 'POST']),
    },
  },
});
