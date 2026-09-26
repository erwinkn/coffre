import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime, principalReport } from '../server/runtime.ts';
import { instanceRole, principalId } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/directory/user/$principalId')({
  server: {
    handlers: {
      // This route is more specific than directory/$principalType/$principalId,
      // so it answers every method for people, not only the ones below.
      GET: ({ context, params }) => apiResponse(() => {
        const parsed = z.object({ principalId }).parse(params);
        return principalReport(getRuntime(), requestContext(context), 'user', parsed.principalId);
      }),
      DELETE: ({ context, params }) => apiResponse(() => {
        const parsed = z.object({ principalId }).parse(params);
        return getRuntime().admin.removeDirectoryPrincipal(
          requestContext(context), 'user', parsed.principalId,
        );
      }),
      PATCH: ({ context, params, request }) => apiResponse(async () => {
        const parsed = z.object({ principalId }).parse(params);
        const body = await parseJson(request, (input) =>
          z.object({ instanceRole }).parse(input));
        return getRuntime().admin.updateDirectoryPrincipalRole(
          requestContext(context), parsed.principalId, body.instanceRole,
        );
      }),
      ANY: () => methodNotAllowed(['GET', 'DELETE', 'PATCH']),
    },
  },
});
