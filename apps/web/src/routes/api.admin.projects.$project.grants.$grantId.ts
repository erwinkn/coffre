import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { grantId, slug } from '../shared/schemas.ts';

const paramsSchema = z.object({ project: slug, grantId });

export const Route = createFileRoute('/api/admin/projects/$project/grants/$grantId')({
  server: {
    handlers: {
      DELETE: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().admin.revokeGrant(
          requestContext(context), parsed.project, parsed.grantId,
        );
      }),
      PATCH: ({ context, params, request }) => apiResponse(async () => {
        const parsed = paramsSchema.parse(params);
        const body = await parseJson(request, (input) => z.object({ role: slug }).parse(input));
        return getRuntime().admin.updateGrant(
          requestContext(context), parsed.project, parsed.grantId, body.role,
        );
      }),
      ANY: () => methodNotAllowed(['DELETE', 'PATCH']),
    },
  },
});
