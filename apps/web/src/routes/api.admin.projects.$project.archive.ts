import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseOptionalJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { slug } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/projects/$project/archive')({
  server: {
    handlers: {
      POST: ({ context, params, request }) => apiResponse(async () => {
        const { project } = z.object({ project: slug }).parse(params);
        const body = await parseOptionalJson(request, (input) =>
          z.object({ archived: z.boolean().default(true) }).parse(input));
        return getRuntime().admin.setProjectArchived(requestContext(context), project, body.archived);
      }),
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
