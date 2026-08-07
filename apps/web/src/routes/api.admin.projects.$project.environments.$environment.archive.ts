import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseOptionalJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { slug } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/projects/$project/environments/$environment/archive')({
  server: {
    handlers: {
      POST: ({ context, params, request }) => apiResponse(async () => {
        const parsed = z.object({ project: slug, environment: slug }).parse(params);
        const body = await parseOptionalJson(request, (input) =>
          z.object({ archived: z.boolean().default(true) }).parse(input));
        return getRuntime().admin.setEnvironmentArchived(
          requestContext(context), parsed.project, parsed.environment, body.archived,
        );
      }),
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
