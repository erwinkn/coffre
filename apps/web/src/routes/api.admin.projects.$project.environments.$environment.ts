import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { displayName, slug } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/projects/$project/environments/$environment')({
  server: {
    handlers: {
      PATCH: ({ context, params, request }) => apiResponse(async () => {
        const parsed = z.object({ project: slug, environment: slug }).parse(params);
        const body = await parseJson(request, (input) => z.object({
          slug: slug.optional(),
          name: displayName.optional(),
        }).parse(input));
        return getRuntime().admin.updateEnvironment(
          requestContext(context), parsed.project, parsed.environment, body,
        );
      }),
      ANY: () => methodNotAllowed(['PATCH']),
    },
  },
});
