import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { displayName, slug } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/projects/$project')({
  server: {
    handlers: {
      PATCH: ({ context, params, request }) => apiResponse(async () => {
        const { project } = z.object({ project: slug }).parse(params);
        const body = await parseJson(request, (input) => z.object({
          slug: slug.optional(),
          name: displayName.optional(),
        }).parse(input));
        return getRuntime().admin.updateProject(requestContext(context), project, body);
      }),
      ANY: () => methodNotAllowed(['PATCH']),
    },
  },
});
