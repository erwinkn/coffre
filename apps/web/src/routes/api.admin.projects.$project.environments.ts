import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { displayName, slug } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/projects/$project/environments')({
  server: {
    handlers: {
      POST: ({ context, params, request }) => apiResponse(async () => {
        const { project } = z.object({ project: slug }).parse(params);
        const body = await parseJson(request, (input) =>
          z.object({ slug, name: displayName }).parse(input));
        return getRuntime().admin.createEnvironment(
          requestContext(context), project, body.slug, body.name,
        );
      }, 201),
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
