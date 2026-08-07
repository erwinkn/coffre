import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { displayName, slug } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/projects')({
  server: {
    handlers: {
      GET: ({ context }) => apiResponse(async () => ({
        projects: await getRuntime().admin.listProjects(requestContext(context)),
      })),
      POST: ({ context, request }) => apiResponse(async () => {
        const body = await parseJson(request, (input) =>
          z.object({ slug, name: displayName }).parse(input));
        return getRuntime().admin.createProject(requestContext(context), body.slug, body.name);
      }, 201),
      ANY: () => methodNotAllowed(['GET', 'POST']),
    },
  },
});
