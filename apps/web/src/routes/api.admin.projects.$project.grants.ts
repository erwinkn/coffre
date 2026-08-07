import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { isoDateTime, principalId, principalType, slug } from '../shared/schemas.ts';

export const Route = createFileRoute('/api/admin/projects/$project/grants')({
  server: {
    handlers: {
      GET: ({ context, params }) => apiResponse(async () => {
        const { project } = z.object({ project: slug }).parse(params);
        return { grants: await getRuntime().admin.listGrants(requestContext(context), project) };
      }),
      POST: ({ context, params, request }) => apiResponse(async () => {
        const { project } = z.object({ project: slug }).parse(params);
        const body = await parseJson(request, (input) => z.object({
          principalType,
          principalId,
          role: slug,
          environmentSlug: slug.nullish(),
          expiresAt: isoDateTime.nullish(),
        }).parse(input));
        return getRuntime().admin.createGrant(requestContext(context), project, body);
      }, 201),
      ANY: () => methodNotAllowed(['GET', 'POST']),
    },
  },
});
