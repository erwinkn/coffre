import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { secretKey, slug } from '../shared/schemas.ts';

const paramsSchema = z.object({ project: slug, environment: slug, key: secretKey });

export const Route = createFileRoute('/api/projects/$project/environments/$environment/secrets/$key/rollback')({
  server: {
    handlers: {
      POST: ({ context, params, request }) => apiResponse(async () => {
        const parsed = paramsSchema.parse(params);
        const body = await parseJson(request, (input) =>
          z.object({ version: z.number().int().positive() }).parse(input));
        return getRuntime().secrets.rollback(
          requestContext(context), parsed.project, parsed.environment, parsed.key, body.version,
        );
      }),
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
