import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import {
  apiResponse,
  methodNotAllowed,
  parseOptionalJson,
  requestContext,
} from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { secretKey, slug } from '../shared/schemas.ts';

const paramsSchema = z.object({ project: slug, environment: slug, key: secretKey });

export const Route = createFileRoute('/api/projects/$project/environments/$environment/secrets/$key/archive')({
  server: {
    handlers: {
      POST: ({ context, params, request }) => apiResponse(async () => {
        const parsed = paramsSchema.parse(params);
        const body = await parseOptionalJson(request, (input) =>
          z.object({ archived: z.boolean().default(true) }).parse(input));
        return getRuntime().secrets.setSecretArchived(
          requestContext(context), parsed.project, parsed.environment, parsed.key, body.archived,
        );
      }),
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
