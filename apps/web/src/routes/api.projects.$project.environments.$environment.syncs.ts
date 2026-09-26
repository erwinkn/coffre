import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { slug } from '../shared/schemas.ts';

const paramsSchema = z.object({ project: slug, environment: slug });

// The provider validates its own config, with messages that name the field.
const createSchema = z.object({
  provider: z.string().min(1).max(64),
  config: z.record(z.string(), z.unknown()),
  credential: z.string().min(1).max(400),
});

export const Route = createFileRoute('/api/projects/$project/environments/$environment/syncs')({
  server: {
    handlers: {
      GET: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().syncs.list(requestContext(context), parsed.project, parsed.environment);
      }),
      POST: ({ context, params, request }) => apiResponse(async () => {
        const parsed = paramsSchema.parse(params);
        const body = await parseJson(request, (input) => createSchema.parse(input));
        return getRuntime().syncs.create(requestContext(context), parsed.project, parsed.environment, body);
      }, 201),
      ANY: () => methodNotAllowed(['GET', 'POST']),
    },
  },
});
