import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import {
  apiResponse,
  methodNotAllowed,
  parseJson,
  requestContext,
} from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { secretKey, slug } from '../shared/schemas.ts';

const paramsSchema = z.object({ project: slug, environment: slug, key: secretKey });

export const Route = createFileRoute('/api/projects/$project/environments/$environment/secrets/$key')({
  server: {
    handlers: {
      GET: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().secrets.readSecret(
          requestContext(context), parsed.project, parsed.environment, parsed.key,
        );
      }),
      PUT: ({ context, params, request }) => apiResponse(async () => {
        const parsed = paramsSchema.parse(params);
        const body = await parseJson(request, (input) =>
          z.object({ value: z.string().max(64 * 1024) }).parse(input));
        return getRuntime().secrets.writeSecret(
          requestContext(context), parsed.project, parsed.environment, parsed.key, body.value,
        );
      }),
      PATCH: ({ context, params, request }) => apiResponse(async () => {
        const parsed = paramsSchema.parse(params);
        const body = await parseJson(request, (input) =>
          z.object({ key: secretKey }).parse(input));
        return getRuntime().secrets.renameSecret(
          requestContext(context), parsed.project, parsed.environment, parsed.key, body.key,
        );
      }),
      ANY: () => methodNotAllowed(['GET', 'PUT', 'PATCH']),
    },
  },
});
