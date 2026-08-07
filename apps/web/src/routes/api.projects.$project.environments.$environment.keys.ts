import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { slug } from '../shared/schemas.ts';

const paramsSchema = z.object({ project: slug, environment: slug });

export const Route = createFileRoute('/api/projects/$project/environments/$environment/keys')({
  server: {
    handlers: {
      GET: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().secrets.listKeys(
          requestContext(context), parsed.project, parsed.environment,
        );
      }),
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
