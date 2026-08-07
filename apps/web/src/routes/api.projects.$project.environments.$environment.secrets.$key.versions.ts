import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { secretKey, slug } from '../shared/schemas.ts';

const paramsSchema = z.object({ project: slug, environment: slug, key: secretKey });

export const Route = createFileRoute('/api/projects/$project/environments/$environment/secrets/$key/versions')({
  server: {
    handlers: {
      GET: ({ context, params }) => apiResponse(() => {
        const parsed = paramsSchema.parse(params);
        return getRuntime().secrets.listVersions(
          requestContext(context), parsed.project, parsed.environment, parsed.key,
        );
      }),
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
