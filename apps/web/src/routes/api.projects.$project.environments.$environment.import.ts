import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';

import { apiResponse, methodNotAllowed, parseJson, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';
import { slug } from '../shared/schemas.ts';
import { parseDotenv } from '../../../../packages/core/src/dotenv.ts';

const paramsSchema = z.object({ project: slug, environment: slug });

export const Route = createFileRoute('/api/projects/$project/environments/$environment/import')({
  server: {
    handlers: {
      POST: ({ context, params, request }) => apiResponse(async () => {
        const parsed = paramsSchema.parse(params);
        const body = await parseJson(request, (input) => z.object({
          content: z.string().max(1024 * 1024),
          dryRun: z.boolean().default(false),
        }).parse(input));
        const dotenv = parseDotenv(body.content);
        if (dotenv.entries.length === 0 && dotenv.problems.length > 0) {
          return { bundleId: null, plan: [], problems: dotenv.problems };
        }
        const result = await getRuntime().secrets.importSecrets(
          requestContext(context), parsed.project, parsed.environment, dotenv.entries, body.dryRun,
        );
        return { ...result, problems: dotenv.problems };
      }),
      ANY: () => methodNotAllowed(['POST']),
    },
  },
});
