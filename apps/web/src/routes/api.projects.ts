import { createFileRoute } from '@tanstack/react-router';

import { apiResponse, methodNotAllowed, requestContext } from '../server/http.ts';
import { getRuntime } from '../server/runtime.ts';

export const Route = createFileRoute('/api/projects')({
  server: {
    handlers: {
      GET: ({ context }) => apiResponse(async () => {
        const accessible = await getRuntime().secrets.listAccessible(requestContext(context));
        const projects = new Map<string, { slug: string; environments: unknown[] }>();
        for (const entry of accessible) {
          const project = projects.get(entry.project) ?? { slug: entry.project, environments: [] };
          project.environments.push({
            slug: entry.environment,
            permissions: entry.permissions,
          });
          projects.set(entry.project, project);
        }
        return { projects: [...projects.values()] };
      }),
      ANY: () => methodNotAllowed(['GET']),
    },
  },
});
