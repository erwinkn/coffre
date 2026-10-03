import { useSuspenseQueries } from '@tanstack/react-query';
import { useMemo } from 'react';

import { useCoffre } from './coffre';
import { queries, shellOf, type Shell } from './queries';

/**
 * The shell as a component reads it: from the same queries the root loader
 * fetched, so it follows any change that refetches them.
 */
export function useShell(): Shell {
  const client = useCoffre();
  const [auth, me, projects] = useSuspenseQueries({
    queries: [queries.auth(client), queries.me(client), queries.projects(client)],
  });
  return useMemo(() => shellOf(auth.data, me.data, projects.data), [auth.data, me.data, projects.data]);
}
