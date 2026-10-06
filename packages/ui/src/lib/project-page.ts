import { useSuspenseQuery } from '@tanstack/react-query';

import { useCoffre } from './coffre';
import { projectOf, queries } from './queries';

/**
 * The project one of its tabs shows, as its layout found it: the layout
 * renders a tab only once the project is there for its visitor.
 */
export function useProject(slug: string) {
  const found = projectOf(useSuspenseQuery(queries.projects(useCoffre())).data, slug);
  if (!found.ok) throw new Error(`no project "${slug}" for this tab`);
  return found;
}
