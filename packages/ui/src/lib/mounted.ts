import { useRouter } from '@tanstack/react-router';

/**
 * Whether the deployment put a page at `path`, a route's full path such as
 * `/audit` or `/projects/$project`: as a route of its own, or as the index
 * of one (`/projects/`), as a file route at `projects.index.tsx` is. A
 * deployment may leave any of coffre's pages out: the nav and the command
 * palette offer only those it kept.
 */
export function useMounted(): (path: string) => boolean {
  const { routesByPath } = useRouter();
  return (path) => Object.hasOwn(routesByPath, path) || Object.hasOwn(routesByPath, `${path}/`);
}
