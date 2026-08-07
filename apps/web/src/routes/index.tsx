import { createFileRoute, redirect } from '@tanstack/react-router';

/**
 * The root is the project list, one level up.
 *
 * Projects live under `/projects/:slug` rather than at `/:slug` so that a
 * project may be called `audit` or `login` without shadowing the page of that
 * name. Nothing renders here; `/` only exists so the obvious URL still lands
 * somewhere.
 */
export const Route = createFileRoute('/')({
  beforeLoad: () => {
    throw redirect({ to: '/projects' });
  },
});
