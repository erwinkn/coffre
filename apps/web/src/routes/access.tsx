import { createFileRoute, redirect } from '@tanstack/react-router';

/**
 * The directory used to be one page here. It is now Members and Tokens; the
 * old address still lands somewhere sensible for bookmarks and links.
 */
export const Route = createFileRoute('/access')({
  beforeLoad: () => {
    throw redirect({ to: '/members' });
  },
});
