// The server functions Start finds by id: one, which redirects.
import { redirect } from '@tanstack/react-router';

export async function getServerFnById(id: string) {
  if (id !== 'redirects') throw new Error(`no server function ${id}`);
  return async () => ({ error: redirect({ to: '/done' }) });
}
