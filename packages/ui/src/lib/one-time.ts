import { useEffect, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';

/**
 * A notice that rides in the URL once, as a sign-in's `?error=` does: read
 * as the page first renders, on the server, so it shows without JavaScript;
 * then taken out of the address, the history entry replaced, so that a
 * reload is a clean retry and a copied link carries no stale error. What was
 * read stays shown until the page is left.
 *
 * Why the URL and not a one-time cookie: the URL is the one thing the server
 * renders from, so nothing has to be set on the redirect, read by the
 * render and cleared by exactly the right response, which streaming and the
 * requests a page fires beside it make fragile. The cost: without
 * JavaScript, a reload shows the notice again, and coffre's pages need
 * JavaScript for everything else.
 */
export function useOneTime<T extends Record<string, unknown>, K extends keyof T & string>(search: T, names: readonly K[]): Pick<T, K> {
  const [kept] = useState(() => Object.fromEntries(names.map((name) => [name, search[name]])) as Pick<T, K>);
  const navigate = useNavigate();
  const present = names.some((name) => search[name] !== undefined);
  useEffect(() => {
    if (!present) return;
    void navigate({
      to: '.',
      search: (previous: Record<string, unknown>) => Object.fromEntries(Object.entries(previous).filter(([name]) => !(names as readonly string[]).includes(name))),
      replace: true,
    });
    // Once, after hydration: later renders keep what was read.
  }, []);
  return kept;
}
