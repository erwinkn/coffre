import { useQueryClient, type QueryKey } from '@tanstack/react-query';
import { useState } from 'react';

import { failureMessage } from './coffre';
import { refresh } from './queries';

/**
 * Run a change against the API, then refetch what it touched. A failed call
 * leaves the page as it was and says why, in `error`.
 *
 * Each change names what it touches (`affects` in `lib/queries.ts`), and
 * those queries are refetched before the change counts as done: at once where
 * they are on screen, such as the sidebar's project tree, and on next use
 * where they are not. So your own change always shows, and nothing else is
 * asked for again.
 */
export function useAction() {
  const queryClient = useQueryClient();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run<T>(
    fn: () => Promise<T>,
    {
      affects,
      onSuccess,
    }: {
      affects: QueryKey[] | ((result: T) => QueryKey[]);
      // `unknown` rather than `void`, so a one-expression callback can end in
      // `toast.success(...)` -- which returns an id -- without a block body.
      onSuccess?: (result: T) => unknown;
    },
  ): Promise<void> {
    setPending(true);
    let result: T;
    try {
      result = await fn();
    } catch (failure) {
      setError(failureMessage(failure));
      setPending(false);
      return;
    }

    setError(null);
    try {
      await refresh(queryClient, typeof affects === 'function' ? affects(result) : affects);
      await onSuccess?.(result);
    } catch {
      setError('The change was saved, but the page could not refresh. Reload before you retry.');
    }
    setPending(false);
  }

  return { pending, error, setError, run };
}
