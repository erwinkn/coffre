import { useQueryClient, type QueryClient, type QueryKey } from '@tanstack/react-query';
import { useState } from 'react';

import { failureMessage, landedUnread } from './coffre.ts';
import { refresh } from './queries.ts';

/**
 * Run a change against the API, then refetch what it touched. A failed call
 * leaves the page as it was and says why, in `error`.
 *
 * Each change names what it touches (`affects` in `lib/queries.ts`), and
 * those queries are refetched before the change counts as done: at once where
 * they are on screen, such as the sidebar's project tree, and on next use
 * where they are not. So your own change always shows, and nothing else is
 * asked for again.
 *
 * A change the server answered with a success cut off on the way
 * (`landedUnread`) was made, but its answer is lost: what it touched is read
 * again (everything, when what it touched is named from that answer), and
 * `error` says the answer was lost, since `onSuccess` needs it.
 */
export function useAction() {
  const queryClient = useQueryClient();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run<T>(fn: () => Promise<T>, then: Then<T>): Promise<void> {
    setPending(true);
    await act(queryClient, fn, then, setError);
    setPending(false);
  }

  return { pending, error, setError, run };
}

/** What a change touches, and what to do once it is done and they are read again. */
export type Then<T> = {
  affects: QueryKey[] | ((result: T) => QueryKey[]);
  // `unknown` rather than `void`, so a one-expression callback can end in
  // `toast.success(...)` -- which returns an id -- without a block body.
  onSuccess?: (result: T) => unknown;
};

/**
 * `useAction`'s `run` without the page: `say` is told what to show, null
 * once the call went through (before `onSuccess`, which may say more), or
 * why it failed.
 */
export async function act<T>(
  queryClient: QueryClient,
  fn: () => Promise<T>,
  { affects, onSuccess }: Then<T>,
  say: (error: string | null) => void,
): Promise<void> {
  let result: T;
  try {
    result = await fn();
  } catch (failure) {
    if (landedUnread(failure)) {
      await (typeof affects === 'function' ? queryClient.invalidateQueries() : refresh(queryClient, affects)).catch(() => {});
    }
    say(failureMessage(failure));
    return;
  }
  say(null);
  try {
    await refresh(queryClient, typeof affects === 'function' ? affects(result) : affects);
    await onSuccess?.(result);
  } catch {
    say('The change was saved, but the page could not refresh. Reload before you retry.');
  }
}
