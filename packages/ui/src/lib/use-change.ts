import { useMutation, useMutationState, useQueryClient, type QueryKey } from '@tanstack/react-query';
import { useCallback } from 'react';

import {
  changeKey,
  changeOptions,
  dismiss,
  failedAdds,
  itemStatus,
  type Change,
  type ChangeContext,
} from './optimistic';

/** Make a change that shows before the server answers (`lib/optimistic.ts`). */
export function useChange<TData, TItem, TVars, TResult>(change: Change<TData, TItem, TVars, TResult>) {
  const queryClient = useQueryClient();
  return useMutation(changeOptions(queryClient, change)).mutate;
}

/** How each item of a list stands, from the changes made to it here. */
export function useChangeStatus(list: QueryKey) {
  const queryClient = useQueryClient();
  const changes = useMutationState({
    filters: { mutationKey: changeKey(list) },
    select: (mutation) => ({
      mutationId: mutation.mutationId,
      state: mutation.state as typeof mutation.state & { context: ChangeContext | undefined },
    }),
  });

  const status = useCallback((id: string) => itemStatus(changes, id), [changes]);

  /** Adds the server refused, whose items are not in `present`: rendered as rows of their own. */
  const refusedAdds = useCallback(
    <TVars,>(present: readonly string[]) => failedAdds<TVars>(changes, present),
    [changes],
  );

  const forget = useCallback((mutationId: number) => dismiss(queryClient, mutationId), [queryClient]);

  return { status, failedAdds: refusedAdds, dismiss: forget };
}
