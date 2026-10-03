import type { Mutation, MutationOptions, QueryClient, QueryKey } from '@tanstack/react-query';

import { announce } from './announce.ts';
import { failureMessage } from './coffre.ts';
import { refresh } from './queries.ts';

/**
 * Changes that show before the server answers.
 *
 * An add or an edit shows at once, as it will be, marked as saving; a removal
 * keeps its row, struck through, until the server confirms it, since access
 * must never look gone while it still holds. Either way, if the server
 * refuses, the list goes back to what it was and the row says why
 * (`failureMessage`: the API's own sentence where it gives one), until
 * dismissed or retried.
 *
 * Several changes can be in flight at once, so a failure undoes its own
 * items only, not the whole list as it was when it started; and the list is
 * read back from the server once the last change to it has landed, so one
 * landing does not erase another still on its way.
 */

/** What a row is waiting for. */
export type Pending = 'saving' | 'removing';

/** One item a change touches, and how. */
export type Target = { id: string; kind: Pending };

/** How a change is worded on its row: "Archiving…", "Not archived." */
export type Words = { pending: string; done: string; failed: string };

const WORDS: Record<Pending, Words> = {
  saving: { pending: 'Saving…', done: 'saved', failed: 'Not saved.' },
  removing: { pending: 'Removing…', done: 'removed', failed: 'Not removed.' },
};

/** How one cached query holds a list of items, each with an identity. */
export type ListShape<TData, TItem> = {
  queryKey: QueryKey;
  items: (data: TData) => TItem[];
  withItems: (data: TData, items: TItem[]) => TData;
  id: (item: TItem) => string;
};

export type Change<TData, TItem, TVars, TResult> = {
  list: ListShape<TData, TItem>;
  /** What the change is called, for the screen reader: "access for dev@acme.example". */
  label: (vars: TVars) => string;
  /**
   * The items it touches, whose rows show it: saved ones as they will be,
   * removed ones as they are until confirmed. A rename touches both names.
   */
  targets: (vars: TVars) => Target[];
  /** How removals are worded, when not as removals: archiving, revoking. */
  removing?: Words;
  /** The items as they will be once the saves land; removals are left for the server. */
  apply?: (items: TItem[], vars: TVars) => TItem[];
  /** The items once the server confirms; by default, without those removed. Archiving keeps them, archived. */
  confirmed?: (items: TItem[], vars: TVars, removed: ReadonlySet<string>) => TItem[];
  /** Anything else it touches, refetched once it lands (`affects` in `queries.ts`). */
  affects: (vars: TVars, result: TResult | undefined) => QueryKey[];
  run: (vars: TVars) => Promise<TResult>;
};

/** What `onMutate` keeps: the list as it was, and what the rows should show. */
export type ChangeContext = { previous: unknown; targets: Target[]; words: Record<Pending, Words> };

/** Every optimistic change is keyed under this, then its list's key. */
export const CHANGE = 'change';

export function changeKey(list: QueryKey): QueryKey {
  return [CHANGE, ...list];
}

export function changeOptions<TData, TItem, TVars, TResult>(
  queryClient: QueryClient,
  change: Change<TData, TItem, TVars, TResult>,
): MutationOptions<TResult, unknown, TVars, ChangeContext> {
  const { list } = change;
  const mutationKey = changeKey(list.queryKey);
  return {
    mutationKey,
    mutationFn: change.run,
    onMutate: async (vars) => {
      const targets = change.targets(vars);
      const words = { saving: WORDS.saving, removing: change.removing ?? WORDS.removing };
      announce(`${change.label(vars)}: ${words[mainKind(targets)].pending}`);
      // A read already on its way would land over the change.
      await queryClient.cancelQueries({ queryKey: list.queryKey });
      const previous = queryClient.getQueryData<TData>(list.queryKey);
      if (change.apply !== undefined && previous !== undefined) {
        const apply = change.apply;
        queryClient.setQueryData<TData>(list.queryKey, (current) =>
          current === undefined ? current : list.withItems(current, apply(list.items(current), vars)),
        );
      }
      return { previous, targets, words };
    },
    onError: (error, vars, context) => {
      if (context === undefined) return;
      announce(
        `${change.label(vars)}: ${context.words[mainKind(context.targets)].failed} ${failureMessage(error)}`,
        { urgent: true },
      );
      if (context.previous === undefined || change.apply === undefined) return;
      const previous = context.previous as TData;
      const saved = context.targets.filter((target) => target.kind === 'saving').map((target) => target.id);
      queryClient.setQueryData<TData>(list.queryKey, (current) =>
        current === undefined ? current : revert(list, current, previous, saved),
      );
    },
    onSuccess: (_result, vars, context) => {
      if (context === undefined) return;
      announce(`${capitalize(change.label(vars))} ${context.words[mainKind(context.targets)].done}`);
      // Confirmed: the rows removed can go now, before the list is read back.
      const gone = new Set(
        context.targets.filter((target) => target.kind === 'removing').map((target) => target.id),
      );
      if (gone.size > 0) {
        const confirmed =
          change.confirmed ?? ((items: TItem[]) => items.filter((item) => !gone.has(list.id(item))));
        queryClient.setQueryData<TData>(list.queryKey, (current) =>
          current === undefined ? current : list.withItems(current, confirmed(list.items(current), vars, gone)),
        );
      }
    },
    onSettled: (result, _error, vars) => {
      // This one still counts as in flight here.
      if (queryClient.isMutating({ mutationKey }) > 1) return;
      // Not awaited: the row settles when the server answers, and the list
      // is read back behind it.
      void refresh(queryClient, [list.queryKey, ...change.affects(vars, result)]);
    },
  };
}

/**
 * The list with one change undone: each target as it was before, wherever
 * it now is, and gone if it was not there. Everything else stays as it is,
 * including other changes still in flight.
 */
export function revert<TData, TItem>(
  list: ListShape<TData, TItem>,
  current: TData,
  previous: TData,
  targets: string[],
): TData {
  const before = list.items(previous);
  let items = list.items(current).filter((item) => !targets.includes(list.id(item)));
  for (const id of targets) {
    const index = before.findIndex((item) => list.id(item) === id);
    if (index === -1) continue;
    // Back where it was, counting only what is still there before it.
    const after = before
      .slice(0, index)
      .filter((item) => items.some((kept) => list.id(kept) === list.id(item))).length;
    items = [...items.slice(0, after), before[index]!, ...items.slice(after)];
  }
  return list.withItems(current, items);
}

/** What a change mostly does, to word it as a whole: a save, unless it only removes. */
function mainKind(targets: Target[]): Pending {
  return targets.length > 0 && targets.every((target) => target.kind === 'removing') ? 'removing' : 'saving';
}

/** What a row shows: nothing, a change on its way, or one the server refused. */
export type ItemStatus =
  | { state: 'idle' }
  | { state: 'pending'; kind: Pending; words: Words }
  | { state: 'failed'; kind: Pending; words: Words; error: string; mutationId: number };

type Tracked = Pick<Mutation<unknown, unknown, unknown, ChangeContext>, 'mutationId' | 'state'>;

/**
 * An item's status, from the changes to its list: the latest one that
 * touches it decides, so retrying clears an old failure.
 */
export function itemStatus(changes: readonly Tracked[], id: string): ItemStatus {
  let latest: Tracked | undefined;
  for (const change of changes) {
    if (change.state.context?.targets.some((target) => target.id === id) !== true) continue;
    if (latest === undefined || change.state.submittedAt >= latest.state.submittedAt) latest = change;
  }
  const context = latest?.state.context;
  if (latest === undefined || context === undefined) return { state: 'idle' };
  const kind = context.targets.find((target) => target.id === id)!.kind;
  const words = context.words[kind];
  if (latest.state.status === 'pending') return { state: 'pending', kind, words };
  if (latest.state.status === 'error') {
    const error = failureMessage(latest.state.error);
    return { state: 'failed', kind, words, error, mutationId: latest.mutationId };
  }
  return { state: 'idle' };
}

/** A refused add: no row is left to say so, so it gets one of its own. */
export type FailedAdd<TVars> = {
  mutationId: number;
  vars: TVars;
  /** The ids it would have added. */
  ids: string[];
  status: Extract<ItemStatus, { state: 'failed' }>;
};

/**
 * The adds the server refused whose items are not listed: each is shown as
 * a row of its own. Asked again and refused again, an add is listed once,
 * as the latest refusal.
 */
export function failedAdds<TVars>(changes: readonly Tracked[], present: readonly string[]): FailedAdd<TVars>[] {
  return changes.flatMap((change) => {
    const context = change.state.context;
    if (change.state.status !== 'error' || context === undefined) return [];
    const added = context.targets.filter((target) => target.kind === 'saving' && !present.includes(target.id));
    if (added.length === 0 || added.length < context.targets.length) return [];
    const status = itemStatus(changes, added[0]!.id);
    if (status.state !== 'failed' || status.mutationId !== change.mutationId) return [];
    const ids = added.map((target) => target.id);
    return [{ mutationId: change.mutationId, vars: change.state.variables as TVars, ids, status }];
  });
}

/** Forget a failure once its row has said so and been dismissed. */
export function dismiss(queryClient: QueryClient, mutationId: number): void {
  const cache = queryClient.getMutationCache();
  const mutation = cache.getAll().find((entry) => entry.mutationId === mutationId);
  if (mutation !== undefined) cache.remove(mutation);
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
