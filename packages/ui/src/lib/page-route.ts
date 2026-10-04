import { useLoaderData, useParams, useSearch, type AnyRoute, type RootRoute } from '@tanstack/react-router';

import type { CoffreContext } from '../routes';

/**
 * A parent to read a page's types at: its params, search and data are its
 * own, whatever it is under. `pageRoute<ReturnType<typeof environment<Parent>>>()`.
 */
export type Parent = RootRoute<unknown, undefined, CoffreContext>;

/** Untyped, as the router gives it for a match it cannot name. */
const read = (value: unknown) => value;

/**
 * What a page's component reads of its route, wherever the deployment put
 * it. coffre's routes are functions of their parent (`routes.ts`), so a page
 * has no route object of its own to import: these read the match it renders
 * in, typed as `TRoute`.
 */
export function pageRoute<TRoute extends AnyRoute>() {
  return {
    useLoaderData: () => read(useLoaderData({ strict: false })) as TRoute['types']['loaderData'],
    useParams: () => read(useParams({ strict: false })) as TRoute['types']['params'],
    useSearch: () => read(useSearch({ strict: false })) as TRoute['types']['searchSchema'],
  };
}
