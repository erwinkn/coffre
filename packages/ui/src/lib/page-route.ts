import { useLoaderData, useParams, useSearch } from '@tanstack/react-router';

/** A page's route options, as `../options.ts` has them. */
type PageOptions = { loader?: (context: never) => unknown; validateSearch?: (search: never) => unknown };

type Params<TOptions extends PageOptions> = Parameters<NonNullable<TOptions['loader']>>[0] extends { params: infer P } ? P : object;

/** Untyped, as the router gives it for a match it cannot name. */
const read = (value: unknown) => value;

/**
 * What a page's component reads of its route, wherever the deployment put
 * it, typed by the page's options: the match it renders in, its loader's
 * data, its params and its search. `pageRoute<typeof project>()`.
 */
export function pageRoute<TOptions extends PageOptions>() {
  return {
    useLoaderData: () => read(useLoaderData({ strict: false })) as Awaited<ReturnType<NonNullable<TOptions['loader']>>>,
    useParams: () => read(useParams({ strict: false })) as Params<TOptions>,
    useSearch: () => read(useSearch({ strict: false })) as ReturnType<NonNullable<TOptions['validateSearch']>>,
  };
}
