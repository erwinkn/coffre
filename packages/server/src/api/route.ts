import { environmentPath, folderName, roleId, secretKey, slug } from '@coffre/core/schemas';
import { z } from 'zod';

import type { ApiContext } from './context.ts';

/**
 * A route of the API: what it takes, and its handler. Each area's are in a
 * file of its own (`routes/`), and `routes.ts` is all of them.
 */

type ParamNames<Pattern> = Pattern extends `${string}:${infer Name}/${infer Rest}`
  ? Name | ParamNames<`/${Rest}`>
  : Pattern extends `${string}:${infer Name}`
    ? Name
    : never;

export type Params<Key> = { [Name in ParamNames<Key>]: string };

type Schema = z.ZodType | undefined;
type Parsed<S extends Schema> = S extends z.ZodType ? z.output<S> : undefined;

export type Route<Key extends string, S extends Schema, Output, Q extends Schema = undefined> = {
  /** The body, or the query string for a GET. */
  input?: S;
  /** Flags in the query string of a route that takes a body, such as `?dryRun=1`. */
  query?: Q;
  run: (ctx: ApiContext, call: { params: Params<Key>; input: Parsed<S>; query: Parsed<Q> }) => Promise<Output>;
};

export function route<
  const Key extends string,
  S extends Schema = undefined,
  Output = unknown,
  Q extends Schema = undefined,
>(key: Key, def: Route<Key, S, Output, Q>): { [K in Key]: Route<Key, S, Output, Q> } {
  return { [key]: def } as { [K in Key]: Route<Key, S, Output, Q> };
}

/** What each named segment of a path may hold. */
export const PARAMS: Record<string, z.ZodType<string>> = {
  project: slug,
  // A slug, or `<slug>@me` for the caller's personal config of it.
  environment: environmentPath,
  key: secretKey,
  member: z.string().min(3).max(330),
  id: z.string().uuid(),
  folder: folderName,
  role: roleId,
};
