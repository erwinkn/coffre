import { useRouter } from '@tanstack/react-router';

import { CoffreError, type CoffreClient } from '../../../../packages/client/src/index.ts';

/**
 * The API as whoever is looking at the page. In the browser this is plain
 * `fetch` to `/api`, carrying the session cookie; mutations call it straight
 * from event handlers, and loaders read through `context.client`.
 */
export function useCoffre(): CoffreClient {
  return useRouter().options.context.client;
}

/** A refusal the page words itself, shown as it is. */
export class Refusal extends Error {}

type Failure = { ok: false; error: string };

/** The HTTP status of an API error; undefined when the request never got an answer. */
export function statusOf(error: unknown): number | undefined {
  return error instanceof CoffreError ? error.status : undefined;
}

/** What to tell the person when a call fails. */
export function failureMessage(error: unknown): string {
  if (error instanceof Refusal) return error.message;
  if (!(error instanceof CoffreError)) return 'The request could not be sent. Nothing was changed.';
  if (error.status === 401) return 'Your session has ended. Sign in again, then retry.';
  if (error.code === 'cross_origin') return 'coffre refused a change that did not come from this page. Reload, then retry.';
  if (error.status === 403) {
    return 'You hold no grant that covers this. Someone with grant.manage on the project can add one.';
  }
  if (error.status === 404) return 'Not found. It may have been renamed or archived.';
  // A 400 or 409 carries a sentence written for the person, such as which
  // field of a sync's destination is wrong. Anything unexpected stays generic.
  if (error.status === 400 || error.status === 409) return error.message;
  return 'Coffre is unavailable. Nothing was read or written.';
}

export function uiFailure(error: unknown): Failure {
  return { ok: false, error: failureMessage(error) };
}

/** A loader's answer: what it read, or what to say instead. */
export async function uiResult<T extends object>(
  operation: () => Promise<T>,
): Promise<({ ok: true } & T) | Failure> {
  try {
    return { ok: true, ...(await operation()) };
  } catch (error) {
    return uiFailure(error);
  }
}

/** How the API names a member: `user:ada@acme.example`, `token:ci-deploy`. */
export function memberRef(principalType: 'user' | 'service', principalId: string): string {
  return `${principalType === 'user' ? 'user' : 'token'}:${principalId}`;
}
