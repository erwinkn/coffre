import { CoffreError, type CoffreClient } from '@coffre/client';
import { useRouter } from '@tanstack/react-router';

import type { CoffreContext } from '../options';

/**
 * The API as whoever is looking at the page, with their permissions: what
 * coffre's pages call, and a deployment's own may too. In the browser this
 * is plain `fetch` to `/api`, carrying the session cookie; on the server,
 * the API in process. Components call it from event handlers; loaders read
 * the same client as `context.coffre`.
 */
export function useCoffre(): CoffreClient {
  return (useRouter().options.context as CoffreContext).coffre;
}

/** A refusal the page words itself, shown as it is. */
export class Refusal extends Error {}

/** A call that failed: what to say, and whether signing in again would help, which it does only for an ended session. */
type Failure = { ok: false; error: string; signedOut: boolean };

/** The HTTP status of an API error; undefined when the request never got an answer. */
export function statusOf(error: unknown): number | undefined {
  return error instanceof CoffreError ? error.status : undefined;
}

/**
 * A write coffre answered with a success whose answer was cut off on the way
 * (the client's `unreadable`): what was asked was done, and its answer is
 * lost. Not a refusal: nothing is to be undone, and what it touched is to be
 * read again. A read so answered is no such thing: it read nothing, and a
 * change that reads before it writes (an invite looks for the person first)
 * stopped there, so it failed, and may be retried.
 */
export function landedUnread(error: unknown): boolean {
  return (
    error instanceof CoffreError &&
    error.code === 'unreadable' &&
    error.status < 400 &&
    error.method !== undefined &&
    !READS.has(error.method)
  );
}

const READS = new Set(['GET', 'HEAD']);

/** What to tell the person when a call fails. */
export function failureMessage(error: unknown): string {
  if (error instanceof Refusal) return error.message;
  if (!(error instanceof CoffreError)) return 'The request could not be sent. Nothing was changed.';
  if (error.status === 401) return 'Your session has ended. Sign in again, then retry.';
  // A success whose answer was cut off (the client's `unreadable`): what was asked was done, unread.
  if (error.code === 'unreadable') return 'coffre’s answer was cut off on the way. Reload to see where things stand.';
  if (error.code === 'cross_origin') return 'coffre refused a change that did not come from this page. Reload, then retry.';
  // The vault's own rule, which the app could not foresee (one removed by someone else, say), in its words.
  if (error.code === 'vault_refused' && error.reason === 'not_allowed') return error.message.replace(/^the vault refused: /, '');
  // Asked and not given (the dialog closed, `lib/fresh.ts`): nothing was changed, and the next try asks again.
  if (error.code === 'fresh_check_required') {
    return error.reason === 'add_passkey'
      ? 'This takes a passkey, and you have none yet. Nothing was changed.'
      : 'This takes a fresh touch of your passkey. Nothing was changed: try again, and confirm it’s you.';
  }
  if (error.status === 403) {
    return 'You hold no grant that covers this. Someone with grant.manage on the project can add one.';
  }
  if (error.status === 404) return 'Not found. It may have been renamed or archived.';
  // A 400 or 409 carries a sentence written for the person, such as which
  // field of a request is wrong, which names a service account as people
  // do, service:<name>. Anything unexpected stays generic.
  if (error.status === 400 || error.status === 409) return error.message;
  return 'coffre is unavailable. Nothing was read or written.';
}

export function uiFailure(error: unknown): Failure {
  return { ok: false, error: failureMessage(error), signedOut: statusOf(error) === 401 };
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

/** How the API names a member: `user:ada@acme.example`, `token:ci-deploy` (which people read as `service:ci-deploy`). */
export function memberRef(principalType: 'user' | 'service', principalId: string): string {
  return `${principalType === 'user' ? 'user' : 'token'}:${principalId}`;
}
