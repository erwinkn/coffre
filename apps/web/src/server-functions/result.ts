import { CoffreError } from '../../../../packages/client/src/index.ts';
import { ApiError } from '../server/api/errors.ts';

type Failure = { ok: false; error: string };

/** The HTTP status of an API error, from the client or straight from a handler. */
export function statusOf(error: unknown): number | undefined {
  return error instanceof CoffreError || error instanceof ApiError ? error.status : undefined;
}

export function uiFailure(error: unknown): Failure {
  const status = statusOf(error);
  if (status === 403) {
    return {
      ok: false,
      error:
        'You hold no grant that covers this. Someone with grant.manage on the project can add one.',
    };
  }
  if (status === 404) {
    return { ok: false, error: 'Not found. It may have been renamed or archived.' };
  }
  if (status === 409) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : 'That conflicts with existing data.',
    };
  }
  // A 400 carries a sentence written for the person, such as which field of
  // a sync's destination is wrong. Anything unexpected stays generic.
  if (status === 400 && error instanceof Error) {
    return { ok: false, error: error.message };
  }
  return { ok: false, error: 'Coffre is unavailable. Nothing was read or written.' };
}

export async function uiResult<T extends object>(
  operation: () => Promise<T>,
): Promise<({ ok: true } & T) | Failure> {
  try {
    return { ok: true, ...(await operation()) };
  } catch (error) {
    return uiFailure(error);
  }
}

export async function uiMutation(
  operation: () => Promise<unknown>,
): Promise<{ ok: true } | Failure> {
  try {
    await operation();
    return { ok: true };
  } catch (error) {
    return uiFailure(error);
  }
}
