import { KekRefusedError, KekUnavailableError } from '@coffre/core/kek';
import { isUnavailable, POOL_FULL, poolFull } from '@coffre/db/dialect';

/**
 * A vault call's failure, as `serveVault` answers it: its message, and the
 * code its causes carry, which `connectVault` puts back on its error, so
 * the app reads it as it would in process. Its database, or a key service,
 * not answering is the app's outage too, not a bug: 503. One only its
 * words say goes as a code that says the same: a pool with no connection
 * to give as `POOL_FULL`, any other (pg's "Connection terminated") as
 * Postgres's code for a connection that failed, 08006. A key service's
 * failure goes with its name too, `KekUnavailableError` or one of its
 * kind, which the app reads to tell an outage (503) from a refusal (500),
 * and which a plain `Error` rebuilt from words would lose.
 */
export function failureOf(error: unknown): { status: number; body: { error: string; code?: string; name?: string } } {
  const message = error instanceof Error ? error.message : 'the vault failed';
  const kek = keyServiceFailure(error);
  if (kek !== undefined) return { status: kek instanceof KekRefusedError ? 500 : 503, body: { error: message, name: kek.name } };
  let code: string | undefined;
  for (let cause = error; typeof cause === 'object' && cause !== null && code === undefined; cause = (cause as { cause?: unknown }).cause) {
    const found = (cause as { code?: unknown }).code;
    if (typeof found === 'string') code = found;
  }
  if (!isUnavailable(error)) return { status: 500, body: code === undefined ? { error: message } : { error: message, code } };
  return { status: 503, body: { error: message, code: code !== undefined && isUnavailable({ code }) ? code : poolFull(error) ? POOL_FULL : '08006' } };
}

/** `error`, or the first of its causes, that is a key service's failure. */
function keyServiceFailure(error: unknown): KekUnavailableError | undefined {
  for (let cause = error; typeof cause === 'object' && cause !== null; cause = (cause as { cause?: unknown }).cause) {
    if (cause instanceof KekUnavailableError) return cause;
  }
  return undefined;
}
