import { isStackOverflow } from '@coffre/core/vault';
import { isUnavailable } from '@coffre/db/dialect';

/**
 * A vault call's failure, as `serveVault` answers it: its message, and the
 * code its causes carry, which `connectVault` puts back on its error, so
 * the app reads it as it would in process. Its database, or a key service,
 * not answering is the app's outage too, not a bug: 503. One only its
 * words say (pg's "Connection terminated") goes as Postgres's code for a
 * connection that failed, 08006.
 */
export function failureOf(error: unknown): { status: number; body: { error: string; code?: string } } {
  const message = error instanceof Error ? error.message : 'the vault failed';
  let code: string | undefined;
  for (let cause = error; typeof cause === 'object' && cause !== null && code === undefined; cause = (cause as { cause?: unknown }).cause) {
    const found = (cause as { code?: unknown }).code;
    if (typeof found === 'string') code = found;
  }
  // A call's value nested deeper than the vault's walk of it holds: the caller's, as its input, never the vault's state.
  // V8's own words stay in it, which the app reads it by (`isStackOverflow`).
  if (isStackOverflow(error)) return { status: 400, body: { error: `the call is nested too deeply to read (${message})` } };
  if (!isUnavailable(error)) return { status: 500, body: code === undefined ? { error: message } : { error: message, code } };
  return { status: 503, body: { error: message, code: code !== undefined && isUnavailable({ code }) ? code : '08006' } };
}
