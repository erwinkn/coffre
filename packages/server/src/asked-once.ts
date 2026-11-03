/**
 * A value an isolate asks for once and keeps (T201): the vault's `about()`, the proxy gate's reservation. What it keeps
 * is settled values only, never a pending call (AGENTS.md, "What an isolate keeps"): the answer, once there is one;
 * that a call is under way, and since when, a number; and the last call's failure, and when.
 *
 * The first request to find nothing makes the call. Each other request that finds a call under way waits for its
 * answer on timers of its own, then takes it as its own: the value, or the call's failure, should it fail after the
 * request began waiting. So no request waits on another's I/O: a call whose request was cancelled before it settled
 * (on Workers, a page that navigates away) leaves "under way" behind, which a request waiting trusts `TAKE_OVER_MS`,
 * then makes the call itself. A failure is kept only for the requests that waited on it: the next request asks again.
 *
 *   an isolate's first request                  1 call
 *   the requests that come while it is under way    no call: each polls for its answer, from 1 ms to every 20 ms
 *   a call under way for TAKE_OVER_MS               the next poll makes the call again, and the others wait on that one
 *   every request after                          no call
 *
 * Each concurrent first request making its own call instead, a Node deployment's start at 1,000 requests a second
 * queued 200 to 270 of the gate's calls a thread on its vault's pool (8 connections) for 2 s (T201's bench).
 */
export type AskedOnce<T> = { answer: { value: T } | null; since: number | null; failed: { at: number; error: unknown } | null };

/** How long a request waiting trusts a call under way before it makes the call itself: longer than a deploy's write and its seal take. */
export const TAKE_OVER_MS = 3_000;
const POLL_MS = 1;
const POLL_MAX_MS = 20;

export function askedOnce<T>(): AskedOnce<T> {
  return { answer: null, since: null, failed: null };
}

/** The value `kept` holds, asked with `ask` when nothing holds it: by this request, or by the one whose call is under way (`takeOverMs`: tests shorten it). */
export async function askOnce<T>(kept: AskedOnce<T>, ask: () => Promise<T>, takeOverMs = TAKE_OVER_MS): Promise<T> {
  if (kept.answer !== null) return kept.answer.value;
  const began = Date.now();
  for (let pause = POLL_MS; kept.since !== null && Date.now() - kept.since < takeOverMs; pause = Math.min(2 * pause, POLL_MAX_MS)) {
    await new Promise((resolve) => setTimeout(resolve, pause * (0.5 + Math.random())));
    // Read again after the pause: another request may have settled it meanwhile.
    const { answer, failed } = kept as AskedOnce<T>;
    if (answer !== null) return answer.value;
    if (failed !== null && failed.at >= began) throw failed.error;
  }
  const since = Date.now();
  kept.since = since;
  try {
    const value = await ask();
    kept.answer = { value };
    return value;
  } catch (error) {
    kept.failed = { at: Date.now(), error };
    throw error;
  } finally {
    if (kept.since === since) kept.since = null;
  }
}
