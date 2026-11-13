import { ApiError } from './api/errors.ts';

/**
 * A value an isolate asks for once and keeps: the vault's `about()`, the proxy gate's reservation. What it keeps
 * is settled values only, never a pending call (AGENTS.md, "What an isolate keeps"): the answer, once there is one, and
 * the attempt under way, a record of when it began and, once it has, how it settled.
 *
 * The first request to find nothing makes the call, an attempt of its own. Each other request that finds an attempt
 * under way joins it: it keeps the attempt's record, polls it on timers of its own, and takes its outcome as its own,
 * the value or the failure. So no request waits on another's I/O, and an outcome reaches only the requests that joined
 * its attempt: a retry's followers never take the failure before it, nor a superseded attempt's late one. A call whose
 * request was cancelled before it settled (on Workers, a page that navigates away) leaves its attempt under way,
 * unsettled: a request waiting trusts it `TAKE_OVER_MS`, then makes the call itself, a new attempt, which the others
 * join. A failure is kept only on its attempt: the next request asks again.
 *
 *   an isolate's first request                      1 call
 *   the requests that come while it is under way    no call: each polls its attempt, from 1 ms to every 20 ms
 *   an attempt under way for TAKE_OVER_MS           the next poll makes the call again, and the others join that one
 *   a request that has waited WAIT_MS               503 `starting`, Retry-After 1, however many attempts it joined, the
 *                                                   one it made by taking over included
 *   every request after                             no call
 *
 * Each concurrent first request making its own call instead, a Node deployment's start at 1,000 requests a second
 * queued 200 to 270 of the gate's calls a thread on its vault's pool (8 connections) for 2 s.
 */
export type AskedOnce<T> = { answer: { value: T } | null; under: Attempt<T> | null };

/** One call: when it began and, once it has, how it settled. Its record is its identity: a request that joins it keeps it. */
export type Attempt<T> = { readonly since: number; settled: { value: T } | { error: unknown } | null };

/** How long a request waiting trusts a call under way before it makes the call itself: longer than a deploy's write and its seal take. */
export const TAKE_OVER_MS = 3_000;
/**
 * How long a request waits in all before it answers 503 to ask again: a deadline of its own, which no take-over moves.
 * Otherwise a request could wait for ever, each attempt it joins taken over just before it would, and cancelled in turn.
 */
export const WAIT_MS = 2 * TAKE_OVER_MS;
const POLL_MS = 1;
const POLL_MAX_MS = 20;

export function askedOnce<T>(): AskedOnce<T> {
  return { answer: null, under: null };
}

/** The value `kept` holds, asked with `ask` when nothing holds it: by this request, or by the one whose attempt it joins (tests shorten the waits). */
export async function askOnce<T>(
  kept: AskedOnce<T>,
  ask: () => Promise<T>,
  { takeOverMs = TAKE_OVER_MS, waitMs = WAIT_MS }: { takeOverMs?: number; waitMs?: number } = {},
): Promise<T> {
  if (kept.answer !== null) return kept.answer.value;
  // The isolate's first request: its own call, as long as the call takes (the vault's calls have deadlines of their own).
  if (kept.under === null) return begin(kept, ask).call;
  // A request that joins one waits WAIT_MS in all. A call it takes over is an attempt of its own, which it waits on as
  // it did on the one it joined: by polling, under the same deadline, so its own call hanging (Workers cancelled the
  // request that made the attempt it took over, and then this call) holds it no longer, nor keeps from it an answer
  // another attempt gives meanwhile.
  const deadline = Date.now() + waitMs;
  let mine: { attempt: Attempt<T>; settles: Promise<unknown> } | null = null;
  for (let joined: Attempt<T> | null = kept.under, pause = POLL_MS; ; pause = Math.min(2 * pause, POLL_MAX_MS)) {
    if (joined === null) {
      // Nothing under way, no answer: this request makes the call, and waits on it as on any; past its deadline, none.
      if (Date.now() >= deadline) throw starting();
      const made = begin(kept, ask);
      joined = made.attempt;
      mine = { attempt: made.attempt, settles: made.call.catch(() => {}) };
    }
    // The outcome of the attempt this request joined, once it has one, whatever another attempt answered since.
    const settled = joined.settled;
    if (settled !== null) {
      if ('error' in settled) throw settled.error;
      return settled.value;
    }
    // Its attempt is under way still: another one, taken over, may have answered meanwhile (a value is a value).
    const { answer } = kept as AskedOnce<T>;
    if (answer !== null) return answer.value;
    if (kept.under !== joined) {
      // Taken over, or settled and cleared after a take-over's: join what is under way now, or make the call.
      joined = kept.under;
      continue;
    }
    const now = Date.now();
    if (now >= deadline) throw starting();
    // Another's call not settled in time is taken over; its own, never: this request is alive, so its call is too.
    if (joined !== mine?.attempt && now - joined.since >= takeOverMs) {
      joined = null;
      continue;
    }
    // Its own call, once it made one, wakes it as soon as it settles; another's only on its next poll. Once its own call
    // has settled, in an attempt it no longer waits on (taken over meanwhile, it joined the newer one), its wake has
    // fired for good: raced again, it would answer every poll at once, a loop of microtasks that never yields to a timer
    // or I/O until the deadline. Its rejection stays handled: `settles` caught it.
    if (mine?.attempt.settled) mine = null;
    const polled = new Promise((resolve) => setTimeout(resolve, Math.min(pause * (0.5 + Math.random()), deadline - now)));
    await (mine === null ? polled : Promise.race([polled, mine.settles]));
  }
}

const starting = () => new ApiError('unavailable', 'coffre is still starting: ask again in a moment', 'starting', '1');

/** A call made: its attempt, under way until the call settles, and the call. */
function begin<T>(kept: AskedOnce<T>, ask: () => Promise<T>): { attempt: Attempt<T>; call: Promise<T> } {
  const attempt: Attempt<T> = { since: Date.now(), settled: null };
  kept.under = attempt;
  const call = (async () => {
    try {
      const value = await ask();
      attempt.settled = { value };
      kept.answer = { value };
      return value;
    } catch (error) {
      attempt.settled = { error };
      throw error;
    } finally {
      if (kept.under === attempt) kept.under = null;
    }
  })();
  return { attempt, call };
}
