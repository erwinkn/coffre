/**
 * What an answer of `/api/auth/passkey` means for the passkey page: the
 * step, `refused` (the server ended it, with a code `signinErrorMessage`
 * says in words), or `unavailable` (no answer to go by: the network, a 5xx,
 * a 408 or 429, a body that does not parse; or one that says to ask again:
 * a 409 `changed`, another change having come between each of its tries,
 * `retrying` in `api/changes.ts`). The server keeps the pending sign-in on
 * all of those, so the page offers to try again rather than send the person
 * back to their provider. A 401 or 409 whose body did not arrive whole is
 * unread too: those are the statuses whose refusals may keep the step
 * (`passkey_failed`, `changed`), so the page cannot tell it ended.
 */
export type PasskeyAnswer<T> = { kind: 'ok'; value: T } | { kind: 'refused'; code: string | undefined } | { kind: 'unavailable' };

export async function passkeyAnswer<T>(request: Promise<Response>): Promise<PasskeyAnswer<T>> {
  const answer = await answerOf<T>(request);
  return answer.kind === 'landed' ? { kind: 'unavailable' } : answer;
}

/**
 * `passkeyAnswer`, with a success whose body did not arrive whole told apart: `landed`. A GET's (the step's options)
 * is no step to go by, so `passkeyAnswer` says `unavailable`; a POST's was taken (`sendPasskey`), its headers, the new
 * session's cookie among them, having arrived with its status.
 */
async function answerOf<T>(request: Promise<Response>): Promise<PasskeyAnswer<T> | { kind: 'landed' }> {
  let response: Response;
  try {
    response = await request;
  } catch {
    return { kind: 'unavailable' };
  }
  if (response.status >= 500 || response.status === 408 || response.status === 429) return { kind: 'unavailable' };
  const body: unknown = await response.json().catch(() => undefined);
  if (response.ok) return body === undefined ? { kind: 'landed' } : { kind: 'ok', value: body as T };
  if (body === undefined && (response.status === 401 || response.status === 409)) return { kind: 'unavailable' };
  const { error, reason } = typeof body === 'object' && body !== null ? body as { error?: unknown; reason?: unknown } : {};
  if (response.status === 409 && error === 'conflict' && reason === 'changed') return { kind: 'unavailable' };
  return { kind: 'refused', code: typeof error === 'string' ? error : undefined };
}

/**
 * Two clocks, read together: the wall's (`Date.now`), and the time elapsed since the page opened
 * (`performance.now`), which no clock correction moves. A step's deadline is past once either says so: a wall
 * clock set forward ends it early, which only asks coffre for new options, and one set back cannot keep it.
 */
export type Clock = { wall(): number; elapsed(): number };
export const browserClock: Clock = { wall: () => Date.now(), elapsed: () => performance.now() };

/** When a step's options lapse, by each clock. */
export type Deadline = { wall: number; elapsed: number };

/**
 * The deadline of a step whose GET was sent at `sent`, by `clock`, and whose options' `timeout` says what was left of
 * its five minutes when the server answered (`remainingMs`). Dated from the send, not the answer: the server's five
 * minutes began after it, so the page's deadline never falls after the server's.
 */
export function deadlineOf(sent: { wall: number; elapsed: number }, timeout: number): Deadline {
  return { wall: sent.wall + timeout, elapsed: sent.elapsed + timeout };
}

export function readClock(clock: Clock): { wall: number; elapsed: number } {
  return { wall: clock.wall(), elapsed: clock.elapsed() };
}

/** What is left of `ends` now, by the clock that says less; 0 once past. */
export function leftOf(ends: Deadline, clock: Clock): number {
  return Math.max(0, Math.min(ends.wall - clock.wall(), ends.elapsed - clock.elapsed()));
}

/**
 * A call to the authenticator ended at `left` milliseconds, by this page: `call` is given the signal to pass to
 * `create()` or `get()`, aborted then, and a call it ended throws `TimeoutError` (`lapsed`). The options' `timeout` is
 * a hint the browser may stretch: Chromium raises one under three minutes to three, so a step with seconds left would
 * wait minutes, and a passkey made after the step lapsed is one coffre refuses, left on the device. An answer that
 * came first is kept: coffre, not the page, says whether it came in time.
 */
export async function withinDeadline<T>(left: number, call: (signal: AbortSignal) => Promise<T>, closed?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(lapsed()), Math.max(0, left));
  // `closed`: the page put the call away (its dialog closed) before it was answered; that ends it too, as itself.
  const close = () => controller.abort(closed?.reason);
  if (closed?.aborted) close();
  closed?.addEventListener('abort', close, { once: true });
  try {
    return await call(controller.signal);
  } catch (thrown) {
    if (closed?.aborted) throw closed.reason;
    throw controller.signal.aborted ? lapsed() : thrown;
  } finally {
    clearTimeout(timer);
    closed?.removeEventListener('abort', close);
  }
}

/** The throw of an authenticator call the page ended at its step's deadline (`withinDeadline`). */
export function lapsed(): DOMException {
  return new DOMException('the request lapsed before a passkey answered', 'TimeoutError');
}

function isLapse(thrown: unknown): boolean {
  return thrown instanceof DOMException && thrown.name === 'TimeoutError';
}

/**
 * A step's press, in the page's own memory: the answer the server did not answer, for the next press, whether the
 * step's options were asked of the authenticator already, and when they lapse. Each GET's step starts with neither
 * answer nor ask.
 */
export type Unsent = { body: string | null; asked?: boolean; ends?: Deadline };

/**
 * One press of the passkey page's button: the authenticator's answer, sent. An answer the server did not answer
 * (`unavailable`) is kept, and the next press sends it again rather than ask the authenticator for another: the
 * page's options name one user handle, and a second `create()` with it could replace on the authenticator a passkey
 * the first POST added though its answer was lost, which the server would refuse
 * (`passkey_exists`), leaving the person a key coffre does not hold. Sent again, the same passkey either completes the
 * step or, the first having committed, ends it with `passkey_exists`, and the key on the device is the one coffre holds.
 * Another tab, or the page reloaded, asks its own GET, whose options draw a user handle of their own, so no
 * page's `create()` replaces another's. A touch is the same: the same assertion again, never a second touch for one
 * challenge. `ask` throws as the browser's `create()` or `get()` does, and its throw forgets the press: no passkey was
 * made.
 *
 * `landed`: a 2xx whose body did not arrive whole. The server did what was asked: the sign-in, the step-up or the
 * removal is done, and the response's cookie is this browser's new session. Sent again, the same answer would meet a
 * step that ended, a refusal of something done, so the page goes on as on `ok`, without the
 * answer's `next`.
 *
 * `once`: the options may be asked of the authenticator once only, as a `create()`'s are: after a refusal that keeps
 * the step, the press answers `stale`, asking nothing, and the page asks coffre for new options, a user handle of
 * their own. A refusal says nothing of the answers sent before it: tab A's POST commits and its response is lost, tab
 * B's sign-in replaces the pending cookie, and A's answer, sent again, fails B's challenge (`passkey_failed`); a
 * second `create()` with A's options would name the handle coffre now holds, and could replace that passkey on the
 * authenticator.
 *
 * `ends`: a press past it answers `expired`, asking nothing either. A page left open past its five minutes would
 * otherwise hand the authenticator options the server no longer takes, and the person a passkey coffre refuses (the
 * `timeout` the options carry starts when the authenticator is called, not at the GET). Before it, `ask` is given what
 * is left, the `timeout` to call the authenticator with, and an `ask` the page ended there
 * (`withinDeadline`) answers `expired` too.
 */
export async function sendPasskey<T>(
  unsent: Unsent,
  ask: (left: number) => Promise<string>,
  send: (body: string) => Promise<Response>,
  { once = false, clock = browserClock }: { once?: boolean; clock?: Clock } = {},
): Promise<PasskeyAnswer<T> | { kind: 'landed' } | { kind: 'stale' } | { kind: 'expired' }> {
  if (unsent.body === null && once && unsent.asked === true) return { kind: 'stale' };
  let body = unsent.body;
  if (body === null) {
    const left = unsent.ends === undefined ? undefined : leftOf(unsent.ends, clock);
    if (left === 0) return { kind: 'expired' };
    try {
      body = await ask(left ?? Number.POSITIVE_INFINITY);
    } catch (thrown) {
      if (isLapse(thrown)) return { kind: 'expired' };
      throw thrown;
    }
  }
  unsent.body = body;
  unsent.asked = true;
  const answer = await answerOf<T>(send(body));
  // Kept only while the server may still take it; `passkey_failed` added nothing of this answer's, so a touch may
  // ask for another (a new passkey asks for new options first, `once`).
  if (answer.kind !== 'unavailable') unsent.body = null;
  return answer;
}

/**
 * What the page says when the browser's `create()` or `get()` throws, for the RP ID the options named. `SecurityError`
 * is the browser refusing the RP ID for this origin: one that is not the host or a registrable parent of it, which
 * only the browser's public suffix list decides (`co.uk`, `workers.dev`). coffre's startup check holds `rpId` to the
 * host or a parent on a label boundary, and leaves that list to the browser (docs/design/passkeys.md, section 7.1), so
 * the first to press here, the Owner setting the deployment up, is told which setting to fix.
 */
export function authenticatorError(thrown: unknown, rpId: string): string {
  const name = thrown instanceof DOMException ? thrown.name : undefined;
  if (name === 'InvalidStateError') return 'This device already holds a passkey of yours here. Use another device, or sign in with that one.';
  if (name === 'TimeoutError') return 'This request lapsed before a passkey answered. Press again for a new one.';
  if (name === 'NotAllowedError') return 'No passkey answered. Try again when you’re ready.';
  if (name === 'SecurityError') {
    return `This browser makes no passkey for ${rpId} on this site. Whoever runs coffre here: passkeys.rpId must be this site’s host or a domain registered above it, not a public suffix such as co.uk or workers.dev.`;
  }
  return 'Your browser could not use a passkey here.';
}
