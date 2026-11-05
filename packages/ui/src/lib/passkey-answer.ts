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
 * (`passkey_failed`, `changed`), so the page cannot tell it ended (review r7
 * of #500).
 */
export type PasskeyAnswer<T> = { kind: 'ok'; value: T } | { kind: 'refused'; code: string | undefined } | { kind: 'unavailable' };

export async function passkeyAnswer<T>(request: Promise<Response>): Promise<PasskeyAnswer<T>> {
  let response: Response;
  try {
    response = await request;
  } catch {
    return { kind: 'unavailable' };
  }
  if (response.status >= 500 || response.status === 408 || response.status === 429) return { kind: 'unavailable' };
  const body: unknown = await response.json().catch(() => undefined);
  if (response.ok) return body === undefined ? { kind: 'unavailable' } : { kind: 'ok', value: body as T };
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
 * A step's press, in the page's own memory: the answer the server did not answer, for the next press, whether the
 * step's options were asked of the authenticator already, and when they lapse. Each GET's step starts with neither
 * answer nor ask.
 */
export type Unsent = { body: string | null; asked?: boolean; ends?: Deadline };

/**
 * One press of the passkey page's button: the authenticator's answer, sent. An answer the server did not answer
 * (`unavailable`) is kept, and the next press sends it again rather than ask the authenticator for another (review r7
 * of #500): the page's options name one user handle, and a second `create()` with it could replace on the
 * authenticator a passkey the first POST added though its answer was lost, which the server would refuse
 * (`passkey_exists`), leaving the person a key coffre does not hold. Sent again, the same passkey either completes the
 * step or, the first having committed, ends it with `passkey_exists`, and the key on the device is the one coffre holds.
 * Another tab, or the page reloaded, asks its own GET, whose options draw a user handle of their own (D173), so no
 * page's `create()` replaces another's. A touch is the same: the same assertion again, never a second touch for one
 * challenge. `ask` throws as the browser's `create()` or `get()` does, and its throw forgets the press: no passkey was
 * made.
 *
 * `once`: the options may be asked of the authenticator once only, as a `create()`'s are: after a refusal that keeps
 * the step, the press answers `stale`, asking nothing, and the page asks coffre for new options, a user handle of
 * their own. A refusal says nothing of the answers sent before it: tab A's POST commits and its response is lost, tab
 * B's sign-in replaces the pending cookie, and A's answer, sent again, fails B's challenge (`passkey_failed`); a
 * second `create()` with A's options would name the handle coffre now holds, and could replace that passkey on the
 * authenticator (review r13 of #500).
 *
 * `ends`: a press past it answers `expired`, asking nothing either. A page left open past its five minutes would
 * otherwise hand the authenticator options the server no longer takes, and the person a passkey coffre refuses (the
 * `timeout` the options carry starts when the authenticator is called, not at the GET). Before it, `ask` is given what
 * is left, the `timeout` to call the authenticator with (review r14 of #500).
 */
export async function sendPasskey<T>(
  unsent: Unsent,
  ask: (left: number) => Promise<string>,
  send: (body: string) => Promise<Response>,
  { once = false, clock = browserClock }: { once?: boolean; clock?: Clock } = {},
): Promise<PasskeyAnswer<T> | { kind: 'stale' } | { kind: 'expired' }> {
  if (unsent.body === null && once && unsent.asked === true) return { kind: 'stale' };
  let body = unsent.body;
  if (body === null) {
    const left = unsent.ends === undefined ? undefined : leftOf(unsent.ends, clock);
    if (left === 0) return { kind: 'expired' };
    body = await ask(left ?? Number.POSITIVE_INFINITY);
  }
  unsent.body = body;
  unsent.asked = true;
  const answer = await passkeyAnswer<T>(send(body));
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
 * the first to press here, the Owner setting the deployment up, is told which setting to fix (review r15 of #500).
 */
export function authenticatorError(thrown: unknown, rpId: string): string {
  const name = thrown instanceof DOMException ? thrown.name : undefined;
  if (name === 'InvalidStateError') return 'This device already holds a passkey of yours here. Use another device, or sign in with that one.';
  if (name === 'NotAllowedError') return 'No passkey answered. Try again when you’re ready.';
  if (name === 'SecurityError') {
    return `This browser makes no passkey for ${rpId} on this site. Whoever runs coffre here: passkeys.rpId must be this site’s host or a domain registered above it, not a public suffix such as co.uk or workers.dev.`;
  }
  return 'Your browser could not use a passkey here.';
}
