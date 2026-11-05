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
 * A step's press, in the page's own memory: the answer the server did not answer, for the next press, and whether
 * the step's options were asked of the authenticator already. Each GET's step starts with neither.
 */
export type Unsent = { body: string | null; asked?: boolean };

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
 */
export async function sendPasskey<T>(
  unsent: Unsent,
  ask: () => Promise<string>,
  send: (body: string) => Promise<Response>,
  once = false,
): Promise<PasskeyAnswer<T> | { kind: 'stale' }> {
  if (unsent.body === null && once && unsent.asked === true) return { kind: 'stale' };
  const body = unsent.body ?? (await ask());
  unsent.body = body;
  unsent.asked = true;
  const answer = await passkeyAnswer<T>(send(body));
  // Kept only while the server may still take it; `passkey_failed` added nothing of this answer's, so a touch may
  // ask for another (a new passkey asks for new options first, `once`).
  if (answer.kind !== 'unavailable') unsent.body = null;
  return answer;
}
