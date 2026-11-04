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
 * One press of the passkey page's button: the authenticator's answer, sent. An answer the server did not answer
 * (`unavailable`) is kept, `unsent`, and the next press sends it again rather than ask the authenticator for
 * another. A second `create()` for the same person can replace, on the authenticator, a passkey the first POST
 * added though its answer was lost, and the server would refuse the new one (`passkey_exists`): the person would
 * hold no key coffre knows (review r7 of #500). Sent again, the same passkey either completes the step or, the
 * first having committed, ends it with `passkey_exists`, and the key on the device is the one coffre holds. A
 * touch is the same: the same assertion again, never a second touch for one challenge. `ask` throws as the
 * browser's `create()` or `get()` does.
 */
export async function sendPasskey<T>(
  unsent: string | null,
  ask: () => Promise<string>,
  send: (body: string) => Promise<Response>,
): Promise<{ answer: PasskeyAnswer<T>; unsent: string | null }> {
  const body = unsent ?? (await ask());
  const answer = await passkeyAnswer<T>(send(body));
  return { answer, unsent: answer.kind === 'unavailable' ? body : null };
}
