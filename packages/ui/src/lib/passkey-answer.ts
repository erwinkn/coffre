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
 * What a passkey step holds between presses: `asking`, a `create()` or `get()` open for it; `unsent`, the
 * authenticator's answer, which coffre did not answer; `done`, an answer coffre did answer, the step ended.
 */
export type Kept = { kind: 'asking' } | { kind: 'unsent'; body: string } | { kind: 'done' };

/** Where a step's `Kept` lives: read, and written, null to forget it. */
export type Keeper = { read(): Kept | null; write(kept: Kept | null): void };

/** A touch's keeper: the page's own memory. A second `get()` replaces nothing, so other tabs need not know. */
export function memoryKeeper(): Keeper {
  let kept: Kept | null = null;
  return { read: () => kept, write: (next) => void (kept = next) };
}

/** The `Storage` methods a keeper uses: `localStorage`'s, or a test's. */
export type KeptStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'key' | 'length'>;

const PREFIX = 'coffre.passkey.';

/**
 * An enrollment's keeper, shared by every tab and every reload of one sign-in (review r8 of #500): `localStorage`,
 * under the step's challenge, which the sign-in's cookie carries, so two tabs of it, or the page again after a reload,
 * find the same entry. A second `create()` for the step, from another tab or a reloaded page, could replace on the
 * authenticator the passkey the first one added, as the page's own memory (review r7) could not stop. Each entry
 * lasts the step's `timeout`, from when it is written: the ceremony's lifetime, which the step's challenge cannot
 * outlive (`CEREMONY_TTL_SECONDS`, which the server gives `create()` as its timeout), and the longest a `create()`
 * stays open, so an `asking` left by a tab closed mid-`create()` lapses when that `create()` would have. Expired
 * entries, any step's, are removed when one is made. Where the browser keeps no storage (or refuses it), the page's
 * memory stands in: one tab's protection, review r7's.
 */
export function storedKeeper(storage: KeptStorage | null, challenge: string, timeoutMs: number, now: () => number = Date.now): Keeper {
  const key = `${PREFIX}${challenge}`;
  const memory = memoryKeeper();
  const live = (value: string | null): Kept | null => {
    if (value === null) return null;
    try {
      const { until, ...kept } = JSON.parse(value) as Kept & { until: number };
      return typeof until === 'number' && until > now() ? kept : null;
    } catch {
      return null;
    }
  };
  try {
    for (let i = (storage?.length ?? 0) - 1; i >= 0; i--) {
      const other = storage!.key(i);
      if (other?.startsWith(PREFIX) && live(storage!.getItem(other)) === null) storage!.removeItem(other);
    }
  } catch {
    // Storage refused: the memory alone keeps this step.
  }
  return {
    read() {
      try {
        if (storage !== null) return live(storage.getItem(key));
      } catch {
        // Fall through to the memory.
      }
      return memory.read();
    },
    write(kept) {
      memory.write(kept);
      try {
        if (kept === null) storage?.removeItem(key);
        else storage?.setItem(key, JSON.stringify({ ...kept, until: now() + timeoutMs }));
      } catch {
        // The memory holds it.
      }
    },
  };
}

/**
 * One press of the passkey page's button: the authenticator's answer, sent. An answer the server did not answer
 * (`unavailable`) is kept, `unsent`, and the next press, this tab's or another's of the same step, sends it again
 * rather than ask the authenticator for another. A second `create()` for the same person can replace, on the
 * authenticator, a passkey the first POST added though its answer was lost, and the server would refuse the new one
 * (`passkey_exists`): the person would hold no key coffre knows (review r7 of #500). Sent again, the same passkey either
 * completes the step or, the first having committed, ends it with `passkey_exists`, and the key on the device is the
 * one coffre holds. For the same reason a press finds the step `elsewhere` while another tab's `create()` is open, and
 * ended (`state_mismatch`, "started in another tab") once another tab's answer was answered (review r8). A touch is
 * the same, in this page alone: the same assertion again, never a second touch for one challenge. `ask` throws as the
 * browser's `create()` or `get()` does, and its throw forgets the press: no passkey was made.
 */
export async function sendPasskey<T>(
  keeper: Keeper,
  ask: () => Promise<string>,
  send: (body: string) => Promise<Response>,
): Promise<PasskeyAnswer<T> | { kind: 'elsewhere' }> {
  const kept = keeper.read();
  if (kept?.kind === 'done') return { kind: 'refused', code: 'state_mismatch' };
  if (kept?.kind === 'asking') return { kind: 'elsewhere' };
  let body = kept?.kind === 'unsent' ? kept.body : null;
  if (body === null) {
    keeper.write({ kind: 'asking' });
    try {
      body = await ask();
    } catch (error) {
      keeper.write(null);
      throw error;
    }
    keeper.write({ kind: 'unsent', body });
  }
  const answer = await passkeyAnswer<T>(send(body));
  // `passkey_failed`: the server added nothing and the step goes on, so another passkey may be asked for.
  keeper.write(answer.kind === 'unavailable' ? { kind: 'unsent', body } : answer.kind === 'refused' && answer.code === 'passkey_failed' ? null : { kind: 'done' });
  return answer;
}
