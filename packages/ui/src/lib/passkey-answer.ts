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
 * authenticator's answer, which coffre did not answer; `done`, an answer coffre did answer, or the step's lifetime
 * over: the step ended.
 */
export type Kept = { kind: 'asking' } | { kind: 'unsent'; body: string } | { kind: 'done' };

/** Where a step's `Kept` lives: read, and written, null to forget it. */
export type Keeper = { read(): Kept | null; write(kept: Kept | null): void };

/**
 * A moment on both of the browser's clocks: `wall`, `Date.now()`, which every tab shares and which may jump when the
 * clock is corrected; `elapsed`, `performance.now()`, which never jumps but is the tab's own and may stand still while
 * the machine sleeps.
 */
export type Instant = { wall: number; elapsed: number };

export const browserClock = (): Instant => ({ wall: Date.now(), elapsed: performance.now() });

/**
 * When a step ends on the server, from its options' `timeout`, what was left of it when the server answered the GET.
 * The page asks the authenticator for nothing once either clock says the step may have ended: `ends` (the GET's send
 * plus `timeout`, on the wall clock) or `elapsedEnds` (the same on the tab's elapsed clock). A `create()` of an ended
 * step could replace, on the authenticator, the passkey another tab of it added (review r9 of #500), and neither clock
 * alone can be trusted: the wall clock moves back when corrected, the elapsed one stops in a sleep (review r10).
 * `endedBy`, the GET's arrival plus `timeout` on the wall clock, comes after this tab's `ends`: the step's shared entry
 * is kept until the latest `endedBy` of the tabs that read it (`storedKeeper`).
 */
export type Lifetime = { ends: number; endedBy: number; elapsedEnds: number };

/** The lifetime of a step whose GET left at `sent` and came back at `received` with this `timeout`. */
export function lifetime(sent: Instant, received: Instant, timeout: number): Lifetime {
  return { ends: sent.wall + timeout, endedBy: received.wall + timeout, elapsedEnds: sent.elapsed + timeout };
}

const over = (life: Lifetime, at: Instant) => at.wall >= life.ends || at.elapsed >= life.elapsedEnds;

/** A keeper that reads `done` once the step's lifetime is over, whatever it holds. */
function ending(keeper: Keeper, life: Lifetime, clock: () => Instant): Keeper {
  return { read: () => (over(life, clock()) ? { kind: 'done' } : keeper.read()), write: keeper.write };
}

function memory(): Keeper {
  let kept: Kept | null = null;
  return { read: () => kept, write: (next) => void (kept = next) };
}

/** A touch's keeper: the page's own memory. A second `get()` replaces nothing, so other tabs need not know. */
export function memoryKeeper(life: Lifetime, clock: () => Instant = browserClock): Keeper {
  return ending(memory(), life, clock);
}

/** The `Storage` methods a keeper uses: `localStorage`'s, or a test's. */
export type KeptStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'key' | 'length'>;

const PREFIX = 'coffre.passkey.';

/** A stored entry: what its step holds, if anything, and until when, on the wall clock, any tab may still ask. */
type Entry = { kept: Kept | null; until: number };

function parse(value: string | null): Entry | null {
  if (value === null) return null;
  try {
    const entry = JSON.parse(value) as Partial<Entry>;
    return typeof entry.until === 'number' ? { kept: entry.kept ?? null, until: entry.until } : null;
  } catch {
    return null;
  }
}

/**
 * An enrollment's keeper, shared by every tab and every reload of one sign-in (review r8 of #500): `localStorage`,
 * under the step's challenge, which the sign-in's cookie carries, so two tabs of it, or the page again after a reload,
 * find the same entry. A second `create()` for the step, from another tab or a reloaded page, could replace on the
 * authenticator the passkey the first one added, as the page's own memory (review r7) could not stop.
 *
 * Its own entry a tab reads whatever its `until`: only the tab's `Lifetime` ends its step. The entry's `until` only
 * says when a tab of another step may remove it, and each tab that reads the step pushes it to its own `endedBy` as it
 * makes its keeper, so the entry outlives, on the wall clock that every tab shares, every tab's `ends`. Timed by the
 * writer alone, an entry could lapse before a tab whose GET came after a clock correction: tab A at 0 with 300 s left,
 * the clock moved 60 s ahead, tab B at 10 with 290 s left; A's entry, until 300 on A's reading, lapsed at 240 s, B's
 * step ran to 300 s, and B made a second passkey (review r10). An `asking` left by a tab closed mid-`create()` lapses
 * with the step. Where the browser keeps no storage, or refuses a read or a write, the page's memory holds the step
 * from then on, one tab's protection, review r7's: a write that failed left nothing for a read to find, and its memory
 * has it (review r9). A tab that cannot push the entry's `until` reads it still, as it could before.
 */
export function storedKeeper(storage: KeptStorage | null, challenge: string, life: Lifetime, clock: () => Instant = browserClock): Keeper {
  const key = `${PREFIX}${challenge}`;
  const mine = memory();
  let shared = storage;
  const store = (kept: Kept | null) => {
    const until = Math.max(life.endedBy, parse(shared!.getItem(key))?.until ?? -Infinity);
    shared!.setItem(key, JSON.stringify({ kept, until } satisfies Entry));
  };
  try {
    const now = clock().wall;
    for (let i = (shared?.length ?? 0) - 1; i >= 0; i--) {
      const other = shared!.key(i);
      if (other?.startsWith(PREFIX) && other !== key && !((parse(shared!.getItem(other))?.until ?? -Infinity) > now)) shared!.removeItem(other);
    }
    if (shared !== null) store(parse(shared.getItem(key))?.kept ?? null);
  } catch {
    // Not pushed: what the storage holds is still read.
  }
  const stored: Keeper = {
    read() {
      try {
        if (shared !== null) return parse(shared.getItem(key))?.kept ?? null;
      } catch {
        shared = null;
      }
      return mine.read();
    },
    write(kept) {
      mine.write(kept);
      try {
        if (shared !== null) store(kept);
      } catch {
        // Kept in memory from now on. What the storage held stays: another tab finds this step `asking` at worst,
        // and asks for nothing.
        shared = null;
      }
    },
  };
  return ending(stored, life, clock);
}

/**
 * One press of the passkey page's button: the authenticator's answer, sent. An answer the server did not answer
 * (`unavailable`) is kept, `unsent`, and the next press, this tab's or another's of the same step, sends it again
 * rather than ask the authenticator for another. A second `create()` for the same person can replace, on the
 * authenticator, a passkey the first POST added though its answer was lost, and the server would refuse the new one
 * (`passkey_exists`): the person would hold no key coffre knows (review r7 of #500). Sent again, the same passkey either
 * completes the step or, the first having committed, ends it with `passkey_exists`, and the key on the device is the
 * one coffre holds. For the same reason a press finds the step `elsewhere` while another tab's `create()` is open, and
 * ended (`state_mismatch`, "expired, or finished in another tab") once another tab's answer was answered (review r8),
or the step's lifetime is over (review r9). A touch is
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
