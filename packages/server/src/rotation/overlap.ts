/**
 * PROTOTYPE (W109): what consumers see while a value they verify with is
 * replaced, and how coffre tells they have moved.
 *
 * A key with an overlap, say `WEBHOOK_SECRET`, signed by one service and
 * verified by another, rotates in three phases, each a pointer to one of
 * the secret's versions:
 *
 *   staged    WEBHOOK_SECRET = v4, WEBHOOK_SECRET_NEXT = v5      verifiers learn v5
 *   promoted  WEBHOOK_SECRET = v5, WEBHOOK_SECRET_PREVIOUS = v4  signers move to v5
 *   retired   WEBHOOK_SECRET = v5                                v4 is forgotten
 *
 * A signer signs with `KEY`; a verifier accepts `KEY`, `KEY_NEXT` and
 * `KEY_PREVIOUS`, whichever are set. Each phase starts only once everyone
 * who reads the key has read the last one (`laggards`), so a signer and a
 * verifier are never more than one phase apart, and any two phases a step
 * apart share a value. Two phases would do only where the signer and the
 * verifier deploy together, or the signer is a provider that signs with both
 * for a while itself (Stripe's webhooks, when their secret is rolled).
 */
export type Phase = 'staged' | 'promoted' | 'retired';

export type Slots = { current: number; next?: number; previous?: number };

/** Which version each name holds, in a phase of the rotation from `from` to `to`. */
export function slots(phase: Phase | null, from: number, to: number): Slots {
  switch (phase) {
    case null:
      return { current: from };
    case 'staged':
      return { current: from, next: to };
    case 'promoted':
      return { current: to, previous: from };
    case 'retired':
      return { current: to };
  }
}

/** The names `export`, `run` and the Action give them: `KEY`, and `KEY_NEXT` or `KEY_PREVIOUS` while set. */
export function exportedNames(key: string, slots: Slots): Record<string, number> {
  return {
    [key]: slots.current,
    ...(slots.next === undefined ? {} : { [`${key}_NEXT`]: slots.next }),
    ...(slots.previous === undefined ? {} : { [`${key}_PREVIOUS`]: slots.previous }),
  };
}

/** A `secret.read` of the log, as the offboarding report reads them. */
export type Read = { actor: string; version: number; at: number };

/**
 * Who has not moved yet: read the replaced version within `lookbackMs`
 * before the new one was stored, and no newer version since. Someone who
 * reads it monthly holds a rotation up to a month; someone who stopped
 * reading it holds nothing.
 */
export function laggards(
  reads: readonly Read[],
  { replaced, stored, storedAt, lookbackMs }: { replaced: number; stored: number; storedAt: number; lookbackMs: number },
): string[] {
  const readers = new Set<string>();
  const moved = new Set<string>();
  for (const read of reads) {
    if (read.version <= replaced && read.at < storedAt && read.at >= storedAt - lookbackMs) readers.add(read.actor);
    if (read.version >= stored && read.at >= storedAt) moved.add(read.actor);
  }
  return [...readers].filter((actor) => !moved.has(actor)).sort();
}
