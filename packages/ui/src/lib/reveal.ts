/**
 * A decrypted value on screen, and which version it was decrypted from.
 *
 * `version` is what makes it safe to keep around at all: the list of keys
 * reports each secret's current version, and a reveal is only shown while the
 * two agree. After a save, a rollback, or someone else's write, the plaintext
 * on screen would be an old value presented as the current one.
 */
export type Reveal = {
  value: string;
  version: number | null;
  /**
   * The id of the secret the value was held in. One number can name two
   * values: a fork's key reset to its parent's reads another secret's v1,
   * and an override written after reads its own next number, which the
   * parent's may have too.
   */
  from: string | null;
  /** When the read happened, in ms since the epoch; drives the auto-hide. */
  at: number;
};

export function revealIsCurrent(
  reveal: Reveal | null,
  currentVersion: number | null,
  currentFrom: string | null,
): reveal is Reveal {
  return reveal !== null && reveal.from !== null && reveal.version === currentVersion && reveal.from === currentFrom;
}

/** What a read opened: the value, and the version it opened, by number and by the secret it is held in. */
export type Read = { value: string; version: number | null; from: string | null };

/**
 * A value read for the row `row` was when asked, stamped with the version it
 * opened. A read that opened another number than the row's has outrun the
 * listing, or the listing it: `refetch` brings the listing up to date first,
 * so that once the value shows, the row says its number too. If the listing
 * has moved past it by then, the value hides, as it is no longer the value.
 *
 * It is stamped with the secret the read says it opened, never the row's:
 * a read across a reset, an override or a repointed reference opened
 * another secret, maybe at the very number the row shows by then, and
 * hides rather than show that secret's value as this one's.
 */
export async function stampedRead(
  row: { version: number | null; from: string | null },
  read: () => Promise<Read>,
  refetch: () => Promise<unknown>,
): Promise<Reveal> {
  const { value, version, from } = await read();
  if (version !== row.version || from !== row.from) await refetch();
  return { value, version, from, at: Date.now() };
}
