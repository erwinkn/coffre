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
   * Where the value was held, when that can change under one version
   * number: a fork's key reset to its parent's reads another secret's v1.
   */
  from?: string;
  /** When the read happened, in ms since the epoch; drives the auto-hide. */
  at: number;
};

export function revealIsCurrent(
  reveal: Reveal | null,
  currentVersion: number | null,
  currentFrom?: string,
): reveal is Reveal {
  return reveal !== null && reveal.version === currentVersion && reveal.from === currentFrom;
}

/** What a read opened: the value, and the number of the version it opened. */
export type Read = { value: string; version: number | null };

/**
 * A value read for the row `row` was when asked, stamped with the version it
 * opened. A read that opened another number than the row's has outrun the
 * listing, or the listing it: `refetch` brings the listing up to date first,
 * so that once the value shows, the row says its number too. If the listing
 * has moved past it by then, the value hides, as it is no longer the value.
 *
 * `from` stays the row's as it was asked: nothing says where the opened
 * value was held, so a read across a reset, an override or a repointed
 * reference hides, and takes a second click, rather than show another
 * secret's value under this number.
 */
export async function stampedRead(
  row: { version: number | null; from: string },
  read: () => Promise<Read>,
  refetch: () => Promise<unknown>,
): Promise<Reveal> {
  const { value, version } = await read();
  if (version !== row.version) await refetch();
  return { value, version, from: row.from, at: Date.now() };
}
