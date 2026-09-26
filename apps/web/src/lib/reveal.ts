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
  /** When the read happened, in ms since the epoch; drives the auto-hide. */
  at: number;
};

export function revealIsCurrent(
  reveal: Reveal | null,
  currentVersion: number | null,
): reveal is Reveal {
  return reveal !== null && reveal.version === currentVersion;
}
