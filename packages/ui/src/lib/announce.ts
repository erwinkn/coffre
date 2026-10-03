/**
 * What a screen reader hears of a change: that it is on its way, that it
 * landed, or why it did not. Changes show on screen as dimmed or struck-out
 * rows; this says the same in words, through two live regions in the shell
 * (`LiveRegion`), one polite and one for failures, which interrupts.
 */
export type Announcement = { text: string; id: number };

type Heard = { polite: Announcement | null; urgent: Announcement | null };

let heard: Heard = { polite: null, urgent: null };
let next = 0;
const listeners = new Set<() => void>();

export function announce(text: string, { urgent = false }: { urgent?: boolean } = {}): void {
  // A fresh id, so the same words said twice are heard twice.
  const said = { text, id: next++ };
  heard = urgent ? { ...heard, urgent: said } : { ...heard, polite: said };
  for (const listener of listeners) listener();
}

export function subscribeAnnouncements(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function announcements(): Heard {
  return heard;
}

const nobody: Heard = { polite: null, urgent: null };

/** On the server nothing has been said yet. */
export function serverAnnouncements(): Heard {
  return nobody;
}
