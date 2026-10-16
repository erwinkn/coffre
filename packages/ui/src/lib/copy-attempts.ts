import { copyText } from './clipboard.ts';

/**
 * How a copy ended, as far as anyone still cares.
 *
 * `superseded`: a newer copy began before this one ended, so this one reports
 * nothing and writes nothing. Its result, good or bad, is not what the person
 * asked for last.
 */
export type CopyResult = { outcome: 'copied' } | { outcome: 'failed'; failure: unknown } | { outcome: 'superseded' };

/** What a copy button shows: a copy under way, or how the last one ended, for a moment. */
export type CopyFeedback = 'idle' | 'pending' | 'copied' | 'failed';

/**
 * Copies where the latest one wins, and what they look like while they run.
 *
 * A copy may start while an earlier one is still reading its value or waiting on
 * the clipboard: a retry after a refusal, a second click, a button replaced by a
 * remount. Rather than stop that by keeping a button disabled, every copy takes
 * a number before it awaits anything, and only the newest reports, shows its
 * feedback, or writes. A copier belongs to whoever outlives the button (a row);
 * the button only subscribes to it, so a remount picks up where it was.
 */
export type Copier = {
  run(text: string | Promise<string>): Promise<CopyResult>;
  feedback(): CopyFeedback;
  subscribe(listener: () => void): () => void;
};

const SUPERSEDED = new Error('A newer copy began.');

export function createCopier({
  copy = copyText,
  copiedMs = 1400,
  failedMs = 3000,
}: { copy?: typeof copyText; copiedMs?: number; failedMs?: number } = {}): Copier {
  let latest = 0;
  let feedback: CopyFeedback = 'idle';
  let timer: ReturnType<typeof setTimeout> | null = null;
  const listeners = new Set<() => void>();

  function show(next: CopyFeedback) {
    feedback = next;
    for (const listener of listeners) listener();
  }

  return {
    feedback: () => feedback,
    subscribe(listener) {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
    async run(text) {
      const attempt = ++latest;
      if (timer !== null) clearTimeout(timer);
      timer = null;
      show('pending');
      // A read that finishes after a newer copy began is refused here, so it never
      // reaches the clipboard: the fallback does not write it, and a ClipboardItem
      // whose payload rejects writes nothing.
      const gated =
        typeof text === 'string'
          ? text
          : text.then((value) => {
              if (attempt !== latest) throw SUPERSEDED;
              return value;
            });
      let result: CopyResult = { outcome: 'copied' };
      try {
        // Called before anything is awaited: the click's gesture is still live.
        await copy(gated);
      } catch (failure) {
        result = { outcome: 'failed', failure };
      }
      if (attempt !== latest) return { outcome: 'superseded' };
      show(result.outcome === 'copied' ? 'copied' : 'failed');
      timer = setTimeout(() => show('idle'), result.outcome === 'copied' ? copiedMs : failedMs);
      return result;
    },
  };
}
