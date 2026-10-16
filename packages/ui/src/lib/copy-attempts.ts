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
 * The clipboard is one resource per page, so "latest" is decided per page: every
 * copy, from any row, takes a number from one counter before it awaits anything,
 * and only the newest reports, shows feedback, or writes. A copy may start while
 * an earlier one is still reading or waiting on the clipboard: a retry after a
 * refusal, a click on another row, a row filtered out and back, a button replaced
 * by a remount. When a copy from another copier takes over, the older one drops
 * its pending or "Copied" feedback and goes back to idle. A copier belongs to
 * whoever outlives the button (a row); the button only subscribes to it, so a
 * remount picks up where it was.
 */
export type Copier = {
  run(text: string | Promise<string>): Promise<CopyResult>;
  feedback(): CopyFeedback;
  subscribe(listener: () => void): () => void;
};

const SUPERSEDED = new Error('A newer copy began.');

/** The page's newest copy, and the copier that made it. */
let latest = 0;
let owner: { drop(): void } | null = null;

export function createCopier({
  copy = copyText,
  copiedMs = 1400,
  failedMs = 3000,
}: { copy?: typeof copyText; copiedMs?: number; failedMs?: number } = {}): Copier {
  let feedback: CopyFeedback = 'idle';
  let timer: ReturnType<typeof setTimeout> | null = null;
  const listeners = new Set<() => void>();

  function show(next: CopyFeedback) {
    if (feedback === next) return;
    feedback = next;
    for (const listener of listeners) listener();
  }

  function stopTimer() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  }

  const self = {
    /** Another copier's copy took over: nothing of this one's is left showing. */
    drop() {
      stopTimer();
      show('idle');
    },
  };

  return {
    feedback: () => feedback,
    subscribe(listener) {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
    async run(text) {
      const attempt = ++latest;
      if (owner !== null && owner !== self) owner.drop();
      owner = self;
      stopTimer();
      show('pending');
      // A read that finishes after a newer copy began, anywhere on the page, is
      // refused here, so it never reaches the clipboard: the fallback does not
      // write it, and a ClipboardItem whose payload rejects writes nothing.
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
