import { copyText } from './clipboard.ts';

/**
 * How a copy ended, as far as anyone still cares.
 *
 * `superseded`: a newer copy began before this one ended, so this one reports
 * nothing. Its result, good or bad, is not what the person asked for last.
 */
export type CopyResult = { outcome: 'copied' } | { outcome: 'failed'; failure: unknown } | { outcome: 'superseded' };

/**
 * Copies where the latest one wins.
 *
 * A copy may start while an earlier one is still reading its value or waiting on
 * the clipboard: a retry after a refusal, a second click, another button taking
 * over after a remount. Rather than stop that by keeping a button disabled, every
 * copy takes a number before it awaits anything, and only the newest may report.
 * Whoever holds the object (a row, not a button, which a remount replaces)
 * decides what the newest one's result means.
 */
export function copyAttempts(copy: typeof copyText = copyText): (text: string | Promise<string>) => Promise<CopyResult> {
  let latest = 0;
  return async (text) => {
    const attempt = ++latest;
    let result: CopyResult = { outcome: 'copied' };
    try {
      // Called before anything is awaited: the click's gesture is still live.
      await copy(text);
    } catch (failure) {
      result = { outcome: 'failed', failure };
    }
    return attempt === latest ? result : { outcome: 'superseded' };
  };
}
