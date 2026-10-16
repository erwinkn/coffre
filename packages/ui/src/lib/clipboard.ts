/**
 * Writing to the clipboard, from text that may still be on its way.
 *
 * A browser lets a page write to the clipboard only inside a click's user
 * gesture, and Safari drops the gesture across an `await`. So a value that has
 * to be fetched first (Copy on a hidden secret) is handed over as a promise:
 * `clipboard.write` is called at once, with the promise inside a
 * `ClipboardItem`, and the browser waits for it. Where that is not supported,
 * the text is awaited, then written with `writeText`, which is what every
 * browser but Safari allows.
 *
 * The text goes through byte for byte: no trimming, no newline changes.
 */

/** What of the clipboard `copyText` uses; the browser's `navigator.clipboard` fits. */
export type ClipboardLike = {
  writeText(text: string): Promise<void>;
  write?(items: unknown[]): Promise<void>;
};

type ClipboardItemConstructor = new (items: Record<string, Promise<string>>) => unknown;

export async function copyText(
  text: string | Promise<string>,
  {
    clipboard = globalThis.navigator?.clipboard as ClipboardLike | undefined,
    item = (globalThis as { ClipboardItem?: ClipboardItemConstructor }).ClipboardItem,
  }: { clipboard?: ClipboardLike; item?: ClipboardItemConstructor } = {},
): Promise<void> {
  // A read that fails after the copy has ended is nobody's to hear: not an unhandled rejection.
  if (typeof text !== 'string') text.catch(() => {});
  if (clipboard === undefined) throw new Error('The clipboard is not available here.');
  if (typeof text !== 'string' && item !== undefined && clipboard.write !== undefined) {
    // Called before anything is awaited: this is what keeps the user gesture.
    // The text goes in as a string, not a Blob: decoding a Blob drops a leading U+FEFF.
    await clipboard.write([new item({ 'text/plain': text })]);
    return;
  }
  await clipboard.writeText(await text);
}
