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

/**
 * The value could not be read, and the reader has already said why.
 *
 * Thrown by a source so `copyText` stops without a second message; the button
 * shows its failure and whoever read the value shows the reason.
 */
export class ValueUnavailable extends Error {
  constructor() {
    super('The value could not be read.');
    this.name = 'ValueUnavailable';
  }
}

export async function copyText(
  text: string | Promise<string>,
  {
    clipboard = globalThis.navigator?.clipboard as ClipboardLike | undefined,
    item = (globalThis as { ClipboardItem?: ClipboardItemConstructor }).ClipboardItem,
  }: { clipboard?: ClipboardLike; item?: ClipboardItemConstructor } = {},
): Promise<void> {
  if (clipboard === undefined) throw new Error('The clipboard is not available here.');
  if (typeof text !== 'string' && item !== undefined && clipboard.write !== undefined) {
    // A browser that rejects the payload may report its own error instead of the
    // source's (WebKit's is always NotAllowedError), so the source's is kept.
    const read: { failure?: { reason: unknown } } = {};
    const tracked = text.catch((reason: unknown) => {
      read.failure = { reason };
      throw reason;
    });
    try {
      // Called before anything is awaited: this is what keeps the user gesture.
      // The text goes in as a string, not a Blob: decoding a Blob drops a leading U+FEFF.
      await clipboard.write([new item({ 'text/plain': tracked })]);
    } catch (failure) {
      throw read.failure === undefined ? failure : read.failure.reason;
    }
    return;
  }
  await clipboard.writeText(await text);
}
