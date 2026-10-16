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
  options: { clipboard?: ClipboardLike; item?: ClipboardItemConstructor } = {},
): Promise<void> {
  // Nobody is left to hear of a read that fails after the copy has: it is the copy's to report.
  if (typeof text !== 'string') text.catch(() => {});
  try {
    await write(text, options);
  } catch (failure) {
    if (typeof text === 'string') throw failure;
    // A copy is not over while its read is out. Were it over at the clipboard's refusal,
    // its button would take a retry with that read still pending, and the read's late
    // failure would report over the retry's result. And an unreadable value is the
    // better thing to report: a browser that rejects the payload may name only its own
    // error instead of the read's (WebKit's is always NotAllowedError).
    const read = await text.then(
      () => null,
      (reason: unknown) => ({ reason }),
    );
    throw read === null ? failure : read.reason;
  }
}

async function write(
  text: string | Promise<string>,
  {
    clipboard = globalThis.navigator?.clipboard as ClipboardLike | undefined,
    item = (globalThis as { ClipboardItem?: ClipboardItemConstructor }).ClipboardItem,
  }: { clipboard?: ClipboardLike; item?: ClipboardItemConstructor },
): Promise<void> {
  if (clipboard === undefined) throw new Error('The clipboard is not available here.');
  if (typeof text !== 'string' && item !== undefined && clipboard.write !== undefined) {
    // Called before anything is awaited: this is what keeps the user gesture.
    // The text goes in as a string, not a Blob: decoding a Blob drops a leading U+FEFF.
    await clipboard.write([new item({ 'text/plain': text })]);
    return;
  }
  await clipboard.writeText(await text);
}
