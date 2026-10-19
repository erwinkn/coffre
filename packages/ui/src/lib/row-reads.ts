import type { Reveal } from './reveal';

/**
 * What a secret's row knows about reading its value.
 *
 * Two things read it, and they must not share state. Reveal (and Edit, which
 * opens on the current value) put the value on screen: `reveal` holds it,
 * `revealing` says a read is out, `error` is its refusal. Copy hands the value
 * to the clipboard and keeps nothing: `copyError` is all of it that the row
 * holds, because Copy's in-flight state belongs to its button. So a Copy never
 * changes whether a value is shown or whether Hide can be pressed, and a Reveal
 * never touches Copy's error, whichever of the two finishes first.
 */
export type RowReads = {
  reveal: Reveal | null;
  revealing: boolean;
  error: string | null;
  copyError: string | null;
};

export const noReads: RowReads = { reveal: null, revealing: false, error: null, copyError: null };

export type RowReadsAction =
  | { type: 'set-reveal'; reveal: Reveal | null }
  /** Reveal or Edit asked for the value. */
  | { type: 'read-started' }
  /** It arrived; `reveal` is null when it was only wanted to edit from. */
  | { type: 'read-succeeded'; reveal: Reveal | null }
  | { type: 'read-failed'; message: string }
  | { type: 'copy-started' }
  | { type: 'copy-succeeded' }
  | { type: 'copy-failed'; message: string };

export function rowReads(state: RowReads, action: RowReadsAction): RowReads {
  switch (action.type) {
    case 'set-reveal':
      return { ...state, reveal: action.reveal };
    case 'read-started':
      return { ...state, revealing: true };
    case 'read-succeeded':
      return {
        ...state,
        revealing: false,
        error: null,
        reveal: action.reveal ?? state.reveal,
      };
    case 'read-failed':
      return { ...state, revealing: false, error: action.message };
    case 'copy-started':
    case 'copy-succeeded':
      return { ...state, copyError: null };
    case 'copy-failed':
      return { ...state, copyError: action.message };
  }
}

/**
 * Whether the eye button is out of reach: while a read is on its way and there
 * is nothing on screen yet. Once a value is shown, Hide is always available,
 * whatever else is being read.
 */
export function revealToggleDisabled(state: RowReads, shown: Reveal | null): boolean {
  return shown === null && state.revealing;
}

/**
 * The value an edit starts from: a plain one as listed, one the caller reads
 * as `read` opens it, or none, the editor opening empty to replace it: a
 * sensitive value, a parent's they do not read, or a read refused or failed,
 * whose reason the row says. It always opens: writing a value takes no read
 * of the one it replaces.
 */
export async function valueToEdit(row: { value: string | null; readable: boolean }, read: () => Promise<string | null>): Promise<string | null> {
  if (row.value !== null) return row.value;
  return row.readable ? read() : null;
}
