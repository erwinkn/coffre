/**
 * Whether a key press comes from inside an open dialog, which a page-wide
 * shortcut leaves alone: Cmd/Ctrl+Enter saves the secrets page, and from a
 * dialog it would save behind it and close it, its work unfinished.
 */
export function inDialog(target: EventTarget | null): boolean {
  const element = target as { closest?: (selector: string) => unknown } | null;
  return typeof element?.closest === 'function' && element.closest('[role="dialog"], [role="alertdialog"]') !== null;
}
