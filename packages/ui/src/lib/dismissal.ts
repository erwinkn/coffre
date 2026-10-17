import type { MissingKey } from '@coffre/client';
import { toast } from 'sonner';

import { failureMessage } from './coffre.ts';

/**
 * Dismiss missing keys, and say so at once in a toast with Undo. A refused
 * dismissal turns that toast into why it was refused, so the reason shows
 * whatever the list does next: when reading it again fails too, the panel
 * has no rows left to say it beneath.
 */
export function dismissWithUndo(
  entries: MissingKey[],
  { dismiss, restore }: { dismiss: (entries: MissingKey[]) => Promise<unknown>; restore: (entries: MissingKey[]) => Promise<unknown> },
): string | number {
  const said = toast.success(entries.length === 1 ? `${entries[0]!.key} dismissed` : `${entries.length} keys dismissed`, {
    action: {
      label: 'Undo',
      onClick: () => void restore(entries).catch((error: unknown) => toast.error(`Not restored. ${failureMessage(error)}`)),
    },
  });
  dismiss(entries).catch((error: unknown) => toast.error(`Not dismissed. ${failureMessage(error)}`, { id: said, action: undefined }));
  return said;
}
