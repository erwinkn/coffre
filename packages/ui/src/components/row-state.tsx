import { useSyncExternalStore, type ReactNode } from 'react';

import { announcements, serverAnnouncements, subscribeAnnouncements } from '../lib/announce';
import type { ItemStatus } from '../lib/optimistic';
import { Spinner } from './ui';
import { AlertCircle, X } from './icons';

/**
 * How a row looks while a change to it is on its way, or after the server
 * refused it. Never colour alone: a waiting row is quieter and says what it
 * waits for, a row being removed is struck through as well, and a refused
 * change says so in words beneath its row.
 */
export function rowClass(status: ItemStatus): string {
  if (status.state === 'pending') return status.kind === 'removing' ? 'is-removing' : 'is-saving';
  if (status.state === 'failed') return 'is-failed';
  return '';
}

/** In place of a row's actions while its change is on its way. */
export function RowPending({ status }: { status: ItemStatus }) {
  if (status.state !== 'pending') return null;
  return (
    <span className="row-pending">
      <Spinner size={13} />
      {status.words.pending}
    </span>
  );
}

/** Beneath a row whose change the server refused: why, until dismissed. */
export function RowFailure({
  status,
  columns,
  onDismiss,
  children,
}: {
  status: ItemStatus;
  columns: number;
  onDismiss: () => void;
  /** Said before the reason; by default, what did not happen. */
  children?: ReactNode;
}) {
  if (status.state !== 'failed') return null;
  return (
    <tr className="row-error row-failure">
      <td colSpan={columns}>
        <ItemFailure status={status} onDismiss={onDismiss}>
          {children}
        </ItemFailure>
      </td>
    </tr>
  );
}

/** Why the server refused a change, where it shows: under a row, or in a card. */
export function ItemFailure({
  status,
  onDismiss,
  children,
}: {
  status: ItemStatus;
  onDismiss: () => void;
  children?: ReactNode;
}) {
  if (status.state !== 'failed') return null;
  return (
    <div className="row-failure-line">
      <p className="error-line">
        <AlertCircle size={14} />
        <span>
          <strong>{children ?? status.words.failed}</strong> {status.error}
        </span>
      </p>
      <button type="button" className="act act-quiet" onClick={onDismiss} aria-label="Dismiss">
        <X size={13} />
      </button>
    </div>
  );
}

/** Where changes are announced to screen readers (`lib/announce.ts`). */
export function LiveRegion() {
  const { polite, urgent } = useSyncExternalStore(subscribeAnnouncements, announcements, serverAnnouncements);
  return (
    <>
      <div className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
        {polite !== null && <span key={polite.id}>{polite.text}</span>}
      </div>
      <div className="visually-hidden" role="alert" aria-live="assertive" aria-atomic="true">
        {urgent !== null && <span key={urgent.id}>{urgent.text}</span>}
      </div>
    </>
  );
}
