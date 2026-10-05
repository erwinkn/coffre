import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { shownMember, type Deletion } from '@coffre/client';

import { useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { Trash } from './icons';
import { ErrorLine, Modal, Notice, Spinner } from './ui';

/**
 * Deleting an archived project or environment for good, `market` or
 * `market/prod`. The dialog first asks the server what the deletion would
 * take, then needs the place's path typed out before it deletes: nothing
 * brings it back, so the one click a slip can make is never enough.
 */
export function DeletePlaceDialog({
  path,
  open,
  onOpenChange,
  onDeleted,
}: {
  path: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDeleted: (deletion: Deletion) => unknown;
}) {
  const coffre = useCoffre();
  const plan = useQuery({ ...queries.deletion(coffre, path), enabled: open });
  const [typed, setTyped] = useState('');
  const { pending, error, setError, run } = useAction();
  const what = path.includes('/') ? 'environment' : 'project';

  useEffect(() => {
    if (!open) return;
    setTyped('');
    setError(null);
  }, [open, setError]);

  const deletion = plan.data?.ok === true ? plan.data.deletion : null;

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={
        <>
          Delete <span className="mono">{path}</span> for good?
        </>
      }
    >
      <div className="dialog-body">
        {plan.data === undefined ? (
          <Spinner />
        ) : plan.data.ok ? (
          <DeletionSummary deletion={plan.data.deletion} what={what} />
        ) : (
          <ErrorLine error={plan.data.error} />
        )}
      </div>
      <div className="dialog-body">
        <Notice tone="bad">
          Nothing brings it back. Backups of the database taken before now still hold its
          encrypted values; only they, with the vault key, could restore them.
        </Notice>
      </div>
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          if (typed !== path || deletion === null) return;
          run(
            () => (what === 'project' ? coffre.projects.delete(path) : coffre.environments.delete(path)),
            {
              affects: affects.places(),
              onSuccess: (result) => {
                onOpenChange(false);
                return onDeleted(result.deletion);
              },
            },
          );
        }}
      >
        <label className="field">
          <span className="label">
            Type <span className="mono">{path}</span> to confirm
          </span>
          <input
            className="input input-mono"
            autoFocus
            spellCheck={false}
            autoComplete="off"
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
          />
        </label>
        <ErrorLine error={error} />
        <div className="dialog-actions">
          <button className="btn" type="button" onClick={() => onOpenChange(false)}>
            Cancel
          </button>
          <button
            className="btn btn-danger"
            type="submit"
            disabled={typed !== path || deletion === null || pending}
          >
            {pending ? <Spinner /> : <Trash size={14} />}
            Delete {what}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** What the deletion takes and what it keeps, in the server's numbers. */
function DeletionSummary({ deletion, what }: { deletion: Deletion; what: 'project' | 'environment' }) {
  const count = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`;
  const environments = what === 'project' && deletion.environments.length > 0 ? (
    <>
      {' '}
      in <span className="mono">{deletion.environments.join(', ')}</span>
    </>
  ) : null;
  return (
    <ul className="deletion-summary">
      <li>
        <strong>Erased:</strong> the values of {count(deletion.versions, 'secret version')}
        {environments}, ciphertext and wrapped key both.
      </li>
      <li>
        <strong>Revoked:</strong> {count(deletion.grants.length, 'grant')}
        {deletion.grants.length > 0 && (
          <>
            {', '}
            {deletion.grants.map((grant, index) => (
              <span key={`${grant.member} ${grant.place}`}>
                {index > 0 && ', '}
                <span className="mono">{shownMember(grant.member)}</span> on{' '}
                <span className="mono">{grant.place}</span>
              </span>
            ))}
          </>
        )}
        .
      </li>
      {deletion.references.length > 0 && (
        <li>
          <strong>Ended:</strong> {count(deletion.references.length, 'reference')}, which read it from
          elsewhere or which it reads:{' '}
          {deletion.references.map((reference, index) => (
            <span key={`${reference.holder} ${reference.source}`}>
              {index > 0 && ', '}
              <span className="mono">{reference.holder}</span> from{' '}
              <span className="mono">{reference.source}</span>
            </span>
          ))}
          .
        </li>
      )}
      <li>
        <strong>Kept, names only:</strong> the {what} and its {count(deletion.keys, 'key')}, as{' '}
        <span className="mono">{deletion.tombstone}</span>, so the audit log still reads. Its
        name is free to use again.
      </li>
      {deletion.stranded.length > 0 && (
        <li>
          <strong>Left with no access:</strong>{' '}
          {deletion.stranded.map((member, index) => (
            <span key={member}>
              {index > 0 && ', '}
              <span className="mono">{shownMember(member)}</span>
            </span>
          ))}
          . Offboard them on the Users or Service accounts page if they are no longer needed.
        </li>
      )}
    </ul>
  );
}
