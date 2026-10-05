import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { useCoffre } from '../lib/coffre';
import { affects, queries } from '../lib/queries';
import { useAction } from '../lib/use-action';
import { Card } from './page';
import { ErrorLine, Timestamp } from './ui';

/**
 * Keys the environment's siblings have and it lacks, of those you read
 * (docs/design/environments.md): each with Add, which opens a new row with
 * its name, and Dismiss, which the whole team then sees, and below them
 * Dismiss all and what was dismissed, each with Restore. Nothing shows when
 * nothing is missing or dismissed.
 */
export function MissingKeys({
  project,
  environment,
  canWrite,
  onAdd,
}: {
  project: string;
  environment: string;
  canWrite: boolean;
  /** Open a new row with this name, empty: its value is yours to give. */
  onAdd: (key: string) => void;
}) {
  const coffre = useCoffre();
  const place = { project, environment };
  const { data } = useQuery(queries.missing(coffre, place));
  const { run, pending, error } = useAction();
  const [showDismissed, setShowDismissed] = useState(false);
  if (data?.ok !== true || (data.missing.length === 0 && data.dismissed.length === 0)) return null;
  const { missing, dismissed } = data;
  const path = `${project}/${environment}`;
  const dismiss = (patch: Record<string, true | null>) => void run(() => coffre.environments.dismiss(path, patch), { affects: affects.secrets(place) });

  return (
    <>
      <Card
        wide
        labelledBy="missing-keys"
        title={missing.length === 0 ? 'Nothing missing' : `${missing.length} ${missing.length === 1 ? 'key' : 'keys'} from other environments ${missing.length === 1 ? "isn't" : "aren't"} here`}
        description="Compared with the environments you can read."
      >
        <div className="dt-wrap">
          <table className="dt stacks missing-keys">
            <tbody>
              {missing.map((entry) => (
                <tr key={entry.key}>
                  <td className="mono" data-label="Key">{entry.key}</td>
                  <td className="cell-muted" data-label="In">
                    In {entry.in.join(', ')}
                    {entry.folder !== null && <>, in {entry.folder}/</>}
                  </td>
                  {canWrite && (
                    <td className="col-actions">
                      <div className="acts">
                        <button type="button" className="btn btn-sm" onClick={() => onAdd(entry.key)}>
                          Add
                        </button>
                        <button type="button" className="btn btn-sm btn-quiet" disabled={pending} onClick={() => dismiss({ [entry.key]: true })}>
                          Dismiss
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
              {showDismissed && dismissed.length > 0 && (
                <tr className="folder-row">
                  <th colSpan={canWrite ? 3 : 2} scope="rowgroup">Dismissed</th>
                </tr>
              )}
              {showDismissed && dismissed.map((entry) => (
                <tr key={`dismissed:${entry.key}`}>
                  <td className="mono" data-label="Key">{entry.key}</td>
                  <td className="cell-muted" data-label="Dismissed">
                    By {entry.dismissedBy} <Timestamp iso={entry.dismissedAt} display="relative" />; in {entry.in.join(', ')}
                  </td>
                  {canWrite && (
                    <td className="col-actions">
                      <button type="button" className="btn btn-sm" disabled={pending} onClick={() => dismiss({ [entry.key]: null })}>
                        Restore
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {error !== null && <ErrorLine error={error} />}
      </Card>
      <div className="table-actions">
        {canWrite && missing.length > 1 && (
          <button type="button" className="btn" disabled={pending} onClick={() => dismiss(Object.fromEntries(missing.map((entry) => [entry.key, true])))}>
            Dismiss all
          </button>
        )}
        {dismissed.length > 0 && (
          <button type="button" className="btn btn-quiet" aria-expanded={showDismissed} onClick={() => setShowDismissed((open) => !open)}>
            {showDismissed ? 'Hide dismissed' : `Dismissed (${dismissed.length})`}
          </button>
        )}
      </div>
    </>
  );
}
