import type { MissingKey } from '@coffre/client';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';

import { dismissMissing, missingList, restoreMissing } from '../lib/changes';
import { failureMessage, useCoffre } from '../lib/coffre';
import { changeOptions } from '../lib/optimistic';
import { queries } from '../lib/queries';
import { useChangeStatus } from '../lib/use-change';
import { Card } from './page';
import { RowFailure, rowClass } from './row-state';

/**
 * Keys the environment's siblings have and it lacks, by name, whether you
 * read them or not (docs/design/environments.md): each with Add, which opens
 * a new row with its name, and Dismiss, which the whole team then sees, and
 * below them Dismiss all. Nothing shows when nothing is missing, dismissed
 * keys included: they are restored from the CLI (`coffre missing
 * --dismissed`), or by Undo right after dismissing.
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
  const queryClient = useQueryClient();
  // Each call's own promise, which `mutate`'s callbacks are not: they follow only the latest call.
  const dismissKeys = useMutation(changeOptions(queryClient, dismissMissing(coffre, place))).mutateAsync;
  const restoreKeys = useMutation(changeOptions(queryClient, restoreMissing(coffre, place))).mutateAsync;
  const list = missingList(place);
  const { status, dismiss: forget } = useChangeStatus(list.queryKey);
  // What is missing, and only that: the dismissed are not listed.
  const missing = data === undefined ? [] : list.items(data);
  if (missing.length === 0) return null;
  const columns = canWrite ? 3 : 2;

  // Gone from the list at once, and said so at once, each dismissal with its
  // own Undo. A refused one takes its word back and puts its rows back,
  // saying why beneath them.
  const dismiss = (entries: MissingKey[]) => {
    const said = toast.success(entries.length === 1 ? `${entries[0]!.key} dismissed` : `${entries.length} keys dismissed`, {
      action: {
        label: 'Undo',
        onClick: () => void restoreKeys(entries).catch((error: unknown) => toast.error(`Not restored. ${failureMessage(error)}`)),
      },
    });
    dismissKeys(entries).catch(() => toast.dismiss(said));
  };

  return (
    <>
      <Card
        wide
        labelledBy="missing-keys"
        title={`${missing.length} ${missing.length === 1 ? 'key' : 'keys'} from other environments ${missing.length === 1 ? "isn't" : "aren't"} here`}
        description="Compared with every other environment of the project, by key name."
      >
        <div className="dt-wrap">
          <table className="dt stacks missing-keys">
            <tbody>
              {missing.map((entry) => {
                const state = status(entry.key);
                return [
                  <tr key={entry.key} className={rowClass(state)}>
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
                          <button type="button" className="btn btn-sm btn-quiet" onClick={() => dismiss([entry])}>
                            Dismiss
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>,
                  <RowFailure
                    key={`failure:${entry.key}`}
                    status={state}
                    columns={columns}
                    onDismiss={() => state.state === 'failed' && forget(state.mutationId)}
                  />,
                ];
              })}
            </tbody>
          </table>
        </div>
      </Card>
      {canWrite && missing.length > 1 && (
        <div className="table-actions">
          <button type="button" className="btn" onClick={() => dismiss(missing)}>
            Dismiss all
          </button>
        </div>
      )}
    </>
  );
}
