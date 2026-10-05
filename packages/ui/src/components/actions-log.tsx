import { useInfiniteQuery } from '@tanstack/react-query';
import { uiResult, useCoffre } from '../lib/coffre';
import { keys } from '../lib/queries';
import { describe, lines } from '../lib/audit-sentences';
import { Sentence } from './audit-sentence';
import { EmptyState, Notice, Spinner, Timestamp } from './ui';
import { Activity, Clock, ShieldCheck, SlashCircle } from './icons';

const PAGE_SIZE = 50;

/**
 * Everything one member did, newest first, from the audit log: the same
 * entries `coffre audit --actor` lists, said as the audit page says them.
 * Older pages come on request.
 */
export function ActionsLog({ member }: { member: string }) {
  const client = useCoffre();
  const log = useInfiniteQuery({
    queryKey: [...keys.audit, 'actor', member],
    staleTime: 0,
    initialPageParam: undefined as number | undefined,
    queryFn: ({ pageParam }) =>
      uiResult(() => client.audit.list({ actor: member, limit: PAGE_SIZE, before: pageParam })),
    getNextPageParam: (page) =>
      page.ok && page.entries.length === PAGE_SIZE ? page.entries.at(-1)!.seq : undefined,
  });

  if (log.isPending) {
    return (
      <p className="hint">
        <Spinner size={13} /> Reading the log…
      </p>
    );
  }
  const failed = log.data?.pages.find((page) => !page.ok);
  if (failed !== undefined && !failed.ok) return <Notice tone="bad">{failed.error}</Notice>;
  const entries = (log.data?.pages ?? []).flatMap((page) => (page.ok ? page.entries : []));
  const shown = lines(entries);

  return (
    <>
      <section className="card" aria-label="Actions log">
        {shown.length === 0 ? (
          <EmptyState title="Nothing done yet">Every read, write and change they make is listed here.</EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt actions-log stacks stacks-inline">
              <thead>
                <tr>
                  <th className="col-shrink">
                    <span className="th">
                      <Clock size={14} />
                      When
                    </span>
                  </th>
                  <th>
                    <span className="th">
                      <Activity size={14} />
                      Action
                    </span>
                  </th>
                  <th className="col-shrink">
                    <span className="th">
                      <ShieldCheck size={14} />
                      Outcome
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((batch) => {
                  const lead = batch[0]!;
                  const sentence = describe(batch);
                  return (
                    <tr key={lead.seq} className={sentence.refused ? 'is-denied' : undefined}>
                      <td className="nowrap cell-muted" title={lead.occurredAt}>
                        <Timestamp iso={lead.occurredAt} display="relative" />
                      </td>
                      <td className="cell-sentence">
                        <span className="sentence">
                          <Sentence parts={sentence.parts} />
                        </span>
                      </td>
                      <td className="nowrap" data-label="Outcome">
                        {sentence.refused ? (
                          <span className="decided decided-refused">
                            <SlashCircle size={13} />
                            Refused
                          </span>
                        ) : (
                          <span className="cell-muted">Allowed</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {log.hasNextPage && (
        <div className="table-actions">
          <button
            type="button"
            className="btn"
            disabled={log.isFetchingNextPage}
            onClick={() => void log.fetchNextPage()}
          >
            {log.isFetchingNextPage && <Spinner />}
            Show older
          </button>
        </div>
      )}
    </>
  );
}
