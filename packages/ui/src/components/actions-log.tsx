import { useInfiniteQuery } from '@tanstack/react-query';
import { uiResult, useCoffre } from '../lib/coffre';
import { keys } from '../lib/queries';
import { describe, lines, runLabel } from '../lib/audit-sentences';
import { Sentence } from './audit-sentence';
import { EmptyState, Notice, Spinner, Timestamp } from './ui';
import { Activity, Clock, ShieldCheck, SlashCircle } from './icons';

const PAGE_SIZE = 50;

/**
 * How far a page's reads are listed, when that says something: 0.15's log
 * lists a read once the vault's projector has caught up with it, which runs
 * apart from sealing, so that a projector behind or stopped shows rather
 * than leaves reads missing unsaid. An instance before 0.15 says nothing.
 */
export function ReadsLag({ reads, omitted }: { reads: { through: string | null; behind: boolean; forged?: true } | undefined; omitted?: 'path' | 'scope' | undefined }) {
  // 0.15 lists reads on the whole log and by member, to whoever reads the whole log, and each person's own (D160).
  if (omitted !== undefined) {
    return (
      <div style={{ marginBottom: '1.25rem' }}>
        <Notice>
          {omitted === 'path'
            ? 'Reads are listed on the whole audit log and on each member’s page, not here.'
            : 'Reads are listed to those who read the whole audit log; your own are on your page.'}
        </Notice>
      </div>
    );
  }
  if (reads?.behind !== true && reads?.forged !== true) return null;
  return (
    <div style={{ marginBottom: '1.25rem' }}>
      {reads.forged === true ? (
        <Notice tone="bad">
          The vault does not vouch for how far reads are listed: something with direct access to the database moved
          it. Newer reads may be missing.
        </Notice>
      ) : (
        <Notice tone="warn">
          {reads.through === null ? (
            'No read is listed yet: the reads sealed so far wait to be listed.'
          ) : (
            <>
              Reads sealed through <Timestamp iso={reads.through} precise />; newer reads wait to be listed.
            </>
          )}
        </Notice>
      )}
    </div>
  );
}

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
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) =>
      uiResult(() => client.audit.list({ actor: member, limit: PAGE_SIZE, sealed: '1', before: pageParam })),
    // A page lists fewer entries where they name many secrets, and says where it stopped in each log: its `next`.
    getNextPageParam: (page) => (page.ok ? page.next ?? undefined : undefined),
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
  const first = log.data?.pages[0];

  return (
    <>
      <ReadsLag reads={first?.ok === true ? first.reads : undefined} omitted={first?.ok === true ? first.readsOmitted : undefined} />
      <section className="card" aria-label="Actions log">
        {shown.length === 0 ? (
          <EmptyState title="Nothing yet" />
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
                    <tr key={`${lead.log}:${lead.seq}`} className={sentence.refused ? 'is-denied' : undefined}>
                      <td className="nowrap cell-muted" title={lead.occurredAt}>
                        <Timestamp iso={lead.occurredAt} display="relative" />
                      </td>
                      <td className="cell-sentence">
                        <span className="sentence">
                          <Sentence parts={sentence.parts} />
                        </span>
                        {lead.run !== null && (
                          // The run a service's credential was issued for, as the audit page says it beside the actor.
                          <small className="actor-run">{runLabel(lead.run)}</small>
                        )}
                      </td>
                      <td className="nowrap" data-label="Outcome">
                        {lead.forged === true ? (
                          // An entry of the sealed log the vault does not vouch for: written, or edited, around coffre.
                          <span className="decided decided-refused" title="The vault does not vouch for this entry">
                            <SlashCircle size={13} />
                            Forged
                          </span>
                        ) : sentence.refused ? (
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
