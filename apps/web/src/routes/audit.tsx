import { createFileRoute, Link } from '@tanstack/react-router';
import { listAudit, verifyAuditChain } from '../server-functions/audit';
import type { AuditRow } from '../shared/models';
import {
  breakAfterUnderscores,
  CopyButton,
  EmptyState,
  Notice,
  Timestamp,
  Tip,
  Toggletip,
} from '../components/ui';
import { ClosedDoor, PageHeader } from '../components/page';
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Layers,
  Ledger,
  ShieldCheck,
  SlashCircle,
  User,
  X,
} from '../components/icons';

type AuditSearch = { decision?: 'deny'; actorId?: string };
type ChainResult = Awaited<ReturnType<typeof verifyAuditChain>>;

export const Route = createFileRoute('/audit')({
  // Filters live in the URL so a finding can cite the exact view it came from.
  validateSearch: (search: Record<string, unknown>): AuditSearch => ({
    decision: search.decision === 'deny' ? 'deny' : undefined,
    actorId:
      typeof search.actorId === 'string' && search.actorId !== '' ? search.actorId : undefined,
  }),
  loaderDeps: ({ search }) => search,
  // The chain is recomputed on every visit rather than on demand. At this
  // volume it is one HMAC per row and costs less than the query that fetched
  // them, and a status that is always current beats a button nobody presses.
  loader: async ({ deps }) => {
    const [entries, chain] = await Promise.all([listAudit({ data: deps }), verifyAuditChain()]);
    return { entries, chain };
  },
  component: AuditPage,
});

function AuditPage() {
  const { entries: result, chain } = Route.useLoaderData();
  const { decision, actorId } = Route.useSearch();
  const deniedOnly = decision === 'deny';

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Ledger size={18} />} label="Audit" title="The audit log is closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  return (
    <>
      <PageHeader title="Audit" actions={<ChainStatus chain={chain} />} />

      {chain.ok && chain.integrity === 'broken' && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="bad">
            <strong>Treat this as an incident.</strong> The chain breaks at entry{' '}
            <span className="mono">{chain.failedAtSeq}</span>: {chain.reason}. Entries have been
            altered or removed by something with direct database access, and nothing below can
            be relied on until that is explained.
          </Notice>
        </div>
      )}

      <div className="toolbar">
        <nav className="segmented" aria-label="Filter by decision">
          {/* `exact` compares the whole search, not a subset of it: otherwise
              "All events" for one actor also counts as active while that
              actor's denials are showing, and both halves light up. */}
          <Link
            to="/audit"
            search={actorId === undefined ? {} : { actorId }}
            activeOptions={{ exact: true }}
          >
            All events
          </Link>
          <Link
            to="/audit"
            search={{ decision: 'deny', ...(actorId === undefined ? {} : { actorId }) }}
            activeOptions={{ exact: true }}
          >
            <SlashCircle size={13} />
            Denials only
          </Link>
        </nav>

        {actorId !== undefined && (
          <Link
            className="filter-chip"
            to="/audit"
            search={deniedOnly ? { decision: 'deny' } : {}}
            aria-label={`Stop filtering by ${actorId}`}
          >
            Actor <span className="mono">{actorId}</span>
            <X size={13} />
          </Link>
        )}
      </div>

      <section className="card" aria-label="Audit entries">
        {result.entries.length === 0 ? (
          <EmptyState title={deniedOnly ? 'No denials recorded' : 'Nothing recorded yet'}>
            {deniedOnly
              ? 'Every authorisation decision reaches this log, refusals included. An empty page means nobody has been turned away.'
              : 'The log fills as secrets are read and written. Listing keys does not appear here; revealing a value does.'}
          </EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt audit stacks">
              <thead>
                <tr>
                  <th className="n" title="Sequence number in the hash chain">
                    #
                  </th>
                  <th className="col-shrink">
                    <span className="th">
                      <Clock size={14} />
                      When (UTC)
                    </span>
                  </th>
                  <th>
                    <span className="th">
                      <User size={14} />
                      Actor
                    </span>
                  </th>
                  <th className="col-shrink">
                    <span className="th">
                      <Activity size={14} />
                      Action
                    </span>
                  </th>
                  <th>
                    <span className="th">
                      <Layers size={14} />
                      Subject
                    </span>
                  </th>
                  <th className="col-shrink">
                    <span className="th">
                      <ShieldCheck size={14} />
                      Decision
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {result.entries.map((entry) => (
                  <AuditTableRow key={entry.seq} entry={entry} deniedOnly={deniedOnly} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function AuditTableRow({ entry, deniedOnly }: { entry: AuditRow; deniedOnly: boolean }) {
  const denied = entry.decision === 'deny';

  return (
    <tr className={denied ? 'is-denied' : undefined}>
      <td className="n" data-label="Sequence">
        {entry.seq}
      </td>
      <td className="nowrap cell-mono" data-label="When (UTC)">
        <Timestamp iso={entry.occurredAt} precise />
      </td>
      <td data-label="Actor">
        {/* Filtering to one actor is the second question anyone asks after
            "what happened", so the actor cell is the control. */}
        <span className="actor">
          <Link
            to="/audit"
            search={{
              ...(deniedOnly ? { decision: 'deny' as const } : {}),
              actorId: entry.actorId,
            }}
          >
            {entry.actorId}
          </Link>
          {entry.actorType === 'service' && <span className="tag">token</span>}
        </span>
      </td>
      <td className="cell-mono nowrap" data-label="Action">
        {entry.action}
      </td>
      <td className="cell-mono nowrap" data-label="Subject">
        {breakAfterUnderscores(scopedSubject(entry))}
      </td>
      <td className="nowrap" data-label="Decision">
        {/* Glyph first, then the word. The colour is the third signal, never
            the only one -- allow/deny is exactly the pair deuteranopia loses. */}
        <span className={`decision ${denied ? 'decision-deny' : 'decision-allow'}`}>
          {denied ? <SlashCircle size={13} /> : <CheckCircle size={13} />}
          {entry.decision}
        </span>
      </td>
    </tr>
  );
}

/**
 * Whether the log verifies, stated rather than offered.
 *
 * This replaced a card with a "Verify chain" button on it. A green result you
 * have to ask for is reassurance rather than evidence: it is checked when
 * someone is already feeling confident, and not on the morning it would have
 * mattered. Recomputing on load makes the claim continuous.
 *
 * The head hash is the part worth carrying away. Recomputation only proves the
 * log is consistent with itself; comparing this value against one recorded
 * earlier, somewhere coffre cannot write, is what proves it is unchanged.
 */
/**
 * Whether the log still recomputes from its first entry, beside the title.
 *
 * Intact is the normal state, so it is a seal that names itself on hover or
 * tap, next to the head a finding would cite. Anything else is spelled out:
 * a problem that hides behind a hover is not being reported.
 */
function ChainStatus({ chain }: { chain: ChainResult }) {
  if (!chain.ok) {
    return (
      <Toggletip label={chain.error}>
        <button type="button" className="chain-flag">
          <AlertTriangle size={14} />
          Chain not verified
        </button>
      </Toggletip>
    );
  }

  if (chain.integrity === 'broken') {
    return (
      <span className="chain-flag chain-flag-bad" role="status">
        <AlertTriangle size={14} />
        Chain broken at <span className="mono">{chain.failedAtSeq}</span>
      </span>
    );
  }

  return (
    <div className="chain">
      <Toggletip label="Chain intact">
        <button type="button" className="chain-seal" aria-label="Chain intact">
          <ShieldCheck size={16} />
        </button>
      </Toggletip>
      <span className="chain-head">
        <span className="chain-head-label">head</span>
        <Tip label={chain.head}>
          <code tabIndex={0}>{chain.head.slice(0, 16)}…</code>
        </Tip>
        <CopyButton value={chain.head} label="Copy the full chain head" />
      </span>
    </div>
  );
}

function scopedSubject(entry: AuditRow): string {
  const scope = [entry.project, entry.environment].filter(
    (part): part is string => part !== null,
  );
  if (entry.subject !== '--') scope.push(entry.subject);
  return scope.length > 0 ? scope.join('/') : '—';
}
