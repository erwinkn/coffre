import { createFileRoute, Link } from '@tanstack/react-router';
import { listAudit, verifyAuditChain } from '../server-functions/audit';
import type { AuditRow } from '../shared/models';
import { CopyButton, EmptyState, Notice, Timestamp, Tip } from '../components/ui';
import { ClosedDoor, PageHeader } from '../components/page';
import { AlertTriangle, CheckCircle, ShieldCheck, SlashCircle, X } from '../components/icons';

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
      <ClosedDoor eyebrow="Oversight" title="Audit log">
        {result.error}
      </ClosedDoor>
    );
  }

  const denials = result.entries.filter((entry) => entry.decision === 'deny').length;

  return (
    <>
      <PageHeader
        eyebrow="Oversight"
        title="Audit log"
        lede="Who read which secret, and when. Append-only by database grant, not by convention: the application's role holds no UPDATE, DELETE or TRUNCATE on this table."
        actions={<ChainStatus chain={chain} />}
      />

      {!chain.ok && (
        <div style={{ marginTop: '1.25rem' }}>
          <Notice>
            <strong>The chain could not be verified.</strong> {chain.error}
          </Notice>
        </div>
      )}

      {chain.ok && chain.integrity === 'broken' && (
        <div style={{ marginTop: '1.25rem' }}>
          <Notice tone="bad">
            <strong>The audit log does not verify.</strong> The chain breaks at entry{' '}
            <span className="mono">{chain.failedAtSeq}</span>: {chain.reason}. Treat this as an
            incident. Entries have been altered or removed by something with direct database
            access, and nothing below can be relied on until that is explained.
          </Notice>
        </div>
      )}

      <div className="filters">
        <nav className="segmented" aria-label="Filter by decision">
          <Link
            to="/audit"
            search={actorId === undefined ? {} : { actorId }}
            aria-current={deniedOnly ? undefined : 'page'}
          >
            All events
          </Link>
          <Link
            to="/audit"
            search={{ decision: 'deny', ...(actorId === undefined ? {} : { actorId }) }}
            aria-current={deniedOnly ? 'page' : undefined}
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

        <span className="filters-count">
          {result.entries.length} most recent
          {!deniedOnly && denials > 0 && `, ${denials} refused`}
        </span>
      </div>

      {result.entries.length === 0 ? (
        <EmptyState title={deniedOnly ? 'No denials recorded' : 'Nothing recorded yet'}>
          {deniedOnly
            ? 'Every authorisation decision reaches this log, refusals included. An empty page means nobody has been turned away.'
            : 'The log fills as secrets are read and written. Listing keys does not appear here; revealing a value does.'}
        </EmptyState>
      ) : (
        <div className="ledger-wrap">
          <table className="ledger audit stacks">
            <thead>
              <tr>
                <th className="caps col-seq">No.</th>
                <th className="caps col-shrink">When (UTC)</th>
                <th className="caps">Actor</th>
                <th className="caps col-shrink">Action</th>
                <th className="caps">Subject</th>
                <th className="caps col-shrink">Decision</th>
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
    </>
  );
}

function AuditTableRow({ entry, deniedOnly }: { entry: AuditRow; deniedOnly: boolean }) {
  const denied = entry.decision === 'deny';

  return (
    <tr className={denied ? 'is-denied' : undefined}>
      <td className="col-seq" data-label="No.">
        {entry.seq}
      </td>
      <td className="nowrap" data-label="When (UTC)">
        <Timestamp iso={entry.occurredAt} precise />
      </td>
      <td data-label="Actor">
        {/* Filtering to one actor is the second question anyone asks after
            "what happened", so the actor cell is the control. */}
        <span className="actor">
          <Link
            className="mono"
            to="/audit"
            search={{
              ...(deniedOnly ? { decision: 'deny' as const } : {}),
              actorId: entry.actorId,
            }}
          >
            {entry.actorId}
          </Link>
          {entry.actorType === 'service' && <span className="tag tag-outline">service</span>}
        </span>
      </td>
      <td className="cell-mono nowrap" data-label="Action">
        {entry.action}
      </td>
      <td className="cell-mono" style={{ overflowWrap: 'anywhere' }} data-label="Subject">
        {scopedSubject(entry)}
      </td>
      <td className="nowrap" data-label="Decision">
        {/* Glyph first, then the word. The colour is the third signal, never
            the only one -- allow/deny is exactly the pair deuteranopia loses. */}
        <span className={`decision ${denied ? 'decision-deny' : 'decision-allow'}`}>
          {denied ? <SlashCircle size={14} /> : <CheckCircle size={14} />}
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
 * mattered. Recomputing on load makes the claim continuous, which also means
 * the status must stay small enough to sit beside the title.
 *
 * The head hash is the part worth carrying away. Recomputation only proves the
 * log is consistent with itself; comparing this value against one recorded
 * earlier, somewhere coffre cannot write, is what proves it is unchanged.
 */
function ChainStatus({ chain }: { chain: ChainResult }) {
  if (!chain.ok) {
    return (
      <div className="chain chain-unknown">
        <span className="chain-seal">
          <AlertTriangle size={16} />
        </span>
        <span className="chain-text">
          <span className="chain-title">Verification unavailable</span>
          <span className="chain-sub">The chain was not recomputed</span>
        </span>
      </div>
    );
  }

  if (chain.integrity === 'broken') {
    return (
      <div className="chain chain-bad" role="status">
        <span className="chain-seal">
          <AlertTriangle size={16} />
        </span>
        <span className="chain-text">
          <span className="chain-title">Chain broken</span>
          <span className="chain-sub">
            at entry <span className="mono">{chain.failedAtSeq}</span>
          </span>
        </span>
      </div>
    );
  }

  return (
    <div className="chain">
      <span className="chain-seal">
        <ShieldCheck size={17} />
      </span>
      <span className="chain-text">
        <span className="chain-title">Chain intact</span>
        <span className="chain-sub">
          {chain.rows} {chain.rows === 1 ? 'entry' : 'entries'}, recomputed on load · head
          <Tip label="The chain head: every entry folded into one HMAC. Record it somewhere coffre cannot reach, and a later mismatch proves the log was altered.">
            <code className="chain-head" tabIndex={0}>
              {chain.head.slice(0, 12)}
            </code>
          </Tip>
        </span>
      </span>
      <CopyButton value={chain.head} label="Copy the full chain head" />
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
