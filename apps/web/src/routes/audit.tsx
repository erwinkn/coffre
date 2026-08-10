import { createFileRoute, Link } from '@tanstack/react-router';
import { listAudit, verifyAuditChain } from '../server-functions/audit';
import type { AuditRow } from '../shared/models';
import { CopyButton, EmptyState, Notice, Timestamp, Tip } from '../components/ui';
import { AlertTriangle, CheckCircle, Ledger, ShieldCheck, SlashCircle, X } from '../components/icons';

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

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="sub">
            Who read which secret, when. Append-only by database grant, not by convention:
            the application role holds no UPDATE, DELETE or TRUNCATE on this table.
          </p>
        </div>
        <ChainStatus chain={chain} />
      </div>

      {!chain.ok && (
        <Notice>
          <strong>Chain verification is not available.</strong> {chain.error}
        </Notice>
      )}

      {chain.ok && chain.integrity === 'broken' && (
        <Notice tone="bad">
          <strong>The audit log does not verify.</strong> Chain broken at seq{' '}
          {chain.failedAtSeq}: {chain.reason}. Treat this as an
          incident: entries have been altered or removed by something holding direct database
          access, and nothing below can be relied on until it is explained.
        </Notice>
      )}

      {!result.ok ? (
        <Notice tone="bad">{result.error}</Notice>
      ) : (
        <>
          <div className="cluster" style={{ margin: 'var(--space-6) 0 var(--space-4)' }}>
            <Link
              className={`btn btn-sm${deniedOnly || actorId ? '' : ' btn-primary'}`}
              to="/audit"
              search={{}}
            >
              All events
            </Link>
            <Link
              className={`btn btn-sm${deniedOnly ? ' btn-primary' : ''}`}
              to="/audit"
              search={{ decision: 'deny' }}
            >
              <SlashCircle size={13} />
              Denials only
            </Link>
            {actorId && (
              <Link
                className="btn btn-sm"
                to="/audit"
                search={deniedOnly ? { decision: 'deny' } : {}}
              >
                <X size={13} />
                <span className="mono">{actorId}</span>
              </Link>
            )}
            <span className="meta" style={{ marginLeft: 'auto' }}>
              {result.entries.length} most recent
            </span>
          </div>

          <div className="card">
            {result.entries.length === 0 ? (
              <EmptyState
                icon={<Ledger size={26} />}
                title={deniedOnly ? 'No denials recorded' : 'Nothing recorded yet'}
              >
                {deniedOnly
                  ? 'Every authorisation decision reaches this table, including refusals. An empty result means nobody has been turned away.'
                  : 'The log fills as secrets are read and written. Listing keys does not appear here; revealing a value does.'}
              </EmptyState>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th className="shrink num">Seq</th>
                      <th className="shrink">When (UTC)</th>
                      <th>Actor</th>
                      <th className="shrink">Action</th>
                      <th>Subject</th>
                      <th className="shrink">Decision</th>
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
          </div>
        </>
      )}
    </>
  );
}

function AuditTableRow({ entry, deniedOnly }: { entry: AuditRow; deniedOnly: boolean }) {
  const denied = entry.decision === 'deny';

  return (
    <tr style={denied ? { background: 'var(--deny-wash)' } : undefined}>
      <td className="num meta">{entry.seq}</td>
      <td className="num">
        <Timestamp iso={entry.occurredAt} precise />
      </td>
      <td className="wrap">
        {/* Filtering to one actor is the second question anyone asks after
            "what happened", so the actor cell is the control. */}
        <Link
          className="mono"
          to="/audit"
          search={{
            ...(deniedOnly ? { decision: 'deny' as const } : {}),
            actorId: entry.actorId,
          }}
        >
          {entry.actorId}
        </Link>{' '}
        <span className="pill pill-muted">{entry.actorType}</span>
      </td>
      <td className="mono">{entry.action}</td>
      <td className="wrap mono">{scopedSubject(entry)}</td>
      <td>
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
      <span className="chain-status">
        <AlertTriangle size={14} />
        Verification unavailable
      </span>
    );
  }

  if (chain.integrity === 'broken') {
    return (
      <span className="chain-status chain-status-bad">
        <AlertTriangle size={14} />
        Chain broken
      </span>
    );
  }

  return (
    <span className="chain-status">
      <ShieldCheck size={14} />
      Chain intact
      <span className="meta">
        {chain.rows} {chain.rows === 1 ? 'entry' : 'entries'}, recomputed just now
      </span>
      <Tip label="The chain head: every entry folded into one HMAC. Record it somewhere coffre cannot reach, and a later mismatch proves the log was altered.">
        <code className="mono chain-head">{chain.head.slice(0, 12)}</code>
      </Tip>
      <CopyButton value={chain.head} label="Copy chain head" />
    </span>
  );
}

function scopedSubject(entry: AuditRow): string {
  const scope = [entry.project, entry.environment].filter(
    (part): part is string => part !== null,
  );
  if (entry.subject !== '--') scope.push(entry.subject);
  return scope.length > 0 ? scope.join('/') : '--';
}
