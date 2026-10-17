import { type AuditEntryView } from '@coffre/client';
import { useState, type ReactNode } from 'react';
import { useQuery, useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useCoffre } from '../lib/coffre';
import { queries, type AuditSearch, type ChainResult } from '../lib/queries';
import {
  decidedBy,
  describe,
  lines,
  runLabel,
  who,
  type Part,
} from '../lib/audit-sentences';
import { absolute, EmptyState, Notice, Spinner, Timestamp, Toggletip } from '../components/ui';
import { memberName, Sentence } from '../components/audit-sentence';
import { ClosedDoor, PageHeader } from '../components/page';
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  Clock,
  Info,
  Ledger,
  ShieldCheck,
  SlashCircle,
  User,
  X,
} from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { audit } from '../options';

const Route = pageRoute<typeof audit>();

export function AuditPage() {
  const search = Route.useSearch();
  const client = useCoffre();
  const { data: result } = useSuspenseQuery(queries.auditEntries(client, search));
  // Not suspended: the table shows while the log is verified.
  const verification = useQuery(queries.auditChain(client));
  const chain = verification.data;
  const { decision, actorId } = search;
  const detail = search.detail === '1';
  const deniedOnly = decision === 'deny';

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Ledger size={18} />} label="Audit" title="The audit log is closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  const broken = chain?.integrity === 'broken' ? chain : null;
  const breakAt = broken?.failedAtSeq ?? null;
  const shown = lines(result.entries);
  const filters = { decision, actorId };

  return (
    <>
      <PageHeader
        title="Audit"
        actions={
          // One region for every state, so each change of it is announced.
          <div className="chain-live" aria-live="polite" aria-atomic="true">
            <ChainStatus chain={chain} onRetry={() => void verification.refetch()} />
          </div>
        }
      />

      {broken !== null && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="bad">
            <strong>Treat this as an incident.</strong>{' '}
            {broken.failedAtSeq === null
              ? `The log does not verify, found by the ${broken.author}'s check: ${broken.reason}.`
              : `The log breaks at entry ${broken.failedAtSeq}, found by the ${broken.author}'s check: ${broken.reason}.`}{' '}
            {broken.through !== null && `Every entry through ${broken.through} holds. `}
            Something with direct access to the database has changed what it records
            {broken.failedAtSeq === null ? '' : `, and nothing from entry ${broken.failedAtSeq} on can be relied on`} until
            that is explained.
            {breakAt !== null && !result.entries.some((entry) => entry.seq === breakAt) && (
              <>
                {' '}Entry {breakAt} is not among the entries below
                {detail ? (
                  <>
                    ; <code>coffre audit</code> lists them all.
                  </>
                ) : (
                  ': it may be detail, which Everything lists.'
                )}
              </>
            )}
          </Notice>
        </div>
      )}

      <div className="toolbar">
        {/* One control for what the log lists. `exact` holds each link to the
            whole search, so only the view shown lights up. */}
        <nav className="segmented" aria-label="Show">
          <Link to="/audit" search={{ actorId }} activeOptions={{ exact: true }}>
            Actions
          </Link>
          <Link to="/audit" search={{ actorId, detail: '1' }} activeOptions={{ exact: true }}>
            Everything
          </Link>
          <Link to="/audit" search={{ actorId, decision: 'deny', detail: '1' }} activeOptions={{ exact: true }}>
            <SlashCircle size={13} />
            Denials
          </Link>
        </nav>

        {actorId !== undefined && (
          <Link
            className="filter-chip"
            to="/audit"
            search={{ ...filters, actorId: undefined, detail: search.detail }}
            aria-label={`Stop filtering by ${actorId}`}
          >
            Actor <span className="mono">{actorId}</span>
            <X size={13} />
          </Link>
        )}
      </div>

      <section className="card card-wide" aria-label="Audit entries">
        {shown.length === 0 ? (
          <EmptyState title={deniedOnly ? 'No denials recorded' : 'Nothing recorded yet'}>
            {deniedOnly
              ? 'Nobody has been turned away.'
              : 'The log fills as people read and write secrets and change who has access.'}
          </EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt audit events stacks">
              <thead>
                <tr>
                  <th className="n" title="Sequence number in the log">
                    #
                  </th>
                  <th className="col-shrink">
                    <span className="th">
                      <Clock size={14} />
                      When (UTC)
                    </span>
                  </th>
                  <th className="col-shrink">
                    <span className="th">
                      <User size={14} />
                      Who
                    </span>
                  </th>
                  <th>
                    <span className="th">
                      <Activity size={14} />
                      What they did
                    </span>
                  </th>
                  <th className="col-shrink">
                    <span className="th">
                      <ShieldCheck size={14} />
                      Decided by
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((batch) => (
                  <Line key={batch[0]!.seq} batch={batch} filters={filters} detail={search.detail} breakAt={breakAt} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

    </>
  );
}

type Entry = AuditEntryView;
type Filters = { decision?: 'deny'; actorId?: string };

/** One action: an entry, or a batch of them under one operation, which opens to each. */
function Line({
  batch,
  filters,
  detail,
  breakAt,
}: {
  batch: Entry[];
  filters: Filters;
  detail: '1' | undefined;
  breakAt: number | null;
}) {
  const breaksInside = breakAt !== null && batch.some((entry) => entry.seq === breakAt);
  const [open, setOpen] = useState(breaksInside);
  const lead = batch[0]!;
  const sentence = describe(batch);
  const seqs = batch.map((entry) => entry.seq);
  const grouped = batch.length > 1;

  return (
    <>
      <Row
        entry={lead}
        seq={grouped ? `${Math.min(...seqs)}–${Math.max(...seqs)}` : String(lead.seq)}
        parts={sentence.parts}
        refused={sentence.refused}
        decided={decidedBy(batch)}
        filters={filters}
        detail={detail}
        breaks={breaksInside && !grouped}
        marked={breaksInside}
        toggle={
          grouped ? (
            <button
              type="button"
              className="batch-toggle"
              aria-expanded={open}
              aria-label={open ? 'Hide each entry' : `Show each of ${batch.length} entries`}
              onClick={() => setOpen(!open)}
            >
              <ChevronRight size={14} />
            </button>
          ) : undefined
        }
      />
      {grouped &&
        open &&
        batch.map((entry) => {
          const one = describe([entry]);
          return (
            <Row
              key={entry.seq}
              entry={entry}
              seq={String(entry.seq)}
              parts={one.parts}
              refused={one.refused}
              decided={decidedBy([entry])}
              filters={filters}
              detail={detail}
              breaks={entry.seq === breakAt}
              marked={false}
              child
            />
          );
        })}
    </>
  );
}

function Row({
  entry,
  seq,
  parts,
  refused,
  decided,
  filters,
  detail,
  breaks,
  marked,
  toggle,
  child = false,
}: {
  entry: Entry;
  seq: string;
  parts: Part[];
  refused: boolean;
  decided: string;
  filters: Filters;
  detail: '1' | undefined;
  /** The entry where verification stopped. */
  breaks: boolean;
  /** A batch holding it, closed or open. */
  marked: boolean;
  toggle?: ReactNode;
  child?: boolean;
}) {
  const actor = who(entry);
  const classes = [
    refused && 'is-denied',
    (breaks || marked) && 'is-break',
    child && 'is-child',
    entry.detail && 'is-detail',
    entry.action === 'vault.tampered' && 'is-tampered',
  ].filter(Boolean);
  return (
    <tr className={classes.length === 0 ? undefined : classes.join(' ')}>
      <td className="n" data-label="Sequence">
        {seq}
      </td>
      <td className="nowrap cell-mono" data-label="When (UTC)">
        <Timestamp iso={entry.occurredAt} precise />
      </td>
      <td data-label="Who">
        {/* Filtering to one actor is the second question anyone asks after
            "what happened", so the actor is the control. */}
        <span className="actor">
          {typeof actor === 'string' ? (
            <Link to="/audit" search={{ ...filters, actorId: entry.actorId, detail }}>
              {actor}
            </Link>
          ) : (
            <Link to="/audit" search={{ ...filters, actorId: entry.actorId, detail }}>
              {memberName(actor.member)}
            </Link>
          )}
        </span>
        {entry.run !== null && (
          // The run its issuer named when the credential was exchanged: what it asserted, kept in entry #exchangeSeq.
          <small className="actor-run" title={`Exchanged in entry ${entry.run.exchangeSeq}`}>
            {runLabel(entry.run)}
          </small>
        )}
        {entry.token !== null && (
          // The personal token the person made the request with, by the label it was made with.
          <small className="actor-run" title={`Personal token ${entry.token.id}`}>
            via token “{entry.token.label}”
          </small>
        )}
      </td>
      <td className="cell-sentence" data-label="What they did">
        <span className="sentence">
          {toggle}
          {entry.action === 'vault.tampered' && <AlertTriangle size={13} />}
          <Sentence parts={parts} />
          {breaks && <BreakMark />}
        </span>
      </td>
      <td className="nowrap" data-label="Decided by">
        <span className={refused ? 'decided decided-refused' : 'decided'}>
          {refused && <SlashCircle size={13} />}
          {decided}
          {refused && ', refused'}
        </span>
      </td>
    </tr>
  );
}

/** The entry the log breaks at, said in words as well as in red. */
function BreakMark() {
  return (
    <span className="break-mark">
      <AlertTriangle size={11} />
      breaks here
    </span>
  );
}

/**
 * Whether the log still verifies, beside the title.
 *
 * This replaced a card with a "Verify chain" button on it. A green result you
 * have to ask for is reassurance rather than evidence: it is checked when
 * someone is already feeling confident, and not on the morning it would have
 * mattered. Recomputing on load makes the claim continuous.
 *
 * It is not waited for, though: verifying re-reads the whole log, so until
 * it answers the badge says it is verifying, and a check that could not run
 * says so and offers to run again, rather than passing for a broken log.
 */
function ChainStatus({ chain, onRetry }: { chain: ChainResult | undefined; onRetry: () => void }) {
  if (chain === undefined) {
    return (
      <span className="chain-note">
        <Spinner size={14} />
        Verifying…
      </span>
    );
  }

  if (chain.integrity === 'owners-only') {
    return (
      <Toggletip
        align="end"
        label="Only auditors, admins and owners of the whole instance can check the log: it takes every entry, and you see only your projects'."
      >
        <button type="button" className="chain-note">
          <Info size={14} />
          Verified by owners
        </button>
      </Toggletip>
    );
  }

  if (chain.integrity === 'unknown') {
    return (
      <div className="chain">
        <Toggletip
          align="end"
          label={`coffre could not check the log: ${chain.problem}. The entries below are unverified.`}
        >
          <button type="button" className="chain-flag chain-flag-warn">
            <AlertTriangle size={14} />
            Couldn’t verify
          </button>
        </Toggletip>
        <button type="button" className="btn btn-sm" onClick={onRetry}>
          Retry
        </button>
      </div>
    );
  }

  if (chain.integrity === 'broken') {
    return (
      <span className="chain-flag chain-flag-bad">
        <AlertTriangle size={14} />
        {chain.failedAtSeq === null ? 'Log does not verify' : `Log broken at ${chain.failedAtSeq}`}
      </span>
    );
  }

  return (
    <div className="chain">
      {chain.pending > 0 && (
        <Toggletip
          align="end"
          label="Keys released through KMS whose outcome the vault has not logged yet. Each settles within seconds, or is logged as failed."
        >
          <button type="button" className="chain-note" role="status">
            {chain.pending} key operation{chain.pending === 1 ? '' : 's'} in flight
          </button>
        </Toggletip>
      )}
      <Toggletip
        align="end"
        label={
          chain.checkpoint === null
            ? 'Audit log verified by the app and vault keys, not signed yet.'
            : `Audit log verified by the app and vault keys, last signature at ${absolute(chain.checkpoint.signedAt, false)} UTC.`
        }
      >
        <button type="button" className="chain-seal">
          <ShieldCheck size={14} />
          Verified
        </button>
      </Toggletip>
    </div>
  );
}
