import type { AuditEntryView } from '@coffre/client';
import { Fragment, useState, type ReactNode } from 'react';
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
import { breakAfterUnderscores, EmptyState, Notice, Spinner, Timestamp, Toggletip } from '../components/ui';
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
import { pageRoute, type Parent } from '../lib/page-route';
import type { audit } from '../routes';

const Route = pageRoute<ReturnType<typeof audit<Parent>>>();

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
                  ': it may be detail, which Show detail lists.'
                )}
              </>
            )}
          </Notice>
        </div>
      )}

      <div className="toolbar">
        <nav className="segmented" aria-label="Filter by decision">
          {/* `exact` compares the whole search, not a subset of it: otherwise
              "All events" for one actor also counts as active while that
              actor's denials are showing, and both halves light up. */}
          <Link to="/audit" search={{ ...filters, decision: undefined, detail: search.detail }} activeOptions={{ exact: true }}>
            All events
          </Link>
          <Link to="/audit" search={{ ...filters, decision: 'deny', detail: search.detail }} activeOptions={{ exact: true }}>
            <SlashCircle size={13} />
            Denials only
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

        <Link
          className="detail-toggle"
          to="/audit"
          search={{ ...filters, detail: detail ? undefined : '1' }}
          aria-pressed={detail}
        >
          <span className="switch" aria-hidden="true" />
          Show detail
        </Link>
      </div>

      <section className="card" aria-label="Audit entries">
        {shown.length === 0 ? (
          <EmptyState title={deniedOnly ? 'No denials recorded' : 'Nothing recorded yet'}>
            {deniedOnly
              ? 'Every decision reaches this log, refusals included. An empty page means nobody has been turned away.'
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
        batch={batch}
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
  batch,
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
  /** The batch a line stands for, to name a sync by any of its entries. */
  batch?: Entry[];
}) {
  const actor = who(batch ?? [entry]);
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

/** A sentence, its people and places links to their pages. */
function Sentence({ parts }: { parts: Part[] }) {
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {typeof part === 'string' ? (
            part
          ) : 'place' in part ? (
            <PlaceLink path={part.place} />
          ) : (
            <MemberLink member={part.member} />
          )}
        </Fragment>
      ))}
    </>
  );
}

function PlaceLink({ path }: { path: string }) {
  const [project, environment] = path.split('/') as [string, string | undefined];
  const text = <span className="mono">{breakAfterUnderscores(path)}</span>;
  return environment === undefined ? (
    <Link to="/projects/$project" params={{ project }}>
      {text}
    </Link>
  ) : (
    <Link to="/projects/$project/$environment" params={{ project, environment }}>
      {text}
    </Link>
  );
}

function MemberLink({ member }: { member: string }) {
  return member.startsWith('token:') ? (
    <Link to="/tokens/$token" params={{ token: member.slice('token:'.length) }}>
      {member}
    </Link>
  ) : (
    <Link to="/users/$user" params={{ user: memberName(member) }}>
      {memberName(member)}
    </Link>
  );
}

function memberName(member: string): string {
  return member.startsWith('user:') ? member.slice('user:'.length) : member;
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
        label="Owners and root admins see whether the log is intact. Checking it means recomputing every entry, and you read only your projects' part of it."
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
          label={`coffre could not check the log: ${chain.problem}. The entries below loaded, but whether they are intact is unknown until it can.`}
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
          `Every entry through ${chain.through ?? 0} holds, under the app's key and the vault's.` +
          (chain.checkpoint === null
            ? ' The vault has not signed the log yet.'
            : ` The vault last signed it through entry ${chain.checkpoint.seq}, at ${chain.checkpoint.signedAt}.`)
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
