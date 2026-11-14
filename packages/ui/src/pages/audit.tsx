import { type AuditEntryView } from '@coffre/client';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useSuspenseQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useCoffre } from '../lib/coffre';
import { queries, type AuditSearch } from '../lib/queries';
import { proofOf, remember, shownProofs, type Head, type Proof, type Proved } from '../lib/audit-proofs';
import {
  decidedBy,
  describe,
  lines,
  perSecret,
  runLabel,
  who,
  type Part,
} from '../lib/audit-sentences';
import { absolute, EmptyState, Notice, Timestamp, Toggletip } from '../components/ui';
import { memberName, Sentence } from '../components/audit-sentence';
import { ClosedDoor, PageHeader } from '../components/page';
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  Clock,
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
  const entries = useSuspenseQuery(queries.auditEntries(client, search));
  const result = entries.data;
  // What this page has seen proven, by head, while it is open: see `shownProofs`.
  const proved = useRef<Proved>(new Map());
  const proofs = result.ok ? shownProofs(proved.current, result.head, result.entries) : new Map<number, Proof>();
  useEffect(() => {
    if (result.ok) remember(proved.current, result.head, result.entries);
  }, [result]);
  const { decision, actorId } = search;
  const deniedOnly = decision === 'deny';

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Ledger size={18} />} label="Audit" title="The audit log is closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  const proof = (entry: Entry) => proofs.get(entry.seq) ?? entry.proof;
  const failed = result.entries.filter((entry) => proof(entry) === 'failed');
  const counts = {
    failed: failed.length,
    unproven: result.entries.filter((entry) => proof(entry) === 'unproven').length,
    proven: result.entries.filter((entry) => proof(entry) === 'proven').length,
  };
  const signed = result.head === null ? null : `${absolute(result.head.signedAt, false)} UTC`;
  const holes = result.holes ?? [];
  const missing = holes.reduce((sum, hole) => sum + hole.kept + hole.aging, 0);
  const shown = lines(result.entries);
  const filters = { decision, actorId };

  return (
    <>
      <PageHeader
        title="Audit"
        actions={
          // One region for every state, so each change of it is announced.
          <div className="chain-live" aria-live="polite" aria-atomic="true">
            <ProofStatus
              head={result.head}
              counts={counts}
              checking={entries.isFetching}
              onCheck={() => void entries.refetch()}
            />
          </div>
        }
      />

      {failed.length > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="bad">
            <strong>Treat this as an incident.</strong>{' '}
            {failed.length === 1 ? `Entry ${failed[0]!.seq} is` : `${failed.length} entries below are`} not what the vault
            signed{signed === null ? '' : ` in the head it signed at ${signed}`}. Something with direct access to the
            database has changed what the log records, and {failed.length === 1 ? 'that entry' : 'those entries'} can’t be
            relied on until that is explained.
          </Notice>
        </div>
      )}

      {missing > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="warn">
            The log lacks {missing.toLocaleString('en')} {missing === 1 ? 'entry' : 'entries'} the vault’s head numbers
            {holes.length === 1 ? where(holes[0]!) : `, in ${holes.length} places`}. A prune while the page read the log
            does this, and checking again settles it; entries that stay missing were removed by something with direct
            access to the database.
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
                  <Line key={batch[0]!.seq} batch={batch} filters={filters} detail={search.detail} proof={proof} />
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

/**
 * One action: an entry, or a batch of them under one operation, which opens
 * to each; a read of several secrets, logged as one entry, opens to each
 * secret, under its entry's number.
 */
function Line({
  batch,
  filters,
  detail,
  proof,
}: {
  batch: Entry[];
  filters: Filters;
  detail: '1' | undefined;
  proof: (entry: Entry) => Proof;
}) {
  const proofs = batch.map(proof);
  const shown = proofOf(proofs);
  // A batch with an entry that fails opens on it.
  const [open, setOpen] = useState(shown === 'failed');
  const lead = batch[0]!;
  const sentence = describe(batch);
  const seqs = batch.map((entry) => entry.seq);
  const each = batch.flatMap(perSecret);
  const grouped = each.length > 1;
  const [unit, units] = each.length === batch.length ? ['entry', 'entries'] : ['secret', 'secrets'];
  const [first, last] = [Math.min(...seqs), Math.max(...seqs)];

  return (
    <>
      <Row
        entry={lead}
        seq={first === last ? String(first) : `${first}–${last}`}
        parts={sentence.parts}
        refused={sentence.refused}
        decided={decidedBy(batch)}
        filters={filters}
        detail={detail}
        proof={shown}
        toggle={
          grouped ? (
            <button
              type="button"
              className="batch-toggle"
              aria-expanded={open}
              aria-label={open ? `Hide each ${unit}` : `Show each of ${each.length} ${units}`}
              onClick={() => setOpen(!open)}
            >
              <ChevronRight size={14} />
            </button>
          ) : undefined
        }
      />
      {grouped &&
        open &&
        each.map((entry, i) => {
          const one = describe([entry]);
          return (
            <Row
              key={`${entry.seq}:${i}`}
              entry={entry}
              seq={String(entry.seq)}
              parts={one.parts}
              refused={one.refused}
              decided={decidedBy([entry])}
              filters={filters}
              detail={detail}
              proof={proof(entry)}
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
  proof,
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
  /** Its own, or a batch's: its worst entry's. */
  proof: Proof;
  toggle?: ReactNode;
  child?: boolean;
}) {
  const actor = who(entry);
  const classes = [
    refused && 'is-denied',
    proof === 'failed' && 'is-break',
    child && 'is-child',
    entry.detail && 'is-detail',
    entry.action === 'vault.tampered' && 'is-tampered',
  ].filter(Boolean);
  return (
    <tr className={classes.length === 0 ? undefined : classes.join(' ')} data-proof={proof}>
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
        {entry.token != null && (
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
          {proof === 'failed' && <BreakMark />}
          {proof === 'unproven' && <span className="unproven-mark">not proven</span>}
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

/** An entry that is not what the vault signed, said in words as well as in red. */
function BreakMark() {
  return (
    <span className="break-mark">
      <AlertTriangle size={11} />
      not as signed
    </span>
  );
}

/** Where a hole is, between the entries found around it. */
function where(hole: { above: number | null; below: number | null }): string {
  if (hole.above !== null && hole.below !== null) return ` between entries ${hole.below} and ${hole.above}`;
  if (hole.below !== null) return ` after entry ${hole.below}`;
  if (hole.above !== null) return ` before entry ${hole.above}`;
  return '';
}

/**
 * What the entries shown prove, beside the title: rendered with the page,
 * from the answer that listed them, never a loading state.
 *
 * The vault vouches for a head of the log in the page's own call, and the
 * server proves each entry shown against it from the tiles. So the claim is
 * about what is on screen, every time it is shown, however long the log.
 * An entry past the head is not proven: signed since the vault's read, or
 * put there by a writer, which the page cannot tell apart; checking again,
 * against a newer head, settles the first.
 */
function ProofStatus({
  head,
  counts,
  checking,
  onCheck,
}: {
  head: Head;
  counts: Record<Proof, number>;
  /** The page is being asked again. */
  checking: boolean;
  onCheck: () => void;
}) {
  const plural = (n: number) => `${n.toLocaleString('en')} ${n === 1 ? 'entry' : 'entries'}`;
  if (counts.failed > 0) {
    return (
      <span className="chain-flag chain-flag-bad">
        <AlertTriangle size={14} />
        {plural(counts.failed)} not as signed
      </span>
    );
  }

  const again = (
    <button type="button" className="btn btn-sm" disabled={checking} onClick={onCheck}>
      Check again
    </button>
  );
  if (head === null) {
    return (
      <div className="chain">
        <Toggletip
          align="end"
          label="The vault vouched for no head of the log: it has signed none yet, or the one in the database is not one it signed. No entry below is proven."
        >
          <button type="button" className="chain-flag chain-flag-warn">
            <AlertTriangle size={14} />
            Not proven
          </button>
        </Toggletip>
        {again}
      </div>
    );
  }

  const signed = `${absolute(head.signedAt, false)} UTC`;
  return (
    <div className="chain">
      {counts.unproven > 0 && (
        <>
          <Toggletip
            align="end"
            label={`Past the head the vault signed at ${signed}, of ${head.size.toLocaleString('en')} entries: signed since, or put there by something with direct access to the database. Checking again, against a newer head, settles the first.`}
          >
            <button type="button" className="chain-note" role="status">
              {plural(counts.unproven)} not proven
            </button>
          </Toggletip>
          {again}
        </>
      )}
      {counts.proven > 0 && (
        <Toggletip
          align="end"
          label={`Each entry below the vault’s head, signed at ${signed}, is proven against it: what it records is what the vault signed, where it signed it.`}
        >
          <button type="button" className="chain-seal">
            <ShieldCheck size={14} />
            Proven
          </button>
        </Toggletip>
      )}
    </div>
  );
}
