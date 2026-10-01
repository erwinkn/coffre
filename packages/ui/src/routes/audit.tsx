import type { AuditEntryView, CoffreClient } from '@coffre/client';
import type { ReactNode } from 'react';
import { createFileRoute, Link } from '@tanstack/react-router';
import { statusOf, uiResult } from '../lib/coffre';
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
  Info,
  Layers,
  Ledger,
  ShieldCheck,
  SlashCircle,
  User,
  X,
} from '../components/icons';

type AuditSearch = { decision?: 'deny'; actorId?: string };

const PAGE_SIZE = 200;
const VAULT_PAGE_SIZE = 20;
type ChainResult = Awaited<ReturnType<typeof verifyChain>>;
type VaultResult = Awaited<ReturnType<typeof readVaultLog>>;

export const Route = createFileRoute('/audit')({
  // Filters live in the URL so a finding can cite the exact view it came from.
  validateSearch: (search: Record<string, unknown>): AuditSearch => ({
    decision: search.decision === 'deny' ? 'deny' : undefined,
    actorId:
      typeof search.actorId === 'string' && search.actorId !== '' ? search.actorId : undefined,
  }),
  loaderDeps: ({ search }) => search,
  // Both logs are checked on every visit rather than on demand. At this
  // volume it is one hash per row, of each, and costs less than the query
  // that fetched them, and a status that is always current beats a button
  // nobody presses.
  loader: async ({ context: { client }, deps, parentMatchPromise }) => {
    const rootAdmin = (await parentMatchPromise).loaderData?.instanceRole === 'root-admin';
    const [entries, chain, vault] = await Promise.all([
      listEntries(client, deps),
      verifyChain(client),
      rootAdmin ? readVaultLog(client) : null,
    ]);
    return { entries, chain, vault };
  },
  component: AuditPage,
});

function listEntries(client: CoffreClient, search: AuditSearch) {
  return uiResult(async () => {
    // Sign-ins stay in the log and its chain; this page is about what was
    // done with secrets and access, so the server leaves them out of the page.
    const { entries } = await client.audit.list({
      limit: PAGE_SIZE,
      decision: search.decision,
      actor: search.actorId,
      exclude: 'sign-ins',
    });
    const rows: AuditRow[] = entries.map((entry) => ({
      seq: entry.seq,
      occurredAt: entry.occurredAt,
      actorType: entry.actorType,
      actorId: entry.actorId,
      action: entry.action,
      decision: entry.decision,
      project: entry.project,
      environment: entry.environment,
      subject: subjectOf(entry),
    }));
    return { entries: rows };
  });
}

/**
 * Whether both logs hold, or why that is not known. Verifying is for owners:
 * anyone else reads one project's slice of the log, and a slice cannot be
 * checked as a chain, so for them it is a fact about the page, not a fault.
 */
async function verifyChain(client: CoffreClient) {
  try {
    const result = await client.audit.verify();
    return result.ok
      ? {
          integrity: 'intact' as const,
          rows: result.rows,
          head: result.head,
          checkpoint: result.checkpoint,
          vaultEntries: result.vault.entries,
        }
      : { integrity: 'broken' as const, log: result.log, failedAtSeq: result.failedAtSeq, reason: result.reason };
  } catch (error) {
    const status = statusOf(error);
    if (status === 403) return { integrity: 'owners-only' as const };
    return {
      integrity: 'unknown' as const,
      problem: status === undefined ? 'the request never got an answer' : `the request failed with HTTP ${status}`,
    };
  }
}

function readVaultLog(client: CoffreClient) {
  return uiResult(() => client.audit.vault({ limit: VAULT_PAGE_SIZE }));
}

function AuditPage() {
  const { entries: result, chain, vault } = Route.useLoaderData();
  const { decision, actorId } = Route.useSearch();
  const deniedOnly = decision === 'deny';

  if (!result.ok) {
    return (
      <ClosedDoor icon={<Ledger size={18} />} label="Audit" title="The audit log is closed to you">
        {result.error}
      </ClosedDoor>
    );
  }

  const broken = chain.integrity === 'broken' ? chain : null;
  const appBreak = broken?.log === 'audit' ? broken.failedAtSeq : null;
  const vaultFault = broken?.log === 'vault' ? broken : null;
  const vaultShown = vault !== null && vault.ok ? vault.entries.map((entry) => entry.seq) : [];

  return (
    <>
      <PageHeader title="Audit" actions={<ChainStatus chain={chain} />} />

      {broken !== null && (
        <div style={{ marginBottom: '1.25rem' }}>
          <Notice tone="bad">
            {broken.log === 'audit' ? (
              <>
                <strong>Treat this as an incident.</strong> The chain breaks at entry{' '}
                {broken.failedAtSeq}: {broken.reason}. Something with direct database access has
                altered or removed entries, and nothing from entry {broken.failedAtSeq} on can
                be relied on until that is explained.
                {broken.failedAtSeq !== null &&
                  !result.entries.some((entry) => entry.seq === broken.failedAtSeq) && (
                    <> {notListed(broken.failedAtSeq, 'below, which leave out sign-ins')}</>
                  )}
              </>
            ) : (
              <>
                <strong>Treat this as an incident.</strong>{' '}
                {broken.failedAtSeq === null
                  ? `The vault's store does not match its log. ${sentence(broken.reason)}.`
                  : `The vault log does not hold at entry ${broken.failedAtSeq}: ${broken.reason}.`} Something with direct access to the vault's storage has
                changed its record or who holds what, and no grant can be relied on until that
                is explained.
                {broken.failedAtSeq !== null && vault !== null && !vaultShown.includes(broken.failedAtSeq) && (
                  <> {notListed(broken.failedAtSeq, `in the vault log below, which shows its latest ${VAULT_PAGE_SIZE}`)}</>
                )}
              </>
            )}
          </Notice>
        </div>
      )}

      <section aria-labelledby="app-log">
        <div className="section-head section-head-first">
          <h2 className="section-title" id="app-log">
            App log
          </h2>
        </div>
        <p className="section-desc">
          Everything done through coffre, refusals included, except sign-ins.
          {vault !== null && ' A revealed value appears here, and once in the vault log.'}
        </p>

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

        <div className="card">
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
                    <AuditTableRow
                      key={entry.seq}
                      entry={entry}
                      deniedOnly={deniedOnly}
                      breaks={entry.seq === appBreak}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {vault !== null && <VaultLog vault={vault} fault={vaultFault} />}
    </>
  );
}

function sentence(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** Where to find an entry the notice names but the page does not show. */
function notListed(seq: number, where: string): ReactNode {
  return (
    <>
      Entry {seq} is not among the entries {where}; <code>coffre audit</code> lists them all.
    </>
  );
}

/**
 * The vault's own log, for root admins: the record the app cannot rewrite,
 * of every key it unwrapped or refused and every change of access. Only the
 * latest entries, and whether the whole chain holds; the API pages the rest.
 *
 * Its own verdict checks the chain up to the page; the page's verification
 * also replays who holds what, so a fault that finds is this log's verdict too.
 */
function VaultLog({
  vault,
  fault,
}: {
  vault: VaultResult;
  fault: { failedAtSeq: number | null; reason: string } | null;
}) {
  const failure = vault.ok && !vault.verification.ok ? vault.verification : fault;
  const brokenAt = failure?.failedAtSeq ?? null;
  return (
    <section aria-labelledby="vault-log">
      <div className="section-head">
        <h2 className="section-title" id="vault-log">
          Vault log
        </h2>
        {failure !== null ? (
          <span className="vault-verdict vault-verdict-bad" role="status">
            <AlertTriangle size={13} />
            {failure.failedAtSeq === null ? 'Broken' : `Broken at ${failure.failedAtSeq}`}:{' '}
            {failure.reason}
          </span>
        ) : (
          vault.ok &&
          vault.verification.ok && (
            <span className="vault-verdict">
              <ShieldCheck size={13} />
              {vault.verification.entries} entries, chain intact
            </span>
          )
        )}
      </div>
      <p className="section-desc">
        The vault's own record of every key it opened or sealed and every change of access. The
        app cannot write to it.
      </p>
      <div className="card">
        {!vault.ok ? (
          <EmptyState title="The vault log could not be read">{vault.error}</EmptyState>
        ) : vault.entries.length === 0 ? (
          <EmptyState title="Nothing recorded yet">
            The vault records every key it unwraps or refuses, and every change of access.
          </EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt audit stacks">
              <thead>
                <tr>
                  <th className="n">#</th>
                  <th className="col-shrink">When (UTC)</th>
                  <th>Actor</th>
                  <th className="col-shrink">Action</th>
                  <th>Subject</th>
                  <th className="col-shrink">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {vault.entries.map((entry) => {
                  const refused = entry.outcome === 'refuse';
                  const breaks = entry.seq === brokenAt;
                  return (
                    <tr key={entry.seq} className={rowClass(refused, breaks)}>
                      <td className="n" data-label="Sequence">
                        {entry.seq}
                      </td>
                      <td className="nowrap cell-mono" data-label="When (UTC)">
                        <Timestamp iso={entry.at} precise />
                      </td>
                      <td className="cell-mono" data-label="Actor">
                        {entry.actor}
                      </td>
                      <td className="cell-mono nowrap" data-label="Action">
                        {entry.action}
                        {breaks && <BreakMark />}
                      </td>
                      <td className="cell-mono" data-label="Subject">
                        {entry.subject ?? '—'}
                      </td>
                      <td className="nowrap" data-label="Outcome">
                        <span className={`decision ${refused ? 'decision-deny' : 'decision-allow'}`}>
                          {refused ? <SlashCircle size={13} /> : <CheckCircle size={13} />}
                          {refused ? breakAfterUnderscores(entry.code ?? 'refused') : 'allowed'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

function AuditTableRow({
  entry,
  deniedOnly,
  breaks,
}: {
  entry: AuditRow;
  deniedOnly: boolean;
  breaks: boolean;
}) {
  const denied = entry.decision === 'deny';

  return (
    <tr className={rowClass(denied, breaks)}>
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
        {breaks && <BreakMark />}
      </td>
      {/* Wraps, after its separators: with a person and a role it can be the
          widest cell, and the decision should not scroll out of sight. */}
      <td className="cell-mono" data-label="Subject">
        {breakAfterUnderscores(entry.subject)}
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

function rowClass(denied: boolean, breaks: boolean): string | undefined {
  return [denied && 'is-denied', breaks && 'is-break'].filter(Boolean).join(' ') || undefined;
}

/** The entry a log breaks at, said in words as well as in red. */
function BreakMark() {
  return (
    <span className="break-mark">
      <AlertTriangle size={11} />
      breaks here
    </span>
  );
}

/**
 * Whether both logs still recompute from their first entry, beside the title.
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
function ChainStatus({ chain }: { chain: ChainResult }) {
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
      <Toggletip
        align="end"
        label={`coffre could not check the chain: ${chain.problem}. The entries below loaded, but whether they are intact is unknown until it can. Reload to try again.`}
      >
        <button type="button" className="chain-flag chain-flag-warn">
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
        {chain.log === 'audit'
          ? `Chain broken at ${chain.failedAtSeq}`
          : chain.failedAtSeq === null
            ? "Vault store doesn't match its log"
            : `Vault log broken at ${chain.failedAtSeq}`}
      </span>
    );
  }

  return (
    <div className="chain">
      <Toggletip
        align="end"
        label={
          (chain.checkpoint === null
            ? 'Chain intact. The vault has not signed a checkpoint yet.'
            : `Chain intact, and unchanged through entry ${chain.checkpoint.seq}, which the vault signed at ${chain.checkpoint.signedAt}.`) +
          ` The vault's log holds too: ${chain.vaultEntries} entries, and every member and grant follows from them.`
        }
      >
        <button type="button" className="chain-seal">
          <ShieldCheck size={14} />
          Verified
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

/**
 * What an entry is about, in one line: the place, the key or the reason for a
 * refusal, and whom it concerns when it changes someone's access, with the
 * role. `market/prod · dev@acme.example (developer)`.
 */
function subjectOf(entry: AuditEntryView): string {
  const { metadata } = entry;
  const text = (value: unknown) => (typeof value === 'string' && value !== '' ? value : null);
  const place = [entry.project, entry.environment, text(metadata.key)].filter(
    (part): part is string => part !== null,
  );
  const parts = [place.join('/')];
  const who = text(metadata.principalId);
  if (who !== null) {
    const role = text(metadata.role) ?? (metadata.instanceRole === 'owner' ? 'owner' : null);
    const from = text(metadata.from);
    parts.push(role === null ? who : `${who} (${from === null ? role : `${from} → ${role}`})`);
  }
  if (text(metadata.key) === null) parts.push(text(metadata.reason) ?? '');
  const subject = parts.filter((part) => part !== '').join(' · ');
  return subject === '' ? '—' : subject;
}
