import { useState } from 'react';
import type { ApprovalView, Decision } from '@coffre/client';

import { failureMessage, statusOf, useCoffre } from '../lib/coffre';
import { ClosedDoor } from '../components/page';
import { CopyButton, ErrorLine, Notice, Spinner, Timestamp } from '../components/ui';
import { CheckCircle, Link as LinkIcon, SlashCircle } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { approval } from '../options';

const Route = pageRoute<typeof approval>();

/**
 * Where an MCP client sends you to confirm a change it asked for: what it
 * would do, read afresh, and Approve, which makes it here and now, as you.
 * The app only hears what became of it. Nothing changes until you press
 * Approve, and a value you type goes to coffre and nowhere else.
 */
export function ApprovalPage() {
  const loaded = Route.useLoaderData();
  const [decided, setDecided] = useState<Decision | null>(null);

  if (decided !== null) return <Decided decision={decided} reveal={loaded.ok && loaded.approval.kind === 'reveal'} />;
  if (!loaded.ok) {
    return (
      <ClosedDoor icon={<SlashCircle size={18} />} label="Approve a change" title="This approval can't be shown">
        <p>{loaded.error}</p>
      </ClosedDoor>
    );
  }
  const view = loaded.approval;
  if (view.status !== 'pending') return <Settled view={view} />;
  return <Approve view={view} onDecided={setDecided} />;
}

const SETTLED: Record<Exclude<ApprovalView['status'], 'pending'>, string> = {
  approved: 'You approved this',
  denied: 'You denied this',
  cancelled: 'The app cancelled this',
  failed: 'This change failed',
  expired: 'This approval expired',
};

function Settled({ view }: { view: ApprovalView }) {
  const status = view.status as keyof typeof SETTLED;
  return (
    <ClosedDoor
      icon={status === 'approved' ? <CheckCircle size={18} /> : <SlashCircle size={18} />}
      label="Approve a change"
      title={SETTLED[status]}
    >
      <p>
        {view.client.name} asked to {view.summary}.{' '}
        {view.outcome?.text ?? (status === 'expired' ? 'Nothing changed. The app can ask again.' : 'Nothing changed.')}
      </p>
    </ClosedDoor>
  );
}

function Decided({ decision, reveal }: { decision: Decision; reveal: boolean }) {
  const done = decision.status === 'approved';
  return (
    <ClosedDoor
      icon={done ? <CheckCircle size={18} /> : <SlashCircle size={18} />}
      label={reveal ? 'Show a value' : 'Approve a change'}
      title={done ? (reveal ? 'The value' : 'Done') : decision.status === 'denied' ? 'Denied' : reveal ? 'It could not be shown' : 'The change failed'}
    >
      {!(reveal && done) && <p>{decision.outcome.text}</p>}
      {decision.shown.length > 0 && (
        <>
          <Notice tone="warn">{reveal ? 'Shown here only, and logged as your reveal: the app does not get it.' : 'Shown once, here only: copy it now. The app does not get it.'}</Notice>
          <dl className="facts device-facts">
            {decision.shown.map((line) => (
              <div className="fact" key={line.label}>
                <dt>{line.label}</dt>
                <dd className="cell-account">
                  <span className="mono approval-shown">{line.value}</span>
                  <CopyButton value={line.value} label={`Copy ${line.label.toLowerCase()}`} />
                </dd>
              </div>
            ))}
          </dl>
        </>
      )}
      <p>You can close this tab: the app hears the outcome when it asks.</p>
    </ClosedDoor>
  );
}

function Approve({ view, onDecided }: { view: ApprovalView; onDecided: (decision: Decision) => void }) {
  const coffre = useCoffre();
  const [value, setValue] = useState('');
  const [pending, setPending] = useState<'approve' | 'deny' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { client } = view;
  const asksValue = view.asks?.value ?? null;
  const reveal = view.kind === 'reveal';

  async function decide(approve: boolean) {
    setPending(approve ? 'approve' : 'deny');
    try {
      onDecided(
        await coffre.approvals.decide(view.id, {
          approve,
          digest: view.digest,
          ...(approve && asksValue !== null ? { value } : {}),
        }),
      );
    } catch (error) {
      setError(statusOf(error) === undefined ? 'The answer could not be sent. Nothing changed.' : failureMessage(error));
      setPending(null);
    }
  }

  return (
    <section className="card signin" aria-labelledby="approval-title">
      <div className="signin-head">
        <h1 className="signin-title" id="approval-title">
          {reveal ? 'Show this value?' : 'Approve this change?'}
        </h1>
        <p className="signin-lede">
          {client.name} asks to <strong>{view.summary}</strong>.{' '}
          {reveal
            ? 'Reveal shows it here, to you, logged as your reveal; it is never sent to the app.'
            : 'Read what it does: nothing changes until you approve, and then coffre makes it, as you.'}
        </p>
      </div>

      <div className="consent-client">
        <LinkIcon size={16} />
        <span className="cell-stack">
          {client.host !== null ? <span className="consent-host mono">{client.host}</span> : <span className="consent-host">{client.name}</span>}
          <span>
            {client.host !== null && <>{client.name} </>}
            {client.registration === 'dcr' && <span className="tag tag-amber">Unverified</span>}
          </span>
        </span>
      </div>

      <dl className="facts device-facts">
        {view.details.map((line) => (
          <div className="fact" key={line.label}>
            <dt>{line.label}</dt>
            <dd className={line.kind === 'mono' ? 'mono' : undefined}>
              {line.kind === 'time' ? <Timestamp iso={line.value} /> : line.value}
            </dd>
          </div>
        ))}
        <div className="fact">
          <dt>Expires (UTC)</dt>
          <dd>
            <Timestamp iso={view.expiresAt} />
          </dd>
        </div>
      </dl>

      {asksValue !== null && (
        <label className="field approval-field">
          <span className="label">{asksValue.label}</span>
          <textarea
            className="input mono approval-value"
            name="value"
            rows={3}
            autoComplete="off"
            spellCheck={false}
            value={value}
            disabled={pending !== null}
            onChange={(event) => setValue(event.target.value)}
          />
          <small>{asksValue.note}</small>
        </label>
      )}

      <div className="consent-notices">
        {client.registration === 'dcr' && (
          <Notice tone="warn">This app registered itself: its name is its own claim. Approve only what you asked it to do.</Notice>
        )}
        <ErrorLine error={error} />
      </div>

      <div className="device-actions">
        <button className="btn" disabled={pending !== null} onClick={() => void decide(false)}>
          {pending === 'deny' && <Spinner />}
          Deny
        </button>
        <button
          className="btn btn-primary"
          disabled={pending !== null || (asksValue !== null && value === '')}
          onClick={() => void decide(true)}
        >
          {pending === 'approve' && <Spinner />}
          {reveal ? 'Reveal' : 'Approve'}
        </button>
      </div>
    </section>
  );
}
