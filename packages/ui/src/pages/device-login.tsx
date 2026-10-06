import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { failureMessage, statusOf, useCoffre } from '../lib/coffre';

import { ClosedDoor } from '../components/page';
import { ErrorLine, Spinner, Timestamp } from '../components/ui';
import { CheckCircle, SlashCircle, Terminal } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import type { deviceLogin } from '../options';

const Route = pageRoute<typeof deviceLogin>();

/**
 * Where `coffre login` sends you: approve a terminal's sign-in with the
 * session this browser already has. The terminal shows a code; this page
 * shows the same code and where the request came from, and nothing happens
 * until you press Approve.
 */

export function DevicePage() {
  const loaded = Route.useLoaderData();
  const [decided, setDecided] = useState<'approved' | 'denied' | null>(null);

  if (decided === 'approved') {
    return (
      <ClosedDoor icon={<CheckCircle size={18} />} label="coffre CLI" title="Your terminal is signed in">
        <p>You can close this tab and go back to the terminal.</p>
      </ClosedDoor>
    );
  }
  if (decided === 'denied') {
    return (
      <ClosedDoor icon={<SlashCircle size={18} />} label="coffre CLI" title="Sign-in refused">
        <p>
          The terminal gets nothing. If you did not run <span className="mono">coffre login</span>{' '}
          yourself, someone may be trying to get you to approve theirs.
        </p>
      </ClosedDoor>
    );
  }

  if (loaded === null) return <CodeEntry />;
  if (!loaded.ok) return <CodeEntry error={loaded.error} />;
  if (loaded.request === null) {
    return <CodeEntry error="That code is unknown, already used, or expired. Run coffre login again for a new one." />;
  }
  return <Approve request={loaded.request} sessionDays={loaded.sessionDays} onDecided={setDecided} />;
}

function CodeEntry({ error = null }: { error?: string | null }) {
  const navigate = useNavigate();
  const [code, setCode] = useState('');
  return (
    <section className="card signin" aria-labelledby="device-title">
      <div className="signin-head">
        <h1 className="signin-title" id="device-title">
          Sign in the coffre CLI
        </h1>
        <p className="signin-lede">
          Enter the code your terminal shows after <span className="mono">coffre login</span>.
        </p>
      </div>
      <form
        className="signin-form"
        onSubmit={(event) => {
          event.preventDefault();
          void navigate({ to: '/auth/device', search: { code: code.trim() } });
        }}
      >
        <label className="field">
          <span className="label">Code</span>
          <input
            className="input mono device-code-input"
            name="code"
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            placeholder="XXXX-XXXX"
            maxLength={16}
            value={code}
            onChange={(event) => setCode(event.target.value)}
          />
        </label>
        <button className="btn btn-primary" type="submit" style={{ height: '2.125rem' }} disabled={code.trim() === ''}>
          Continue
        </button>
      </form>
      {error !== null && (
        <div className="signin-error">
          <ErrorLine error={error} />
        </div>
      )}
    </section>
  );
}

function Approve({
  request,
  sessionDays,
  onDecided,
}: {
  request: { userCode: string; clientLabel: string | null; clientIp: string | null; createdAt: string };
  sessionDays: number;
  onDecided: (decision: 'approved' | 'denied') => void;
}) {
  const coffre = useCoffre();
  const [pending, setPending] = useState<'approve' | 'deny' | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function decide(approve: boolean) {
    setPending(approve ? 'approve' : 'deny');
    try {
      await coffre.deviceLogins.decide(request.userCode, approve);
      onDecided(approve ? 'approved' : 'denied');
    } catch (error) {
      setError(
        statusOf(error) === 404
          ? 'That code is unknown, already used, or expired. Run coffre login again.'
          : statusOf(error) === undefined
            ? 'The decision could not be sent. Nothing was approved.'
            : failureMessage(error),
      );
    } finally {
      setPending(null);
    }
  }

  return (
    <section className="card signin" aria-labelledby="device-title">
      <div className="signin-head">
        <h1 className="signin-title" id="device-title">
          Approve this terminal?
        </h1>
        <p className="signin-lede">
          Only if you just ran <span className="mono">coffre login</span> yourself and it shows
          this code. It gets your access for {sessionDays} days.
        </p>
      </div>

      <p className="device-code" aria-label="Code">
        {request.userCode}
      </p>

      <dl className="facts device-facts">
        <div className="fact">
          <dt>Client</dt>
          <dd>
            <span className="cell-account">
              <Terminal size={14} />
              {request.clientLabel ?? 'coffre CLI'}
            </span>
          </dd>
        </div>
        <div className="fact">
          <dt>Requested from</dt>
          <dd className="mono">{request.clientIp ?? 'an unknown address'}</dd>
        </div>
        <div className="fact">
          <dt>Requested (UTC)</dt>
          <dd>
            <Timestamp iso={request.createdAt} />
          </dd>
        </div>
      </dl>

      {error !== null && (
        <div className="signin-error">
          <ErrorLine error={error} />
        </div>
      )}

      <div className="device-actions">
        <Link className="btn btn-quiet" to="/projects">
          Cancel
        </Link>
        <button className="btn" disabled={pending !== null} onClick={() => void decide(false)}>
          {pending === 'deny' && <Spinner />}
          Deny
        </button>
        <button className="btn btn-primary" disabled={pending !== null} onClick={() => void decide(true)}>
          {pending === 'approve' && <Spinner />}
          Approve
        </button>
      </div>
    </section>
  );
}
