import { useEffect, useRef, useState } from 'react';

import { Key } from './icons';
import { ErrorLine, Modal, Spinner } from './ui';
import { onFreshAsk, type FreshAsk } from '../lib/fresh';
import { authenticatorError, browserClock, deadlineOf, passkeyAnswer, readClock, sendPasskey, type Unsent } from '../lib/passkey-answer';
import { requestOptions, toJSON, type RequestJSON } from '../lib/webauthn';

/** What the step-up's door asks of this browser's session: a touch of the person's live passkeys, and its sealed state. */
type Step = { email: string; options: RequestJSON; state: string };

/**
 * "Confirm it's you", over any page, when an act it sent takes a fresh check (`lib/fresh.ts`; docs/design/passkeys.md,
 * section 3.4): a touch at the step-up's door (`GET` and `POST /api/auth/passkey?step-up=1`), which gives this browser
 * a new session, confirmed for five minutes, and ends the one it had; the act then goes again. For a person with no
 * passkey yet, under `optional`: sign in again and add one, which confirms the session it makes. Mounted once, by
 * `CoffreProvider`.
 */
export function FreshCheck() {
  const [ask, setAsk] = useState<FreshAsk | null>(null);
  useEffect(() => onFreshAsk(setAsk), []);
  return (
    <Modal
      open={ask !== null}
      onOpenChange={(open) => {
        if (!open) ask?.settle(false);
      }}
      title={ask?.add === true ? 'Add a passkey first' : 'Confirm it’s you'}
    >
      {ask === null ? null : ask.add ? <AddPasskey ask={ask} /> : <Touch ask={ask} />}
    </Modal>
  );
}

function here(): string {
  return `${window.location.pathname}${window.location.search}`;
}

/** The touch: its options asked as the dialog opens, so that the press reaches the authenticator at once. */
function Touch({ ask }: { ask: FreshAsk }) {
  const [step, setStep] = useState<Step | 'none' | 'unavailable' | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unsent = useRef<Unsent>({ body: null, asked: false });

  useEffect(() => {
    let current = true;
    setStep(null);
    const fresh: Unsent = { body: null, asked: false };
    unsent.current = fresh;
    const sent = readClock(browserClock);
    void passkeyAnswer<Step>(fetch(`/api/auth/passkey?step-up=1&next=${encodeURIComponent(here())}`, { credentials: 'same-origin' })).then((answer) => {
      if (!current) return;
      if (answer.kind === 'ok') fresh.ends = deadlineOf(sent, answer.value.options.timeout);
      setStep(answer.kind === 'ok' ? answer.value : answer.kind === 'refused' ? 'none' : 'unavailable');
    });
    return () => {
      current = false;
    };
  }, [attempt]);

  async function press(current: Step) {
    setBusy(true);
    setError(null);
    try {
      const answer = await sendPasskey<{ next?: unknown }>(
        unsent.current,
        async (left) => {
          const credential = await navigator.credentials.get({ publicKey: requestOptions({ ...current.options, timeout: Math.min(left, current.options.timeout) }) });
          if (credential === null) throw new DOMException('no passkey answered', 'NotAllowedError');
          return JSON.stringify({ state: current.state, response: toJSON(credential as PublicKeyCredential) });
        },
        (body) => fetch('/api/auth/passkey', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body }),
      );
      if (answer.kind === 'ok') {
        // The response set the new session's cookie: the act goes again on it.
        ask.settle(true);
        return;
      }
      if (answer.kind === 'expired' || answer.kind === 'stale') {
        setError('This request lapsed while the dialog was open. Press again for a new one.');
        setAttempt((n) => n + 1);
      } else if (answer.kind === 'unavailable') {
        setError('coffre did not answer just now. Try again in a moment: it sends the same touch, without asking for another.');
      } else if (answer.code === 'passkey_failed') {
        setError('That passkey did not confirm it’s you. Try again, or another one.');
      } else {
        // The session it was asked for ended, or another tab confirmed it first, which left this browser its own new
        // one: ask again, of the session the browser holds now.
        setError('Your session changed meanwhile. Press again.');
        setAttempt((n) => n + 1);
      }
    } catch (thrown) {
      setError(authenticatorError(thrown, current.options.rpId));
    } finally {
      setBusy(false);
    }
  }

  if (step === 'none') {
    return (
      <>
        <p className="dialog-body">This session has no passkey of yours to ask for here. Sign in again, then try once more.</p>
        <div className="dialog-actions">
          <button className="btn" type="button" onClick={() => ask.settle(false)}>
            Cancel
          </button>
          <a className="btn btn-primary" href={`/login?next=${encodeURIComponent(here())}`}>
            Sign in again
          </a>
        </div>
      </>
    );
  }
  return (
    <>
      <p className="dialog-body">
        This takes a touch of your passkey, with your fingerprint, face or device PIN. It counts for the next five minutes.
      </p>
      {step === 'unavailable' && <ErrorLine error="coffre did not answer just now." />}
      <ErrorLine error={error} />
      <div className="dialog-actions">
        <button className="btn" type="button" onClick={() => ask.settle(false)}>
          Cancel
        </button>
        {step === 'unavailable' ? (
          <button className="btn btn-primary" type="button" onClick={() => setAttempt((n) => n + 1)}>
            Try again
          </button>
        ) : (
          <button className="btn btn-primary" type="button" disabled={step === null || busy} aria-busy={step === null || busy} onClick={() => step !== null && void press(step)}>
            {step === null || busy ? <Spinner /> : <Key size={14} />}
            Use passkey
          </button>
        )}
      </div>
    </>
  );
}

/** No passkey yet: sign in again with a provider, asking to add one, and come back here. */
function AddPasskey({ ask }: { ask: FreshAsk }) {
  const [providers, setProviders] = useState<{ id: string; label: string }[] | null>(null);
  useEffect(() => {
    let current = true;
    void fetch('/api/auth', { credentials: 'same-origin' })
      .then((response) => (response.ok ? (response.json() as Promise<{ signin: { providers: { id: string; label: string }[] } | null }>) : null))
      .catch(() => null)
      .then((info) => {
        if (current) setProviders(info?.signin?.providers ?? []);
      });
    return () => {
      current = false;
    };
  }, []);
  const next = encodeURIComponent(here());
  return (
    <>
      <p className="dialog-body">
        This takes a passkey: your fingerprint, face or device PIN, so that your account at your provider alone is not
        enough. Sign in again to add one, then do this again. Your next sign-ins will ask for it too.
      </p>
      <div className="dialog-actions">
        <button className="btn" type="button" onClick={() => ask.settle(false)}>
          Cancel
        </button>
        {providers === null ? (
          <button className="btn btn-primary" type="button" disabled aria-busy>
            <Spinner />
          </button>
        ) : (
          providers.map((provider) => (
            <a key={provider.id} className="btn btn-primary" href={`/auth/signin/${encodeURIComponent(provider.id)}?passkey=add&next=${next}`}>
              Sign in with {provider.label}
            </a>
          ))
        )}
      </div>
    </>
  );
}
