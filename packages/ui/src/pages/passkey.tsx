import { useEffect, useRef, useState } from 'react';

import { ErrorLine, Spinner } from '../components/ui';
import { Key } from '../components/icons';
import { ResetNotice } from '../components/reset-notice';
import { pageRoute } from '../lib/page-route';
import { authenticatorError, browserClock, deadlineOf, passkeyAnswer, readClock, sendPasskey, type Unsent } from '../lib/passkey-answer';
import { signinErrorMessage } from '../lib/signin-errors';
import { createCredential, getCredential, toJSON, type CreationJSON, type RequestJSON } from '../lib/webauthn';
import type { passkey } from '../options';

const Route = pageRoute<typeof passkey>();

/**
 * What `GET /api/auth/passkey` asks the browser for: a touch (`get()`), or a new passkey (`create()`), in WebAuthn's
 * JSON form, with the sealed `state` the answer goes back with: a step-up's, or the user handle this GET drew for a new
 * passkey.
 */
type Step =
  | { purpose: 'signin' | 'step-up'; email: string; options: RequestJSON; state?: string }
  | { purpose: 'enroll'; email: string; options: CreationJSON; state: string; reset?: { by: string; at: string } | null };

/**
 * `/auth/passkey`: the passkey a sign-in waits for after the provider
 * (docs/design/passkeys.md, section 3.1), or a step-up's (`?step-up=1`,
 * section 6.2): "Confirm it's you", or, for a first passkey, "Add a passkey
 * to finish signing in". What to ask the browser is read here, in the
 * browser, which alone can answer it; the button asks at once, as the touch
 * must follow the click.
 */
export function PasskeyPage() {
  const search = Route.useSearch();
  const stepUp = search['step-up'] === '1';
  // `unavailable`: coffre did not answer what to ask; the sign-in still waits, so the page offers to ask again.
  const [step, setStep] = useState<Step | 'none' | 'unavailable' | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Why the step ended without a session, when it did: said above the way back in.
  const [ended, setEnded] = useState<string | null>(null);
  // An answer coffre did not answer: the next press sends it again, never asks for another (`sendPasskey`).
  const [unanswered, setUnanswered] = useState(false);
  // The step's answer coffre did not answer, for the next press; each GET's step starts with none.
  const unsent = useRef<Unsent>({ body: null, asked: false });

  useEffect(() => {
    const query = stepUp ? `?step-up=1${search.next === undefined ? '' : `&next=${encodeURIComponent(search.next)}`}` : '';
    let current = true;
    setStep(null);
    setUnanswered(false);
    const fresh: Unsent = { body: null, asked: false };
    unsent.current = fresh;
    const sent = readClock(browserClock);
    void passkeyAnswer<Step>(fetch(`/api/auth/passkey${query}`, { credentials: 'same-origin' })).then((answer) => {
      if (!current) return;
      // The options lapse with the step, five minutes from its challenge: a press after asks the authenticator nothing.
      if (answer.kind === 'ok') fresh.ends = deadlineOf(sent, answer.value.options.timeout);
      setStep(answer.kind === 'ok' ? answer.value : answer.kind === 'refused' ? 'none' : 'unavailable');
    });
    return () => {
      current = false;
    };
  }, [stepUp, search.next, attempt]);

  const again = `/login${search.next === undefined ? '' : `?next=${encodeURIComponent(search.next)}`}`;
  if (step === null) {
    return (
      <section className="card signin" aria-busy>
        <div className="signin-head">
          <Spinner />
        </div>
      </section>
    );
  }
  if (step === 'unavailable') {
    return (
      <section className="card signin" aria-labelledby="passkey-title">
        <div className="signin-head">
          <h1 className="signin-title" id="passkey-title">
            No answer from coffre
          </h1>
          <p className="signin-lede">
            {stepUp ? 'Your session is still waiting for its passkey.' : 'Your sign-in is still waiting for its passkey.'} Try again in a moment.
          </p>
        </div>
        <button className="btn btn-primary" type="button" onClick={() => setAttempt((n) => n + 1)}>
          Try again
        </button>
      </section>
    );
  }
  if (step === 'none' || ended !== null) {
    return (
      <section className="card signin" aria-labelledby="passkey-title">
        <div className="signin-head">
          <h1 className="signin-title" id="passkey-title">
            Sign in again
          </h1>
          <p className="signin-lede">
            {ended ??
              (stepUp
                ? 'This session needs a passkey behind it, and coffre has none to ask you for here. Signing in again asks for one.'
                : 'This sign-in expired, or was finished in another tab. Start again: it takes a minute.')}
          </p>
        </div>
        <a className="btn btn-primary" href={again}>
          Sign in
        </a>
      </section>
    );
  }

  const enroll = step.purpose === 'enroll';

  async function answer(current: Step) {
    setBusy(true);
    setError(null);
    try {
      const answer = await sendPasskey<{ next?: unknown }>(
        unsent.current,
        async (left) => {
          // What is left of the step, not the five minutes the GET was answered with: the authenticator's timeout starts
          // at the call.
          const timeout = Math.min(left, current.options.timeout);
          const credential = current.purpose === 'enroll'
            ? await createCredential({ ...current.options, timeout })
            : await getCredential({ ...current.options, timeout });
          return JSON.stringify({ response: toJSON(credential), ...(current.state === undefined ? {} : { state: current.state }) });
        },
        (body) => fetch('/api/auth/passkey', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body }),
        { once: current.purpose === 'enroll' },
      );
      if (answer.kind === 'expired') {
        // The page sat open past the step's five minutes: ask coffre again, which has new options while the sign-in
        // waits, and says to sign in again once it does not.
        setError('This passkey request lapsed while the page was open. Press again for a new one.');
        setAttempt((n) => n + 1);
        return;
      }
      if (answer.kind === 'stale') {
        // Not reached: a refused new passkey asks for new options at once, below. Asked anyway, new options.
        setAttempt((n) => n + 1);
        return;
      }
      setUnanswered(answer.kind === 'unavailable');
      if (answer.kind === 'ok' && typeof answer.value.next === 'string') {
        // A full navigation: the new session cookie is the next page's.
        window.location.assign(answer.value.next);
        return;
      }
      if (answer.kind === 'landed') {
        // Signed in, the answer naming where to go cut off on the way: the new session's home. The page's own `next`
        // is the server's to hold to its origin (`safeNext`), so it is not followed here.
        window.location.assign('/');
        return;
      }
      if (answer.kind !== 'refused') {
        // No answer to go by: the sign-in still waits, and the next press sends the same answer again.
        setError(
          enroll
            ? 'coffre did not answer just now. Try again in a moment: it sends the passkey you just made, without asking for another.'
            : 'coffre did not answer just now. Try again in a moment.',
        );
      } else if (answer.code === 'passkey_failed') {
        setError(enroll ? 'That passkey could not be added. Try again, or another one.' : 'That passkey did not confirm it’s you. Try again, or another one.');
        // A new passkey's options are asked of the authenticator once (`sendPasskey`'s `once`): the next press's come
        // from coffre again, with a user handle of their own.
        if (enroll) setAttempt((n) => n + 1);
      } else {
        setEnded(signinErrorMessage(answer.code ?? 'state_mismatch') ?? signinErrorMessage('state_mismatch'));
      }
    } catch (thrown) {
      // Cancelled, timed out, a passkey this browser already holds for you, or an RP ID it refuses: said, and the person
      // decides what next.
      setError(authenticatorError(thrown, current.purpose === 'enroll' ? current.options.rp.id : current.options.rpId));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card signin" aria-labelledby="passkey-title">
      <div className="signin-head">
        <h1 className="signin-title" id="passkey-title">
          {enroll ? 'Add a passkey to finish signing in' : 'Confirm it’s you'}
        </h1>
        <p className="signin-lede">
          {enroll ? (
            <>
              Signing in as <span className="mono">{step.email}</span> takes a passkey here too: your fingerprint, face
              or device PIN, so a stolen account at your provider is not enough.
            </>
          ) : (
            <>
              Touch a passkey of <span className="mono">{step.email}</span>, with your fingerprint, face or device PIN.
            </>
          )}
        </p>
      </div>
      {/* An Owner's reset of every passkey of theirs, which is why this sign-in asks for a new one (section 3.7). */}
      {step.purpose === 'enroll' && step.reset != null && <ResetNotice reset={step.reset} />}
      <button className="btn btn-primary" type="button" disabled={busy} aria-busy={busy} onClick={() => void answer(step)}>
        {busy ? <Spinner /> : <Key size={14} />}
        {unanswered ? 'Try again' : enroll ? 'Add passkey' : 'Use passkey'}
      </button>
      {error !== null && (
        <div className="signin-error">
          <ErrorLine error={error} />
        </div>
      )}
      {!enroll && <p className="signin-lede">Lost your passkeys? An Owner can reset them.</p>}
    </section>
  );
}
