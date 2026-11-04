import { useEffect, useMemo, useState } from 'react';

import { ErrorLine, Spinner } from '../components/ui';
import { Key } from '../components/icons';
import { pageRoute } from '../lib/page-route';
import { browserClock, lifetime, memoryKeeper, passkeyAnswer, sendPasskey, storedKeeper, type KeptStorage, type Lifetime } from '../lib/passkey-answer';
import { signinErrorMessage } from '../lib/signin-errors';
import type { passkey } from '../options';

const Route = pageRoute<typeof passkey>();

/** What `GET /api/auth/passkey` asks the browser for: a touch (`get()`), or a new passkey (`create()`), in WebAuthn's JSON form. */
type Step =
  | { purpose: 'signin' | 'step-up'; email: string; options: RequestJSON; state?: string }
  | { purpose: 'enroll'; email: string; options: CreationJSON };

/** A step, and when it ends, timed from its GET (`Lifetime`). */
type Timed = Step & { life: Lifetime };

type Descriptor = { type: 'public-key'; id: string; transports?: string[] };
type RequestJSON = { challenge: string; rpId: string; allowCredentials: Descriptor[]; userVerification: UserVerificationRequirement; timeout: number };
type CreationJSON = {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  authenticatorSelection: AuthenticatorSelectionCriteria;
  attestation: AttestationConveyancePreference;
  excludeCredentials: Descriptor[];
  timeout: number;
};

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
  const [step, setStep] = useState<Timed | 'none' | 'unavailable' | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Why the step ended without a session, when it did: said above the way back in.
  const [ended, setEnded] = useState<string | null>(null);
  // An answer coffre did not answer: the next press sends it again, never asks for another (`sendPasskey`).
  const [unanswered, setUnanswered] = useState(false);
  // What the step holds between presses: an enrollment's in `localStorage`, shared by its tabs and reloads; a touch's here.
  // Either reads the step ended once its lifetime is over, a page restored from the back-forward cache included.
  const keeper = useMemo(
    () => (step === null || typeof step === 'string' ? null : step.purpose === 'enroll' ? storedKeeper(browserStorage(), step.options.challenge, step.life) : memoryKeeper(step.life)),
    [step],
  );

  useEffect(() => {
    const query = stepUp ? `?step-up=1${search.next === undefined ? '' : `&next=${encodeURIComponent(search.next)}`}` : '';
    let current = true;
    setStep(null);
    setUnanswered(false);
    const sent = browserClock();
    void passkeyAnswer<Step>(fetch(`/api/auth/passkey${query}`, { credentials: 'same-origin' })).then((answer) => {
      if (!current) return;
      setStep(answer.kind === 'ok' ? { ...answer.value, life: lifetime(sent, browserClock(), answer.value.options.timeout) } : answer.kind === 'refused' ? 'none' : 'unavailable');
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

  async function answer(current: Timed) {
    if (keeper === null) return;
    setBusy(true);
    setError(null);
    try {
      const answer = await sendPasskey<{ next?: unknown }>(
        keeper,
        async () => {
          const credential = current.purpose === 'enroll'
            ? await navigator.credentials.create({ publicKey: creationOptions(current.options) })
            : await navigator.credentials.get({ publicKey: requestOptions(current.options) });
          if (credential === null) throw new DOMException('no passkey answered', 'NotAllowedError');
          return JSON.stringify({ response: toJSON(credential as PublicKeyCredential), ...('state' in current ? { state: current.state } : {}) });
        },
        (body) => fetch('/api/auth/passkey', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body }),
      );
      setUnanswered(answer.kind === 'unavailable');
      if (answer.kind === 'ok' && typeof answer.value.next === 'string') {
        // A full navigation: the new session cookie is the next page's.
        window.location.assign(answer.value.next);
        return;
      }
      if (answer.kind === 'elsewhere') {
        // Another tab of this sign-in is making its passkey: a second `create()` could replace that one (review r8 of #500).
        setError('Another tab of this sign-in is adding your passkey. Finish there, or try again here in a moment.');
      } else if (answer.kind !== 'refused') {
        // No answer to go by: the sign-in still waits, and the next press sends the same answer again.
        setError(
          enroll
            ? 'coffre did not answer just now. Try again in a moment: it sends the passkey you just made, without asking for another.'
            : 'coffre did not answer just now. Try again in a moment.',
        );
      } else if (answer.code === 'passkey_failed') {
        setError(enroll ? 'That passkey could not be added. Try again, or another one.' : 'That passkey did not confirm it’s you. Try again, or another one.');
      } else {
        setEnded(signinErrorMessage(answer.code ?? 'state_mismatch') ?? signinErrorMessage('state_mismatch'));
      }
    } catch (thrown) {
      // Cancelled, timed out, or a passkey this browser already holds for you: the person decides what next.
      setError(
        thrown instanceof DOMException && thrown.name === 'InvalidStateError'
          ? 'This device already holds a passkey of yours here. Use another device, or sign in with that one.'
          : thrown instanceof DOMException && thrown.name === 'NotAllowedError'
            ? 'No passkey answered. Try again when you’re ready.'
            : 'Your browser could not use a passkey here.',
      );
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

/** `localStorage`, or null where the browser keeps none for this page or refuses to say. */
function browserStorage(): KeptStorage | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

const bytes = (value: string): ArrayBuffer => {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out.buffer;
};

const text = (buffer: ArrayBuffer | null): string | null => {
  if (buffer === null) return null;
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const descriptors = (list: Descriptor[]): PublicKeyCredentialDescriptor[] =>
  list.map(({ type, id, transports }) => ({ type, id: bytes(id), ...(transports === undefined ? {} : { transports: transports as AuthenticatorTransport[] }) }));

/** WebAuthn's JSON form as `get()` takes it: `parseRequestOptionsFromJSON`, written out for the browsers that lack it. */
function requestOptions(options: RequestJSON): PublicKeyCredentialRequestOptions {
  return { ...options, challenge: bytes(options.challenge), allowCredentials: descriptors(options.allowCredentials) };
}

/** And as `create()` takes it. */
function creationOptions(options: CreationJSON): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: bytes(options.challenge),
    user: { ...options.user, id: bytes(options.user.id) },
    excludeCredentials: descriptors(options.excludeCredentials),
  };
}

/** The credential as `toJSON()` gives it, written out for the browsers that lack it: what the verifier reads. */
function toJSON(credential: PublicKeyCredential): unknown {
  const response = credential.response;
  const common = {
    id: credential.id,
    rawId: text(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if ('attestationObject' in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    return {
      ...common,
      response: { clientDataJSON: text(attestation.clientDataJSON), attestationObject: text(attestation.attestationObject), transports: attestation.getTransports?.() ?? [] },
    };
  }
  const assertion = response as AuthenticatorAssertionResponse;
  return {
    ...common,
    response: {
      clientDataJSON: text(assertion.clientDataJSON),
      authenticatorData: text(assertion.authenticatorData),
      signature: text(assertion.signature),
      userHandle: text(assertion.userHandle),
    },
  };
}
