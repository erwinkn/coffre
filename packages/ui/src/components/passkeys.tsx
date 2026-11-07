import { useQuery, useQueryClient, useSuspenseQuery } from '@tanstack/react-query';
import { Fragment, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';

import { Key, Pencil, Plus, X } from './icons';
import { Card } from './page';
import { ResetNotice } from './reset-notice';
import { RowFailure, RowPending, rowClass } from './row-state';
import { ConfirmDialog, EmptyState, ErrorLine, Modal, Notice, Spinner, Timestamp, Toggletip } from './ui';
import { renamePasskey } from '../lib/changes';
import { failureMessage, memberRef, useCoffre } from '../lib/coffre';
import { authenticatorError, browserClock, deadlineOf, leftOf, passkeyAnswer, readClock, sendPasskey, type Deadline, type Unsent } from '../lib/passkey-answer';
import {
  addOutcome,
  addsInPlace,
  kindOf,
  nameProblem,
  promptsForPasskey,
  readAddOptions,
  readsForPrompt,
  removable,
  removalSentence,
  resetSentence,
  type Ends,
  type Passkey,
  type PasskeyStanding,
} from '../lib/passkeys';
import { usePreferences } from '../lib/preferences';
import { affects, queries, refresh } from '../lib/queries';
import { signinErrorMessage } from '../lib/signin-errors';
import { useChange, useChangeStatus } from '../lib/use-change';
import { useShell } from '../lib/use-shell';
import { createCredential, getCredential, toJSON, type CreationJSON, type RequestJSON } from '../lib/webauthn';

/**
 * The passkey pages (docs/design/passkeys.md, sections 3.3, 3.6 and 3.7): Account › Passkeys, its dialogs, the prompt
 * under `optional`, and an Owner's reset of someone else's.
 */

type Standing = NonNullable<PasskeyStanding>;

/** What a person's page says of their policy, above their passkeys. */
function policyLine(standing: Standing, count: number): string {
  if (standing.policy === 'off') {
    return 'Passkeys are off on this coffre: you sign in with your provider alone. Your passkeys are kept for when they are back on, and you may remove the ones you lost.';
  }
  if (count === 0) {
    return standing.policy === 'required'
      ? 'Signing in takes your provider and a touch of a passkey.'
      : 'Add one, and signing in will take your provider and a touch of it, so a stolen account at your provider is not enough.';
  }
  return 'Signing in takes your provider and a touch of one of these. Changing access, issuing credentials or removing a passkey asks for a touch within the last five minutes.';
}

/** Account › Passkeys: your own, with Rename and Remove on each, and Add a passkey. */
export function PasskeysCard({ email, standing }: { email: string; standing: Standing }) {
  const client = useCoffre();
  const member = memberRef('user', email);
  const { data } = useSuspenseQuery(queries.passkeys(client, member));
  const change = renamePasskey(client, member);
  const { status, dismiss } = useChangeStatus(change.list.queryKey);
  const [renaming, setRenaming] = useState<Passkey | null>(null);
  const [removing, setRemoving] = useState<Passkey | null>(null);
  const [adding, setAdding] = useState(false);
  if (!data.ok) return <ErrorLine error={data.error} />;
  const { passkeys, ends, reset, max } = data;
  const last = passkeys.length === 1;
  const mayRemove = removable(standing, passkeys.length);

  return (
    <>
      {reset !== null && passkeys.length === 0 && (
        <div className="report-notice">
          <ResetNotice reset={reset} />
        </div>
      )}
      <Card labelledBy="passkeys" title="Passkeys" description={policyLine(standing, passkeys.length)}>
        {passkeys.length === 0 ? (
          <EmptyState title="No passkey yet">
            A passkey is your fingerprint, face or device PIN, kept by your phone, your computer, a password manager or a
            security key.
          </EmptyState>
        ) : (
          <div className="dt-wrap">
            <table className="dt stacks stacks-inline">
              <thead>
                <tr>
                  <th>Passkey</th>
                  <th className="col-shrink">Kind</th>
                  <th className="col-shrink">Added (UTC)</th>
                  <th className="col-shrink">Last used</th>
                  <th className="col-actions">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {passkeys.map((passkey) => {
                  const state = status(passkey.id);
                  return (
                    <Fragment key={passkey.id}>
                      <tr className={rowClass(state)}>
                        <td>
                          <span className="cell-account">
                            <Key size={15} />
                            <span className="cell-stack">
                              <span>{passkey.name}</span>
                              {passkey.provider !== null && passkey.provider !== passkey.name && <small>{passkey.provider}</small>}
                            </span>
                          </span>
                        </td>
                        <td className="nowrap cell-muted" data-label="Kind">
                          {kindOf(passkey)}
                        </td>
                        <td className="nowrap" data-label="Added (UTC)">
                          <Timestamp iso={passkey.createdAt} />
                        </td>
                        <td className="nowrap cell-muted" data-label="Last used">
                          {passkey.lastUsedAt === null ? 'Never' : <Timestamp iso={passkey.lastUsedAt} display="relative" />}
                        </td>
                        <td className="col-actions">
                          {state.state === 'pending' ? (
                            <RowPending status={state} />
                          ) : (
                            <>
                              <button className="act" type="button" onClick={() => setRenaming(passkey)}>
                                <Pencil size={13} />
                                Rename
                              </button>
                              {mayRemove ? (
                                <button className="act" type="button" onClick={() => setRemoving(passkey)}>
                                  <X size={13} />
                                  Remove
                                </button>
                              ) : (
                                <Toggletip label="This coffre requires a passkey: add another before you remove your last." align="end">
                                  <button className="act" type="button" aria-label={`Why ${passkey.name} can't be removed`}>
                                    <X size={13} />
                                    Remove
                                  </button>
                                </Toggletip>
                              )}
                            </>
                          )}
                        </td>
                      </tr>
                      <RowFailure status={state} columns={5} onDismiss={() => state.state === 'failed' && dismiss(state.mutationId)} />
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <AddActions standing={standing} count={passkeys.length} max={max} onAdd={() => setAdding(true)} />

      <AddPasskeyDialog open={adding} onOpenChange={setAdding} member={member} />
      <RenamePasskeyDialog passkey={renaming} onOpenChange={(open) => !open && setRenaming(null)} member={member} />
      <RemovePasskeyDialog
        passkey={removing}
        ends={ends}
        last={last}
        policy={standing.policy}
        onOpenChange={(open) => !open && setRemoving(null)}
      />
    </>
  );
}

/** Under the list: Add a passkey in place, or, for a first one, a sign-in that adds it; or why neither. */
function AddActions({ standing, count, max, onAdd }: { standing: Standing; count: number; max: number; onAdd: () => void }) {
  if (standing.policy === 'off') return null;
  if (count >= max) {
    return (
      <div className="table-actions">
        <span className="hint">You hold {max} passkeys, the most a person may. Remove one to add another.</span>
      </div>
    );
  }
  if (addsInPlace(standing, count, max)) {
    return (
      <div className="table-actions">
        <button className="btn" type="button" onClick={onAdd}>
          <Plus size={14} />
          Add a passkey
        </button>
      </div>
    );
  }
  return (
    <div className="table-actions">
      <span className="hint">Your first passkey is added as you sign in again.</span>
      <FirstPasskeyLinks next="/account/passkeys" />
    </div>
  );
}

/**
 * A first passkey: sign in again with a provider, asking to add one (`?passkey=add`), and come back to `next`. Its
 * session is young enough to add a first passkey, which a stolen cookie rarely is (section 3.3).
 */
export function FirstPasskeyLinks({ next, primary = false }: { next: string; primary?: boolean }) {
  const { auth } = useShell();
  const providers = auth.signin?.providers ?? [];
  return (
    <>
      {providers.map((provider) => (
        <a
          key={provider.id}
          className={primary ? 'btn btn-primary' : 'btn'}
          href={`/auth/signin/${encodeURIComponent(provider.id)}?passkey=add&next=${encodeURIComponent(next)}`}
        >
          <Key size={14} />
          {providers.length === 1 ? 'Add a passkey' : `Add a passkey with ${provider.label}`}
        </a>
      ))}
    </>
  );
}

/** What `POST …/passkeys/options` answers: `create()`'s options, with excluded the ones you hold, and their state. */
type AddStep = { options: CreationJSON; state: string; ends: Deadline };

/**
 * Add another passkey, in place (section 3.6). The options are asked as the dialog opens, which may ask a touch first
 * (a fresh check: the session must have been confirmed within five minutes, `lib/fresh.ts`), so that the press reaches
 * the authenticator at once, inside its click. A `create()`'s options are asked of the authenticator once: after a
 * refusal, new options. An answer coffre did not answer is sent again as it is, never made again.
 */
function AddPasskeyDialog({ open, onOpenChange, member }: { open: boolean; onOpenChange: (open: boolean) => void; member: string }) {
  const client = useCoffre();
  const queryClient = useQueryClient();
  const [step, setStep] = useState<AddStep | 'unavailable' | { refused: string } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The answer coffre did not answer, sent again by the next press; and whether this step's options were used.
  const unsent = useRef<{ answer: { state: string; response: Record<string, unknown> } | null; asked: boolean }>({ answer: null, asked: false });

  useEffect(() => {
    if (!open) return;
    let current = true;
    setStep(null);
    unsent.current = { answer: null, asked: false };
    const sent = readClock(browserClock);
    // An unreadable 200 rejects too (`readAddOptions`), so that it ends in `unavailable`, with a retry.
    client.passkeys.options(member).then(readAddOptions).then(
      ({ options, state }) => {
        if (current) setStep({ options: options as CreationJSON, state, ends: deadlineOf(sent, options.timeout) });
      },
      (failure: unknown) => {
        if (current) setStep(addOutcome(failure) === 'unavailable' ? 'unavailable' : { refused: failureMessage(failure) });
      },
    );
    return () => {
      current = false;
    };
  }, [open, attempt, client, member]);

  useEffect(() => {
    if (!open) setError(null);
  }, [open]);

  async function added() {
    await refresh(queryClient, affects.passkeys(member));
    toast.success('Passkey added');
    onOpenChange(false);
  }

  async function press(current: AddStep) {
    setBusy(true);
    setError(null);
    try {
      let answer = unsent.current.answer;
      if (answer === null) {
        const left = leftOf(current.ends, browserClock);
        if (left === 0 || unsent.current.asked) {
          setError('This request lapsed while the dialog was open. Press again for a new one.');
          setAttempt((n) => n + 1);
          return;
        }
        unsent.current.asked = true;
        let credential: PublicKeyCredential;
        try {
          credential = await createCredential({ ...current.options, timeout: Math.min(left, current.options.timeout) });
        } catch (thrown) {
          // Ended at the options' deadline (the session's fresh window's end, at most): new options, asked of a session
          // fresh again, rather than a passkey coffre would refuse.
          if (thrown instanceof DOMException && thrown.name === 'TimeoutError') {
            setError(authenticatorError(thrown, current.options.rp.id));
            setAttempt((n) => n + 1);
            return;
          }
          throw thrown;
        }
        answer = { state: current.state, response: toJSON(credential) as Record<string, unknown> };
        unsent.current.answer = answer;
      }
      try {
        await client.passkeys.add(member, answer);
      } catch (failure) {
        const outcome = addOutcome(failure);
        if (outcome === 'unavailable') {
          setError('coffre did not answer just now. Try again: it sends the passkey you just made, without asking for another.');
          return;
        }
        unsent.current.answer = null;
        if (outcome === 'exists') {
          await added();
          return;
        }
        if (outcome === 'again') {
          setError('That passkey could not be added. Press again to try once more.');
          setAttempt((n) => n + 1);
          return;
        }
        setError(failureMessage(failure));
        return;
      }
      unsent.current.answer = null;
      await added();
    } catch (thrown) {
      setError(authenticatorError(thrown, current.options.rp.id));
    } finally {
      setBusy(false);
    }
  }

  const ready = step !== null && typeof step === 'object' && 'options' in step ? step : null;
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Add a passkey">
      <p className="dialog-body">
        Make a passkey on this device, a phone nearby, or a security key: your fingerprint, face or device PIN. It signs you
        in, as your others do.
      </p>
      {step === 'unavailable' && <ErrorLine error="coffre did not answer just now." />}
      {step !== null && typeof step === 'object' && 'refused' in step && <ErrorLine error={step.refused} />}
      <ErrorLine error={error} />
      <div className="dialog-actions">
        <button className="btn" type="button" onClick={() => onOpenChange(false)}>
          Cancel
        </button>
        {step === 'unavailable' || (step !== null && 'refused' in step) ? (
          <button className="btn btn-primary" type="button" onClick={() => setAttempt((n) => n + 1)}>
            Try again
          </button>
        ) : (
          <button className="btn btn-primary" type="button" disabled={ready === null || busy} aria-busy={ready === null || busy} onClick={() => ready !== null && void press(ready)}>
            {ready === null || busy ? <Spinner /> : <Key size={14} />}
            Add passkey
          </button>
        )}
      </div>
    </Modal>
  );
}

/** Rename a passkey: shown at once, as the server takes it, trimmed. */
function RenamePasskeyDialog({ passkey, onOpenChange, member }: { passkey: Passkey | null; onOpenChange: (open: boolean) => void; member: string }) {
  const rename = useChange(renamePasskey(useCoffre(), member));
  const [name, setName] = useState('');
  useEffect(() => {
    if (passkey !== null) setName(passkey.name);
  }, [passkey]);
  const problem = name === '' ? null : nameProblem(name);
  return (
    <Modal open={passkey !== null} onOpenChange={onOpenChange} title="Rename passkey">
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          if (passkey === null || nameProblem(name) !== null) return;
          rename({ id: passkey.id, name: name.trim() });
          onOpenChange(false);
        }}
      >
        <label className="field">
          <span className="label">Name</span>
          <input className="input" autoFocus value={name} maxLength={200} aria-invalid={problem !== null} onChange={(event) => setName(event.target.value)} />
          <span className={`hint${problem !== null ? ' edit-note-error' : ''}`}>{problem ?? 'Only you see it, to tell your passkeys apart.'}</span>
        </label>
        <div className="dialog-actions">
          <button className="btn" type="button" onClick={() => onOpenChange(false)}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" disabled={passkey === null || name.trim() === passkey.name || nameProblem(name) !== null}>
            Save
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** What the passkey door answers for a removal: a touch of a passkey you keep (or of the last, under `optional`), or none under `off`. */
type RemoveStep = { purpose: 'remove'; email: string; name: string; options: RequestJSON | null; state: string };

/** The door's refusals of a removal, in words. */
function removalRefusal(code: string | undefined): string {
  if (code === 'last_passkey') return 'This coffre requires a passkey, and this is your last: add another before you remove it.';
  if (code === 'tampered') return 'Your passkeys failed coffre’s integrity check: they were changed outside coffre. Ask whoever runs coffre.';
  if (code === 'state_mismatch') return 'Your session changed meanwhile, or this passkey was removed already. Reload the page.';
  return signinErrorMessage(code ?? 'session_ended') ?? 'The passkey was not removed.';
}

/**
 * Remove one of your passkeys (section 3.6), through the passkey page's door, as a step-up goes: it replaces this
 * browser's session, which a page's API call cannot. The touch is of a passkey you keep, so the new session names one
 * still live; your last, under `optional`, is touched itself, and the new session names none. Everything else you are
 * signed in with ends, which the dialog counts.
 */
function RemovePasskeyDialog({
  passkey,
  ends,
  last,
  policy,
  onOpenChange,
}: {
  passkey: Passkey | null;
  ends: Ends;
  last: boolean;
  policy: Standing['policy'];
  onOpenChange: (open: boolean) => void;
}) {
  const [step, setStep] = useState<RemoveStep | 'unavailable' | { refused: string | undefined } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unsent = useRef<Unsent>({ body: null, asked: false });
  const id = passkey?.id ?? null;

  useEffect(() => {
    if (id === null) return;
    let current = true;
    setStep(null);
    setError(null);
    const fresh: Unsent = { body: null, asked: false };
    unsent.current = fresh;
    const sent = readClock(browserClock);
    void passkeyAnswer<RemoveStep>(fetch(`/api/auth/passkey?remove=${encodeURIComponent(id)}`, { credentials: 'same-origin' })).then((answer) => {
      if (!current) return;
      if (answer.kind === 'ok' && answer.value.options !== null) fresh.ends = deadlineOf(sent, answer.value.options.timeout);
      setStep(answer.kind === 'ok' ? answer.value : answer.kind === 'refused' ? { refused: answer.code } : 'unavailable');
    });
    return () => {
      current = false;
    };
  }, [id, attempt]);

  async function press(current: RemoveStep) {
    setBusy(true);
    setError(null);
    try {
      const answer = await sendPasskey<{ next?: unknown }>(
        unsent.current,
        async (left) => {
          if (current.options === null) return JSON.stringify({ state: current.state });
          const credential = await getCredential({ ...current.options, timeout: Math.min(left, current.options.timeout) });
          return JSON.stringify({ state: current.state, response: toJSON(credential) });
        },
        (body) => fetch('/api/auth/passkey', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body }),
      );
      if (answer.kind === 'ok') {
        // A full navigation: the response set this browser's new session, and every page read before it is the old one's.
        window.location.assign(typeof answer.value.next === 'string' ? answer.value.next : '/account/passkeys');
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
        setStep({ refused: answer.code });
      }
    } catch (thrown) {
      setError(authenticatorError(thrown, current.options?.rpId ?? ''));
    } finally {
      setBusy(false);
    }
  }

  const ready = step !== null && typeof step === 'object' && 'purpose' in step ? step : null;
  const refused = step !== null && typeof step === 'object' && 'refused' in step ? step : null;
  // Under `optional`, the last one is touched itself, and the person goes back to their provider alone.
  const lastOptional = last && policy === 'optional';
  return (
    <Modal open={passkey !== null} onOpenChange={onOpenChange} title={passkey === null ? 'Remove passkey' : `Remove ${passkey.name}?`}>
      {passkey !== null && (
        <>
          <p className="dialog-body">{removalSentence(passkey.name, ends, lastOptional)}</p>
          {refused === null && (
            <p className="dialog-body">
              {policy === 'off'
                ? 'Passkeys are off here, so removing one asks no touch.'
                : lastOptional
                  ? 'Touch this passkey to confirm it’s you.'
                  : 'Touch a passkey you keep to confirm it’s you.'}
            </p>
          )}
          {step === 'unavailable' && <ErrorLine error="coffre did not answer just now." />}
          {refused !== null && <ErrorLine error={removalRefusal(refused.refused)} />}
          <ErrorLine error={error} />
          <div className="dialog-actions">
            <button className="btn" type="button" onClick={() => onOpenChange(false)}>
              Cancel
            </button>
            {step === 'unavailable' ? (
              <button className="btn btn-primary" type="button" onClick={() => setAttempt((n) => n + 1)}>
                Try again
              </button>
            ) : refused === null ? (
              <button className="btn btn-danger" type="button" disabled={ready === null || busy} aria-busy={ready === null || busy} onClick={() => ready !== null && void press(ready)}>
                {ready === null || busy ? <Spinner /> : policy === 'off' ? <X size={14} /> : <Key size={14} />}
                Remove passkey
              </button>
            ) : null}
          </div>
        </>
      )}
    </Modal>
  );
}

/**
 * The Projects page's prompt, under `optional`, to a person holding no passkey (section 3.3): Add a passkey, which
 * signs in again to add it, or Not now, which puts it off in this browser for 30 days. An Owner's reset of theirs is
 * said first, and shows it again after a Not now pressed before the reset (review r1 of #539).
 */
export function PasskeyPrompt() {
  const { passkeys, principal, auth } = useShell();
  const { passkeyLater, putPasskeyOff } = usePreferences();
  const reads = principal?.type === 'user' && readsForPrompt(passkeys);
  const member = principal?.type === 'user' ? memberRef('user', principal.id) : '';
  // The loader read it (`projects`, options.ts), so the server renders the reset it says, and the browser asks nothing.
  const { data } = useQuery({ ...queries.passkeys(useCoffre(), member), enabled: reads });
  const reset = data?.ok === true ? data.reset : null;
  if (!reads || !promptsForPasskey(passkeys, passkeyLater, reset)) return null;
  const providers = auth.signin?.providers ?? [];
  const provider = providers.length === 1 ? providers[0]!.label : 'your provider';
  return (
    <div className="report-notice">
      <Notice tone="info">
        {reset !== null && (
          <p>
            <span className="mono">{reset.by}</span> reset your passkeys on <Timestamp iso={reset.at} />.
          </p>
        )}
        <p>
          <strong>Add a passkey.</strong> Signing in will then take {provider} and a touch of your passkey, so a stolen{' '}
          {providers.length === 1 ? `${provider} account` : 'account there'} is not enough.
        </p>
        <div className="notice-actions">
          <FirstPasskeyLinks next="/projects" primary />
          <button className="btn" type="button" onClick={putPasskeyOff}>
            Not now
          </button>
        </div>
      </Notice>
    </div>
  );
}

/**
 * An Owner's reset of someone else's passkeys, every one (section 3.7), from their ⋯ menu: what it removes and ends,
 * read as the dialog opens, then a touch of the Owner's own (the fresh check, which the API asks).
 */
export function ResetPasskeysDialog({ person, open, onOpenChange }: { person: string; open: boolean; onOpenChange: (open: boolean) => void }) {
  const client = useCoffre();
  const queryClient = useQueryClient();
  const member = memberRef('user', person);
  const { data, isPending } = useQuery({ ...queries.passkeys(client, member), enabled: open });
  const list = data?.ok === true ? data : null;
  const none = list !== null && list.passkeys.length === 0;
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={
        <>
          Reset the passkeys of <span className="mono">{person}</span>?
        </>
      }
      body={
        isPending
          ? 'Reading their passkeys…'
          : data?.ok === false
            ? data.error
            : none
              ? `${person} holds no passkey: there is nothing to reset.`
              : `${resetSentence(person, list!.passkeys.length, list!.ends)} Their next sign-in asks for a new one, or, while passkeys are optional, takes their provider alone.`
      }
      confirmLabel="Reset passkeys"
      confirmDisabled={list === null || none}
      onConfirm={() => {
        void client.passkeys.reset(member).then(
          async (result) => {
            await refresh(queryClient, affects.passkeys(member));
            // A 200 whose body did not arrive whole is null (the client's `send`): reset all the same.
            toast.success(typeof result?.reset === 'number' ? `Reset ${person}’s passkeys: ${result.reset} removed` : `Reset ${person}’s passkeys`);
          },
          (failure: unknown) => toast.error(`Not reset. ${failureMessage(failure)}`),
        );
      }}
    />
  );
}
