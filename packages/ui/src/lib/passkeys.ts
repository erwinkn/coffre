import { CoffreError, type RouteOutput } from '@coffre/client';

/**
 * What the passkey pages say, apart from the pages (docs/design/passkeys.md, sections 3.3, 3.6 and 3.7): what removing
 * one or resetting someone's ends, in words, and whether the prompt to add a first one shows.
 */

export type PasskeyList = RouteOutput<'GET /members/:member/passkeys'>;
export type Passkey = PasskeyList['passkeys'][number];
export type Ends = PasskeyList['ends'];

/** The deployment's policy and whether you hold one, as `/me` says them; null without coffre's own sign-in. */
export type PasskeyStanding = { policy: 'off' | 'optional' | 'required'; enrolled: boolean; confirmedUntil: string | null } | null;

const plural = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;

/** "a, b and c". */
function listed(parts: string[]): string {
  return parts.length < 2 ? (parts[0] ?? '') : `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}`;
}

/** What `ends` counts, each kind it has any of: "3 sessions, 1 personal token and 2 handles". Empty for none. */
export function endsList(ends: Ends): string {
  return listed(
    [
      ends.sessions > 0 ? plural(ends.sessions, 'session') : null,
      ends.tokens > 0 ? plural(ends.tokens, 'personal token') : null,
      ends.handles > 0 ? plural(ends.handles, 'handle') : null,
      ends.apps > 0 ? plural(ends.apps, 'connected app') : null,
    ].filter((part): part is string => part !== null),
  );
}

/**
 * What removing one of your passkeys does, for its dialog: "Removing YubiKey 5C signs you out of 3 other sessions and
 * ends 1 personal token." The session asking is left out of `ends`: it is replaced, not ended. Under `optional`, the
 * last one also puts the person back on their provider alone.
 */
export function removalSentence(name: string, ends: Ends, last: boolean): string {
  const signedOut = ends.sessions > 0 ? `signs you out of ${plural(ends.sessions, 'other session')}` : null;
  const rest = endsList({ ...ends, sessions: 0 });
  const effects = [signedOut, rest === '' ? null : `ends ${rest}`].filter((part): part is string => part !== null);
  const first = effects.length === 0 ? `Removing ${name} signs you out nowhere else: this browser is the only place you are signed in.` : `Removing ${name} ${effects.join(' and ')}.`;
  return last ? `${first} It is your last passkey: you will sign in with your provider alone, until you add another.` : first;
}

/**
 * What an Owner's reset does, for its dialog (section 3.7): "Removes bob@acme.example's 2 passkeys. Everything they
 * are signed in with ends: 3 sessions, 1 personal token, 2 handles and 1 connected app."
 */
export function resetSentence(person: string, count: number, ends: Ends): string {
  const what = endsList(ends);
  return `Removes ${person}’s ${plural(count, 'passkey')}. ${what === '' ? 'They are signed in nowhere right now.' : `Everything they are signed in with ends: ${what}.`}`;
}

/**
 * Whether the Projects page reads your passkeys, for an Owner's reset of them it says (section 3.7): a person under
 * `optional` holding none, whom the prompt may ask. Its loader reads them too, so the page renders with it.
 */
export function readsForPrompt(standing: PasskeyStanding): boolean {
  return standing !== null && standing.policy === 'optional' && !standing.enrolled;
}

/**
 * Whether the Projects page asks you to add a passkey (sections 3.3 and 3.7): a person under `optional` holding none,
 * who has not put it off in this browser (Not now, `later`, for 30 days), or whose passkeys an Owner reset since: the
 * reset is news Not now did not see, and the prompt says it.
 */
export function promptsForPasskey(standing: PasskeyStanding, later: number | null, reset: { at: string } | null): boolean {
  if (!readsForPrompt(standing)) return false;
  return later === null || (reset !== null && Date.parse(reset.at) > later);
}

/** Whether Account › Passkeys adds one in place: from a passkey you hold, under a policy that has them, below the cap. */
export function addsInPlace(standing: PasskeyStanding, count: number, max: number): boolean {
  return standing !== null && standing.policy !== 'off' && standing.enrolled && count < max;
}

/** Whether a passkey you hold may be removed here: under `required`, never your last (add another first). */
export function removable(standing: PasskeyStanding, count: number): boolean {
  return standing !== null && !(standing.policy === 'required' && count <= 1);
}

/** A passkey's kind, from the authenticator's backup flags: it syncs across your devices, or lives on this one alone. */
export function kindOf(passkey: Pick<Passkey, 'synced'>): string {
  return passkey.synced ? 'Synced' : 'This device only';
}

/**
 * A name a passkey may take, as the server holds it (`passkeyLabel`, `api/routes.ts`): trimmed, one to 64 UTF-16 code
 * units, as zod counts them, and no control character (`\p{Cc}`).
 */
export function nameProblem(name: string): string | null {
  const trimmed = name.trim();
  if (trimmed.length === 0) return 'Give it a name.';
  if (trimmed.length > 64) return 'At most 64 characters.';
  if (/\p{Cc}/u.test(trimmed)) return 'No control characters.';
  return null;
}

/**
 * What a failed add means for its dialog (`POST /members/:member/passkeys`):
 * - `unavailable`: no answer to go by (the network, a 5xx, a 408 or 429, a 409 `changed`, a 401 or 409 unread). The server may have added
 *   it, so the next press sends the same answer again, never asks the authenticator for another: a second `create()`
 *   could replace on the device a passkey coffre holds (as `sendPasskey`, review r7 of #500).
 * - `exists`: that answer was added already, as when the first send's answer was lost. Done.
 * - `again`: the options lapsed, the session changed, the person's passkeys changed, or the authenticator's answer did
 *   not verify: new options, a user handle of their own, and a new `create()`.
 * - `refused`: anything else, said in the server's words (`failureMessage`).
 */
export type AddOutcome = 'unavailable' | 'exists' | 'again' | 'refused';

export function addOutcome(error: unknown): AddOutcome {
  if (!(error instanceof CoffreError)) return 'unavailable';
  if (error.status >= 500 || error.status === 408 || error.status === 429) return 'unavailable';
  if (error.status === 409 && error.reason === 'changed') return 'unavailable';
  // A 401 or 409 whose body did not arrive whole (the client's `http_error`): those are the statuses of `passkey_exists`
  // and of a refusal that keeps the answer, so it is not read as a refusal (as `passkeyAnswer`, review r2 of #539).
  if ((error.status === 401 || error.status === 409) && error.code === 'http_error') return 'unavailable';
  if (error.reason === 'passkey_exists') return 'exists';
  if (error.reason === 'state_mismatch' || error.code === 'touch_failed') return 'again';
  return 'refused';
}
