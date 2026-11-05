// The passkey ceremonies' own pieces (docs/design/passkeys.md, sections 3 and 7): the sealed state a challenge travels
// in, the options a browser's `create()` and `get()` take, and the response's credential ID, read before the verifier
// runs. What they decide, and every row they write, is the sign-in service's (signin.ts).
import { randomBytes } from 'node:crypto';

import { base64urlLength, deriveKey, MAX_CREDENTIAL_ID, PASSKEY_ALGORITHMS, seal, unseal, USER_VERIFICATION, type PasskeysConfig } from '@coffre/core/identity';

/** How long a challenge, and the state it travels in, lasts: five minutes, as the design Erwin approved sets (sections 3.1 and 7.3). */
export const CEREMONY_TTL_SECONDS = 5 * 60;

/**
 * What is left of a ceremony's lifetime, ms, which its options give the browser as `timeout`: the state lasts
 * `CEREMONY_TTL_SECONDS` from its challenge (`issuedAt`, which `seal` dates it from), so `create()` and `get()` wait no
 * longer than it can be answered, and the page knows when its step ends (`Lifetime`, `@coffre/ui`'s passkey-answer.ts):
 * a page left open past it asks the authenticator for nothing (review r9 of #500).
 */
export function remainingMs(state: { issuedAt: number }, now = Date.now()): number {
  return Math.max(0, state.issuedAt + CEREMONY_TTL_SECONDS * 1000 - now);
}

/**
 * Why a sealed state was made, each opened by its own key (section 7.2, step 1): `signin` and `enroll` ride in the
 * sign-in's cookie, after the provider; `step-up` in the page's JSON, bound to the session it replaces; `create`, in the
 * page's JSON too, the user handle one `create()` of an enrollment was given.
 */
export type CeremonyPurpose = 'signin' | 'enroll' | 'step-up' | 'create';

/**
 * A sign-in that passed the provider and waits for its passkey (section 3.1), sealed in `__Host-coffre_passkey`: what
 * the provider vouched for and nothing coffre decided, so that someone who stops here leaves no row behind.
 */
export type PendingFactor = {
  purpose: 'signin' | 'enroll';
  /**
   * What the provider vouched for: the account, the issuer that verified it (`issuerHash`, held to the configured one
   * at the post), and the one verified email the sign-in goes by, the provider's first for a bound account, the one that
   * matched an invitation for a first sign-in. Never the whole list: the cookie stays small.
   */
  account: { provider: string; issuerHash: string; subject: string; email: string | null; name: string | null };
  /** `user:<email>`. */
  principal: string;
  /**
   * The membership the step is for: their row's generation when the callback read it, active or not (a removed member
   * comes back at the one their removal left), and 0, a first admission's, for an Owner the deployment names whom the
   * vault holds no row of yet. The post holds the vault's answer to it, so a removal and readmission meanwhile, which
   * moves it, refuses (review r3 of #500).
   */
  generation: number;
  /** Where to land: a path on this origin. */
  next: string;
  /** 32 random bytes, base64url. */
  challenge: string;
  /** When it was made, ms: the replay mark an assertion moves past (section 7.3). */
  issuedAt: number;
  /** `enroll`: how many passkey rows the person had, removed ones included, which the post holds still (section 3.2). */
  passkeysEver: number | null;
};

/** A step-up (section 6.2): a touch for the session the browser came in on, which it replaces, bound to it. */
export type StepUpState = {
  purpose: 'step-up';
  credentialId: string;
  principal: string;
  generation: number;
  next: string;
  challenge: string;
  issuedAt: number;
};

/**
 * The user handle one `create()` of an enrollment was given (section 3.2): drawn afresh for each GET of its options, so
 * that no two `create()` calls, from two tabs, a reload, or a page whose answer was lost, ever share one. An
 * authenticator keeps one discoverable credential per (RP ID, user handle) and replaces it on a second `create()` with
 * the same handle, so a shared one could replace a passkey coffre had already stored with one it refuses, and lock its
 * person out (reviews r7 to r12 of #500; D173). Sealed in the GET's answer, sent back with the POST, and bound to the
 * enrollment's challenge, it lasts as long as the enrollment does.
 */
export type CreateState = {
  purpose: 'create';
  challenge: string;
  userHandle: string;
  issuedAt: number;
};

type Sealed = PendingFactor | StepUpState | CreateState;

/** Each purpose's key, from the chain key, so that one purpose's state never opens as another's. */
export class CeremonyStates {
  readonly #keys: Record<CeremonyPurpose, Buffer>;

  constructor(chainKey: Buffer) {
    this.#keys = {
      signin: deriveKey(chainKey, 'passkey-state/signin/v1'),
      enroll: deriveKey(chainKey, 'passkey-state/enroll/v1'),
      'step-up': deriveKey(chainKey, 'passkey-state/step-up/v1'),
      create: deriveKey(chainKey, 'passkey-state/create/v1'),
    };
  }

  /** The state, sealed, prefixed by its purpose, which picks the key that opens it; it lasts from its challenge. */
  seal(state: Sealed): string {
    return `${state.purpose}.${seal(this.#keys[state.purpose], state, CEREMONY_TTL_SECONDS, state.issuedAt)}`;
  }

  /** The state, if it opens under the key its prefix names, is that purpose's, and is unexpired; null otherwise. */
  open<P extends CeremonyPurpose>(value: string | null, purposes: readonly P[]): Extract<Sealed, { purpose: P }> | null {
    if (value === null) return null;
    const dot = value.indexOf('.');
    const purpose = value.slice(0, dot) as P;
    if (dot < 0 || !purposes.includes(purpose)) return null;
    const state = unseal<Sealed>(this.#keys[purpose], value.slice(dot + 1));
    return state !== null && state.purpose === purpose ? (state as Extract<Sealed, { purpose: P }>) : null;
  }
}

/** A new challenge, and when it was made. */
export function challenge(): { challenge: string; issuedAt: number } {
  return { challenge: randomBytes(32).toString('base64url'), issuedAt: Date.now() };
}

/** A new WebAuthn user handle (section 3.2): 16 random bytes, which say nothing of the person, one per `create()`. */
export function userHandle(): string {
  return randomBytes(16).toString('base64url');
}

/** What `navigator.credentials.get()` takes, in WebAuthn's JSON form (`parseRequestOptionsFromJSON`). */
export type RequestOptionsJSON = {
  challenge: string;
  rpId: string;
  allowCredentials: { type: 'public-key'; id: string; transports?: string[] }[];
  userVerification: typeof USER_VERIFICATION;
  timeout: number;
};

/** What `navigator.credentials.create()` takes, in WebAuthn's JSON form (`parseCreationOptionsFromJSON`). */
export type CreationOptionsJSON = {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  authenticatorSelection: { residentKey: 'preferred'; userVerification: typeof USER_VERIFICATION };
  attestation: 'none';
  excludeCredentials: { type: 'public-key'; id: string; transports?: string[] }[];
  timeout: number;
};

/** A passkey as a ceremony names it to the browser: its credential ID, and how it said it can be reached. */
export type OfferedPasskey = { credentialId: Buffer; transports: string };

function descriptor(passkey: OfferedPasskey) {
  const transports = transportsOf(passkey.transports);
  return { type: 'public-key' as const, id: Buffer.from(passkey.credentialId).toString('base64url'), ...(transports.length === 0 ? {} : { transports }) };
}

/** The transports a row stores, as JSON: strings only, and none for anything else. */
function transportsOf(stored: string): string[] {
  try {
    const parsed: unknown = JSON.parse(stored);
    return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === 'string') : [];
  } catch {
    return [];
  }
}

/** A touch of one of these passkeys, user verification required (sections 3.1 and 7.4). */
export function requestOptions(config: PasskeysConfig, state: { challenge: string; issuedAt: number }, passkeys: readonly OfferedPasskey[]): RequestOptionsJSON {
  return { challenge: state.challenge, rpId: config.rpId, allowCredentials: passkeys.map(descriptor), userVerification: USER_VERIFICATION, timeout: remainingMs(state) };
}

/** A new passkey for the person, of the three algorithms the verifier takes, attestation none (section 3.2). */
export function creationOptions(
  config: PasskeysConfig,
  state: { challenge: string; userHandle: string; issuedAt: number },
  person: { email: string; name: string | null; site: string },
  existing: readonly OfferedPasskey[],
): CreationOptionsJSON {
  return {
    rp: { id: config.rpId, name: person.site },
    user: { id: state.userHandle, name: person.email, displayName: person.name ?? person.email },
    challenge: state.challenge,
    pubKeyCredParams: PASSKEY_ALGORITHMS.map((alg) => ({ type: 'public-key' as const, alg })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: USER_VERIFICATION },
    attestation: 'none',
    excludeCredentials: existing.map(descriptor),
    timeout: remainingMs(state),
  };
}

/**
 * The credential ID a response names, raw, read before the verifier runs, to find the passkey it checks the response
 * against; null when there is none to read. The verifier checks the rest, `id` against `rawId` included.
 */
export function responseCredentialId(response: unknown): Buffer | null {
  const rawId = (response as { rawId?: unknown } | null)?.rawId;
  if (typeof rawId !== 'string' || rawId.length === 0 || rawId.length > base64urlLength(MAX_CREDENTIAL_ID) || !/^[A-Za-z0-9_-]+$/.test(rawId)) return null;
  return Buffer.from(rawId, 'base64url');
}
