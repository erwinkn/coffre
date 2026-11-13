import { randomUUID } from 'node:crypto';

import { isCredentialScope, scopeWithReads, sealedSessionScope, type CredentialScope } from '@coffre/core/access';
import {
  EXCHANGED_CREDENTIAL_MS,
  SESSION_MS,
  addressWithin,
  BindingInvalid,
  canonicalClaims,
  checkBinding,
  checkFetchUrl,
  checkPolicy,
  CLOCK_TOLERANCE_SECONDS,
  decodeWorkloadToken,
  differingClaims,
  generateToken,
  GitHubAppUnavailable,
  GITLAB_ISSUER,
  hashToken,
  isBearerProfile,
  issuedRefusal,
  keySummaries,
  KeysInvalid,
  MAX_BINDINGS,
  MAX_TOKEN_AGE_SECONDS,
  OIDC_PROFILES,
  POLICY_DEFAULTS,
  runClaims,
  soleAudience,
  UPLOADED_KEYS,
  POLICY_FIELDS,
  policyText,
  REPEATING_PROFILES,
  tokenHint,
  uploadedKeys,
  verifyWorkloadToken,
  WorkloadTokenRefused,
  type BindingClaims,
  type BindingPolicy,
  type DecodedToken,
  type GitHubAppRepositories,
  type JSONWebKeySet,
  type KeySummary,
  type UploadedKeys,
  type WorkloadProfile,
  type WorkloadsConfig,
} from '@coffre/core/identity';
import { shownMember } from '@coffre/core/schemas';
import { type Access, type ChangeBindingsInput, type EndedBinding, type SignInCredential, type SignInInput, type SignInOutcome, type SignInRefusal, type Vault } from '@coffre/core/vault';
import type { Database, Queryable, Transaction } from '@coffre/db';
import { KeyRetired } from '@coffre/db/log';
import { serviceBindings, type credentials } from '@coffre/db/schema';

import { issuedBy } from '../auth-rows.ts';
import { appLogKey, eventOf, noteEvent, type AuditEntry } from '../db/audit.ts';
import {
  bindingRow,
  bindingsNow,
  issuedCredentials,
  issuedSoonest,
  credentialRows,
  liveIssued,
  closedBindings,
  bindingEnded,
  consumeToken,
  exchangeCandidates,
  liveBindings,
  memberStanding,
  places,
  secretHeads,
  sensitiveVersions,
  standingBinding,
  tokenConsumed,
  update,
  type BindingRow,
  type CredentialRow,
  type PlaceRow,
} from '../db/queries.ts';
import { databaseNow, insertSession, keyNames, renewSession, signedSession, workloadCandidates } from '../db/workloads.ts';
import { RemovalUnderWay, type RemovalBudget } from '../removal.ts';
import { logged } from '../logged.ts';
import { newestVaultSeq } from '@coffre/db/log';

/** Who goes on with a removal a request left under way: the scheduled run (`resumeRemovals`). */
const SCHEDULE_ACTOR = 'system:schedule';
import { awsProof } from '../workloads/aws.ts';
import { discoverKeys, DiscoveryFailed } from '../workloads/discovery.ts';
import { expectedAudiences, PROFILE_RULES } from '../workloads/profiles.ts';
import { IssuerUnavailable, verifyWithKeys } from '../workloads/keys.ts';
import { FetchRefused, type WorkloadTransport } from '../workloads/transport.ts';
import type { Caller } from './caller.ts';
import { currentReferences } from './references.ts';
import { endedBinding, madeBinding, sealedBinding, vaultBinds, vaultSweeps, AppChanges, credentialChange, keeps015, ObjectMoved, retrying, vaultMakesCredentials, type CredentialsVault } from './changes.ts';
import type { Asker, SigninService } from './signin.ts';
import { allowed, audited, denied, entryOf, POLICY_CHANGED, Refusal, vaultDecided, withRefusals, type ApiContext } from './context.ts';
import {
  ACCESS_CHANGED,
  inheritedScope,
  issuedScope,
  issuerNow,
  managedAccount,
  notManager,
  parseScope,
  readScope,
  scopeByPath,
  unsealedScope,
  serviceSettingFor,
  setsUp,
  storedScope,
  type ScopeByPath,
} from './services.ts';
import { ApiError, badRequest, conflict, forbidden, notFound } from './errors.ts';
import { formatMember, parsePath } from './paths.ts';

export type WorkloadServiceDeps = {
  db: Database;
  chainKey: Buffer;
  vault: Vault;
  config: WorkloadsConfig;
  transport: WorkloadTransport;
  /** What issues the credential an exchange returns. */
  signin: SigninService;
  /** The audience every token must name, alone. */
  publicUrl: string;
  /** What this request, or scheduled run, may spend on a binding's removal (removal.ts): a Worker's; none on Node. */
  removal?: RemovalBudget | null;
};

/** What a CI run sends: the service it signs in as, `token:<id>`, and its platform's ID token. */
export type ExchangeRequest = { service: string; token: string };

/** A credential of the service, for one run, and when it dies. */
export type Exchanged = { token: string; expiresAt: string };

/** Why an exchange was refused, as a CI user can act on it; never the values a binding expects. */
export type ExchangeReason =
  | 'malformed'
  | 'no_match'
  | 'signature'
  | 'unknown_key'
  | 'expired'
  | 'too_old'
  | 'too_long'
  | 'not_yet_valid'
  | 'audience'
  | 'replayed'
  | 'busy'
  | 'issuer_unavailable'
  // A workload's sign-in's own (docs/design/workload-access.md, section 4.1): its DPoP header missing or bad, a client
  // address outside the binding's `sources` or none to check, an older enrollment code, a code at capacity.
  | 'dpop'
  | 'source'
  | 'superseded'
  | 'full'
  // With 0.15's log, a binding the vault never sealed (one 0.14 made), or one changed around it: it signs nobody in (PR 3a).
  | 'unsealed';

/**
 * A refused exchange: 401 with its reason, 429 when too many come at once,
 * 503 when the issuer cannot be asked. Nobody was authenticated, so none of
 * it goes in the audit log (anyone can mint a genuine token from their own
 * repository); the process log has a line, sampled. One exception: a key
 * a service's uploaded keys lack alerts its managers, once an hour at most
 * (`UnknownKey`).
 */
export class ExchangeRefused extends Error {
  readonly reason: ExchangeReason;
  readonly status: 401 | 429 | 503;
  /** When to come back, in seconds, where something sets it: an issuer's keys not fetched again for ten seconds, or a minute. */
  readonly retryAfter: string | undefined;
  constructor(reason: ExchangeReason, message: string, status: 401 | 429 | 503 = 401, retryAfter?: string) {
    super(message);
    this.name = 'ExchangeRefused';
    this.reason = reason;
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

/**
 * `unknown_key` under a service's uploaded keys: the token names a key they
 * lack, most likely the one its issuer rotated to, which locks out every
 * workload of the service until an Owner uploads the keys again. It says
 * which binding, issuer and key, for the alert that tells them
 * (`unknownKeyAlert`); the token is unverified, so `kid` is shown as
 * `shownKid` bounds it.
 */
export class UnknownKey extends ExchangeRefused {
  /** The service, `token:<name>`. */
  readonly service: string;
  /** The newest of its bindings on the issuer, whose keys the token was held to. */
  readonly binding: Pick<BindingRow, 'id' | 'profile'>;
  readonly issuer: string;
  readonly kid: string | null;
  constructor(service: string, binding: Pick<BindingRow, 'id' | 'profile'>, issuer: string, kid: string | null) {
    super('unknown_key', `the token's key${kid === null ? '' : ` ${kid}`} is not among those uploaded for ${issuer}: if it rotated its keys, replace them`);
    this.service = service;
    this.binding = binding;
    this.issuer = issuer;
    this.kid = kid;
  }
}

/** How much of a token's `kid` a refusal shows. */
const MAX_SHOWN_KID = 64;

/**
 * A token's `kid` as a refusal shows it, in the process log, the audit log
 * and a person's alert: anyone may write the header, so its first 64
 * characters, each outside what a JWK's kid uses (base64url, base64, a
 * thumbprint's `:`) a `?`. Null when it names none.
 */
export function shownKid(header: Record<string, unknown>): string | null {
  const { kid } = header;
  if (typeof kid !== 'string') return null;
  const shown = kid.slice(0, MAX_SHOWN_KID).replace(/[^A-Za-z0-9._~+/=:-]/g, '?');
  return kid.length > MAX_SHOWN_KID ? `${shown}…` : shown;
}

/** The proofs a workload signs in with, by the one key of its body's `proof`: `{ "proof": { "aws": … } }`. */
export type ProofName = 'oidc' | 'aws' | 'enrollment';

/** What a proof's hooks are given: the instance, and who asks to sign in as what, with which key. */
export type ProofContext = {
  db: Database;
  chainKey: Buffer;
  config: WorkloadsConfig;
  transport: WorkloadTransport;
  publicUrl: string;
  /** The service it signs in as, `token:<name>`. */
  service: string;
  /** The thumbprint of the key the exchange's DPoP proof names, which the session will be bound to. */
  jkt: string;
  sourceIp: string | null;
  requestId: string;
};

/** A proof that holds, before the exchange's transaction: the binding it matched and what it said. */
export type MatchedProof = {
  binding: BindingRow;
  claims: Record<string, unknown>;
  /** What spending it records in `spent_id_tokens`, for a bearer proof; none for one that names the key or repeats (section 4.1). */
  spentKey?: Buffer;
  /** A bearer token's own `exp`, which ends the session it makes (section 5.4). */
  notAfter?: Date;
  /**
   * The account's and the binding's newest changes, as the read that found
   * the binding had them (T192), for the vault to check and pin in its one
   * statement; none where that read has none (`aws`, `enrollment`), and the
   * vault reads them itself.
   */
  newest?: SignInInput['newest'];
};

/** What a proof decides inside the exchange's transaction, on database facts alone. */
export type CommittedProof = {
  /** The code it was made from. */
  enrollmentId?: string;
  /** The code's scope, fixed at minting, which the session holds in place of its binding's (`MinterBound`). */
  scope?: string;
  /** The code's end. */
  notAfter?: Date;
  /** The session waits for a person's approval: the exchange answers 202. */
  pending?: true;
};

/** The session an exchange made, for the hooks that run after it. */
export type ExchangeOutcome = { verified: MatchedProof; committed: CommittedProof; sessionId: string };

/** A workload's session as its row holds it, for renewal's hooks. */
export type WorkloadSession = typeof credentials.$inferSelect;

/**
 * One kind of proof, as PR 1a's exchange dispatches to it (section 12).
 * Each refusal is returned, never thrown, so the exchange alone decides
 * what an error means. The session lives `lifetimeMs` past each renewal,
 * and never past the earliest of the binding's `sessionHours` and the
 * `notAfter`s of `verify` and `commit`.
 */
export type ProofKind = {
  /** The binding profiles it may match, the exchange's one read's filter. */
  profiles: readonly WorkloadProfile[];
  /** Before the transaction: the proof checked, outside any. */
  verify(input: unknown, ctx: ProofContext): Promise<MatchedProof | ExchangeRefused>;
  /** Inside it, under the log's head: what the database says, an enrollment's capacity and tombstone. */
  commit?(tx: Transaction, verified: MatchedProof, ctx: ProofContext): Promise<CommittedProof | ExchangeRefused>;
  /** After it, outside: alerts, the tripwire. */
  after?(outcome: ExchangeOutcome, ctx: ProofContext): Promise<void>;
  /** 3_600_000, or 90_000 for an enrollment's, whose expiry is its liveness. */
  lifetimeMs: number;
  renew?: {
    /** Inside renewal's update: a superseded code refuses it. */
    check(tx: Transaction, session: WorkloadSession): Promise<ExchangeRefused | null>;
    /** After it: the tripwire. */
    after(session: WorkloadSession, ctx: ProofContext): Promise<void>;
  };
};

// How long a session lives past each renewal, and a run's credential: @coffre/core, where the vault reads them too.
export { EXCHANGED_CREDENTIAL_MS, SESSION_MS } from '@coffre/core/identity';

/**
 * `oidc`: a platform's ID token (section 4.2), matched against the
 * service's bindings of the ID-token profiles that carry a policy, by the
 * explicit profile list, so a binding of another proof's never matches.
 * The token's audience is held to its binding's: the key's (`keyAudience`),
 * a fixed one (Azure's), or the instance's. What is spent follows section
 * 4.1's rule: a token that names the key, or one its platform hands out
 * again (`REPEATING_PROFILES`), never; any other once, in
 * `spent_id_tokens`. A token that does not name the key ends the session it
 * makes at its own `exp`, so a copy of it buys no more than the platform's
 * own lifetime.
 */
const OIDC: ProofKind = {
  profiles: OIDC_PROFILES,
  lifetimeMs: SESSION_MS,
  async verify(input, ctx) {
    if (typeof input !== 'string') return new ExchangeRefused('malformed', "an oidc proof is the platform's ID token");
    let decoded: DecodedToken;
    try {
      decoded = decodeWorkloadToken(input);
    } catch (error) {
      return refused(error);
    }
    const issuer = decoded.claims.iss;
    const unbound = new ExchangeRefused('no_match', `no workload binding of ${shownMember(ctx.service)} trusts tokens from ${issuer}`);
    // The bindings first, so that a token none can take costs this one read.
    const { bindings: loaded, newest: changes } = await workloadCandidates(ctx.db, ctx.chainKey, ctx.service, issuer, OIDC_PROFILES, MAX_BINDINGS);
    if (loaded.length === 0) return unbound;
    // Those made on this instance's URL: one made on another shadows none that was (review r1).
    const candidates = loaded.filter((binding) => madeHere(binding, ctx.publicUrl));
    if (candidates.length === 0) return madeElsewhere(loaded[loaded.length - 1]!, ctx.publicUrl);
    const accepted = (binding: BindingRow) => expectedAudiences(binding.profile as WorkloadProfile, JSON.parse(binding.policy!) as BindingPolicy, { publicUrl: ctx.publicUrl, jkt: ctx.jkt });
    // The audience the token names, if a binding takes it; else the instance's, which verifying it then refuses.
    const named = soleAudience(decoded.claims.aud);
    const audience = named !== null && candidates.some((binding) => accepted(binding).includes(named)) ? named : ctx.publicUrl;
    const taking = candidates.filter((binding) => accepted(binding).includes(audience));
    // A token its platform hands out again is as old as its platform's cache: its own `exp` ends it, not an hour after `iat`.
    const repeats = taking.some((binding) => REPEATING_PROFILES.includes(binding.profile as WorkloadProfile));
    const newest = candidates[candidates.length - 1]!;
    const expected = { issuer, audience, now: new Date(), ...(repeats ? { maxAge: null } : {}) };
    let claims: Record<string, unknown>;
    try {
      claims = newest.jwks === null
        ? await verifyWithKeys(ctx.transport, newest.jwksUri, input, expected)
        // Uploaded keys: nothing to fetch, and no issuer to ask whether a token still stands, so none lives past the hour.
        : await verifyWorkloadToken(input, JSON.parse(newest.jwks) as JSONWebKeySet, { ...expected, maxLifetime: MAX_TOKEN_AGE_SECONDS });
    } catch (error) {
      // Its keys are not fetched again until then (`workloads/keys.ts`): no sooner is any use.
      if (error instanceof IssuerUnavailable) return new ExchangeRefused('issuer_unavailable', error.message, 503, String(error.retryAfter));
      if (newest.jwks !== null && error instanceof WorkloadTokenRefused && error.reason === 'unknown_key') return new UnknownKey(ctx.service, newest, issuer, shownKid(decoded.header));
      return refused(error);
    }
    if (taking.length === 0) {
      return new ExchangeRefused('audience', `the token is for ${audience}, which no binding of ${shownMember(ctx.service)} on ${issuer} takes: a platform that lets its caller choose names the session's key, ${ctx.publicUrl}#jkt=<thumbprint>`);
    }
    let binding: BindingRow;
    try {
      binding = matching(taking.filter((candidate) => candidate.jwksUri === newest.jwksUri), claims, ctx.service);
    } catch (error) {
      if (error instanceof ExchangeRefused) return error;
      throw error;
    }
    const repeating = REPEATING_PROFILES.includes(binding.profile as WorkloadProfile);
    if (repeats && !repeating) {
      const issued = issuedRefusal(decoded.claims.iat, Date.now() / 1000);
      if (issued !== null) return refused(issued);
    }
    const policy = JSON.parse(binding.policy!) as BindingPolicy;
    const ruled = PROFILE_RULES[binding.profile as WorkloadProfile]?.token(claims, { issuer, claims: JSON.parse(binding.claims) as BindingClaims, policy }) ?? null;
    if (ruled !== null) return new ExchangeRefused('no_match', ruled);
    const namesKey = policy.keyAudience === true;
    return {
      binding,
      claims,
      ...(namesKey || repeating ? {} : { spentKey: decoded.signingInputHash }),
      ...(namesKey ? {} : { notAfter: new Date(decoded.claims.exp * 1000) }),
      newest: { member: changes.member, binding: changes.bindings.get(binding.id) ?? null },
    };
  },
};

/**
 * The proofs the exchange takes, one line each: PR 1a registers `oidc`, PR
 * 2 `aws` and PR 3 `enrollment`.
 */
export const PROOFS: { readonly [K in ProofName]?: ProofKind } = {
  oidc: OIDC,
  // Made at its first use: `workloads/aws.ts` imports this module, so neither may need the other while it loads.
  get aws() {
    return (aws ??= awsProof());
  },
};
let aws: ProofKind | undefined;

/** The proof a binding's sessions are made by: the one whose profiles hold its profile. */
export function proofOf(profile: string): { name: ProofName; kind: ProofKind } | null {
  for (const [name, kind] of Object.entries(PROOFS) as [ProofName, ProofKind][]) {
    if (kind.profiles.includes(profile as WorkloadProfile)) return { name, kind };
  }
  return null;
}

/** What a workload sends to sign in (section 4.1): the service, `token:<name>` or its name, and one proof by its kind. */
export type SessionRequest = { service: string; proof: Readonly<Record<string, unknown>> };

/** A sign-in's request beside its body: its DPoP header, verified (`jkt`, its key's thumbprint), which the vault verifies again. */
export type SignInMeta = { requestId: string; sourceIp: string | null; jkt: string; dpop: string };

/** A session made: its token, sent with the key's proof; its expiry and hard end; the environments it reaches, by path. */
export type SessionIssued = { token: string; tokenType: 'DPoP'; expiresAt: string; notAfter: string; places: string[] };

/** A session made that waits for a person's approval (section 4.4): its ID, and the page that approves it. */
export type SessionPending = { pending: string; approve: string };

/**
 * Who removes bindings, as the vault's change names them (`changeBindings`): a person's request, or the scheduled run
 * going on with one a request left under way (`resumeRemovals`), as `system:schedule`, naming who asked (`continues`).
 * Its `ctx` is the request's, for the refusals it logs; null for the scheduled run's.
 */
type Remover = {
  ctx: Asker | null;
  actor: string;
  via: string | null;
  actorAccess: string | null;
  connection: { id: string; generation: number } | null;
  revokedBy: string;
  policy: ChangeBindingsInput['policy'];
  continues?: { by: string; at: number };
};

/** A person's request, as it removes bindings: who, on which credential and connection, weighed on which policy. */
function asked(ctx: Asker, caller: Caller, accessSeq: bigint | null): Remover {
  return {
    ctx,
    actor: formatMember(ctx.caller.principal), via: ctx.credentialId, actorAccess: accessSeq?.toString() ?? null,
    connection: ctx.via?.connectionId == null ? null : { id: ctx.via.connectionId, generation: ctx.caller.generation },
    revokedBy: ctx.caller.principal.id,
    policy: {
      seq: caller.policySeq?.toString() ?? null,
      protected: Object.values(caller.policy.protectedIn).flat().map(({ environmentId, slug }) => ({ environmentId, slug })),
    },
  };
}

/**
 * The vault calls a removal's request makes once its last one is answered: none, its entries the app's own
 * transaction (`audited`), as a test holds (workload-exchange.test.ts, "counts its vault calls").
 */
export const AFTER_REMOVAL_CALLS = 0;

/** Those of `rows` no removal has closed: a closed one is being removed, and nothing replaces it again (W331). */
const open = (rows: readonly BindingRow[]): BindingRow[] => rows.filter((row) => row.closedAt === null);

/**
 * What one call of a binding's removal revokes, at most (W331; formal/Unbinding.tla; `#bindingsByVault`): as many
 * credentials as its fence allows, and as many bytes as its message does, whichever it reaches first.
 *
 * - The fence: every revoke takes it exclusive, the one fence of the instance, which every `/use` of every credential
 *   shares, for about 0.08 ms a credential, whatever its scope (measured on the compose Postgres, a loaded machine:
 *   157 ms for 2,000, 400 ms for 5,000, 1,583 ms for 20,000). The batches after the close need it too: a request whose
 *   check of its binding passed before the close can reach the vault after it, and an unfenced revoke would number
 *   its use after the revoke (formal/Unbinding.tla, `RevokeOrdersUses` without BatchFenced). A batch holds it
 *   `FENCE_BUDGET_MS` at most, 10 ms: the longest a use waits behind one, Erwin's rule that revoking never pauses
 *   `/use`, a few ms at most. The uses that arrive meanwhile wait, none refused: at R44's rate, 1,000 a second,
 *   10 of them, far below the keys an isolate or process has in flight (`USES_IN_FLIGHT`, 1,250, which bounds
 *   the hold at 1.25 s). It was derived from that count while it was 10 (node-postgres's pool size), every use past it
 *   refused `overloaded` (D181): at 50 ms a batch (D178), one Node process beside a removal of 5,000 refused none of 100
 *   uses a second, 10% at 200, 43% at 400, 68% at 800, as rate × hold passed 10; with the count derived (Q1 of
 *   docs/design/config.md), the hold bounds a use's latency, not its refusal. Rejected too: `HOT_LOCK_TIMEOUT_MS / 2`,
 *   500 ms, the migrator's, which adds up to half a second to each use, batch after batch.
 * - The message: Node's vault transport takes 8 MiB at most (`MAX_BODY`, @coffre/vault's node.ts; Workers' RPC 32 MiB,
 *   Cloudflare's docs). A credential's part of it is its columns, its scope among them, so each is counted as it
 *   serializes (about 550 bytes for one place, 21 kB for a hundred, review r4), the batch's up to half of it: the rest
 *   for the binding made, the policy's places, and the transport's own encoding.
 */
const FENCE_BUDGET_MS = 10;
const FENCE_MS_PER_CREDENTIAL = 0.08;
export const UNBIND_BATCH = Math.floor(FENCE_BUDGET_MS / FENCE_MS_PER_CREDENTIAL);
const VAULT_MESSAGE_BYTES = 8 * 1024 * 1024;
const UNBIND_BYTES = VAULT_MESSAGE_BYTES / 2;
/** A credential's part of a removal's message but for its scope and places: about 450 bytes measured (550 with a one-place scope), rounded up. */
const CREDENTIAL_BYTES = 600;

/**
 * Exchanges under way at once in this isolate or process, at most: past it,
 * 429 at once (R44). Its one writer is packages/server/test/bench/ci.ts,
 * whose one process stands in for the many isolates a burst spreads over.
 */
export const exchangeLimit = { inFlight: 32 };
let inFlight = 0;

/** Refusals logged, by reason and service, once a minute each. */
const refusalsLogged = new Map<string, number>();
const REFUSAL_LOG_MS = 60 * 1000;

/** A binding as an owner sees it. */
export type BindingView = {
  id: string;
  profile: WorkloadProfile;
  issuer: string;
  /** Where coffre fetches its issuer's keys; for one that carries them, `sha256:<hex>` of those. */
  jwksUri: string;
  /** The keys it carries, uploaded with it, under which coffre verifies and fetches nothing; null when they are fetched from `jwksUri`. */
  keys: KeySummary[] | null;
  claims: BindingClaims;
  /** What the credentials it issues reach, of what its account holds, by path; null for one 0.4 made and the app has not sealed yet, which reaches all of it. */
  scope: ScopeByPath | null;
  /** A workload's binding's policy (docs/design/workload-access.md, section 11), its reads by path and name; null for one `/api/auth/oidc` takes. */
  policy: PolicyView | null;
  label: string | null;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
  /**
   * A removal under way (W331): the binding closed, signing nobody in, since when and by whom; what it issued still
   * serves until its removal ends it. Remove it again to finish now; the scheduled run finishes it otherwise. Null for
   * a binding no removal closed.
   */
  removing: { since: string; by: string | null } | null;
};

/** What saving a binding would do: the binding as checked, the keys its issuer names or it carries, and the bindings it replaces. */
export type BindingPlan = {
  profile: WorkloadProfile;
  issuer: string;
  jwksUri: string;
  keys: KeySummary[] | null;
  claims: BindingClaims;
  scope: ScopeByPath;
  /** What it says beyond its claims, canonical, its reads by path and name; null for a binding `/api/auth/oidc` takes. */
  policy: PolicyView | null;
  /** The places of `scope` that hold a sensitive value its credentials will not read: only an Owner of their project binds one that does (R32). */
  withheld: string[];
  /** `asked`: named in `replaces`. `keys_moved`: the service's bindings on the issuer, under its old keys' URL. */
  replaces: { id: string; why: 'asked' | 'keys_moved' }[];
};

export type BindingInput = {
  profile: string;
  issuer: string | null;
  claims: BindingClaims;
  /** What the credentials it issues reach, by path (`issuedScope`): when left out, what the bindings it replaces reached, or all the account holds. */
  scope?: ScopeByPath;
  label: string | null;
  /** Bindings this one takes the place of, as a change to them: they are removed in the same step. */
  replaces: string[];
  /**
   * A workload's binding's policy (`checkPolicy`), which makes it one that
   * `/api/auth/workload` takes for a key-bound session, and
   * `/api/auth/oidc` never. Every profile but today's five always carries
   * one, `{}` at least; one of those five carries one when given, and under
   * `useOnly` always. Left out on one of them, it is a bearer binding, as before.
   * Its `reads` name each environment by path and its keys by name, or `'*'`
   * (`ReadsByPath`): the binding stores them by ID.
   */
  policy?: unknown;
  /**
   * The issuer's public keys, a JWKS, for an issuer coffre cannot or should
   * not fetch them from, such as a private Kubernetes cluster's: then the
   * issuer is any string its tokens name, and coffre asks it nothing.
   */
  jwks?: JSONWebKeySet;
};

/**
 * What replacing a service's keys for an issuer would do: the keys, the
 * bindings on the issuer that new ones, the same but for those keys, take
 * the place of, and the places of their scopes that hold a sensitive value
 * the new ones will not read: one an Owner bound, re-keyed by anyone else.
 */
export type KeysPlan = { issuer: string; jwksUri: string; keys: KeySummary[]; replaces: string[]; withheld: string[] };

/**
 * A workload's ID token, verified for a service: the binding of the service
 * whose every claim it carries, and its claims as verified. Nothing spent:
 * whoever acts on it spends it (the vault's sign-in). Read with the bindings,
 * whether it was spent already, and the newest policy change, for the
 * vault's answer about the service that follows (`exchangeCandidates`).
 */
export type VerifiedWorkload = {
  binding: BindingRow; claims: Record<string, unknown>; token: DecodedToken; spent: boolean; policySeq: bigint | null;
  /** The account's and the binding's newest changes, as `exchangeCandidates` read them beside it (T192). */
  newest: NonNullable<SignInInput['newest']>;
};

/**
 * The IDs a binding names, as an owner would otherwise look them up, under
 * the names the host gives them: `Acme/API` looked up is `acme/api`, as its
 * tokens name it. A GitHub owner, a user or an organization, has an ID alone.
 */
export type WorkloadIds =
  | { github: string; repositoryId: string; ownerId: string }
  | { github: string; ownerId: string }
  | { gitlab: string; projectId: string; namespaceId: string };

const GITHUB_OWNER = /^[A-Za-z0-9-]{1,39}$/;
const GITHUB_REPOSITORY = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const GITLAB_PROJECT = /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+){1,20}$/;

/**
 * Trust bindings: which CI runs may sign in as a service by the ID token
 * their platform signs (docs/design/oidc.md). Owners make and remove them;
 * each is checked against its profile, its issuer asked where its keys are,
 * and nothing about it changes afterwards but its label and last use. A
 * change is a new binding, and the old one's `token.unbind` its tombstone.
 *
 * Making one takes the log's head first, as every audited change does, so
 * two at once cannot both find room under `MAX_BINDINGS`.
 */
export class WorkloadService {
  readonly #deps: WorkloadServiceDeps;
  /** The removal calls each request made, by its context: whether one under way made any (`RemovalUnderWay.progressed`). */
  readonly #removalCalls = new WeakMap<object, number>();

  constructor(deps: WorkloadServiceDeps) {
    this.#deps = deps;
  }

  /** The limit per source every sign-in passes first (`admission` in auth-routes.ts). */
  get limits(): WorkloadsConfig['limits'] {
    return this.#deps.config.limits;
  }

  async listBindings(ctx: Asker, serviceId: string): Promise<BindingView[]> {
    const { principal } = ctx.caller;
    const self = principal.type === 'service' && principal.id === serviceId;
    if (!self && !(await managedAccount(this.#deps, ctx.caller, serviceId)).managed) {
      throw forbidden('only those who manage this service account may see its trust bindings');
    }
    const member = `token:${serviceId}`;
    const standing = await memberStanding(this.#deps.db, member);
    if (standing === null) throw notFound('unknown service');
    const [live, known] = await Promise.all([liveBindings(this.#deps.db, this.#deps.chainKey, member, standing.generation), places(this.#deps.db)]);
    const shown = await this.#shownPolicies(live, known);
    return live.map((row) => view(row, scopeByPath(readScope(row.scope), known), shown(row.policy)));
  }

  /** How these bindings' policies are shown: their reads by path and name, as they are named now (section 6.1, D16). */
  async #shownPolicies(rows: readonly BindingRow[], known?: readonly PlaceRow[]): Promise<(policy: string | null) => PolicyView | null> {
    const listed = rows.flatMap((row) => Object.values((row.policy === null ? {} : (JSON.parse(row.policy) as BindingPolicy)).reads ?? {}));
    const [placed, named] = await Promise.all([known ?? places(this.#deps.db), keyNames(this.#deps.db, listed.flatMap(({ keys }) => (Array.isArray(keys) ? keys : [])))]);
    return (policy) => (policy === null ? null : namedPolicy(JSON.parse(policy) as BindingPolicy, placed, named));
  }

  /**
   * A service's live bindings whose scope this release sealed. One an older
   * release made with none, or with one that does not say where it reads
   * sensitive values, is never sealed from what the account holds:
   * it signs nobody in (`#exchange`), and nothing replaces it or inherits
   * its scope. The service is bound again instead.
   */
  async #scopedBindings(member: string, generation: number): Promise<BindingRow[]> {
    return (await liveBindings(this.#deps.db, this.#deps.chainKey, member, generation)).filter((row) => !unsealedScope(row.scope));
  }

  /** Check a binding and ask its issuer where its keys are; with `dryRun`, write nothing and log nothing. */
  async bind(ctx: Asker, serviceId: string, input: BindingInput, options: { dryRun: boolean }): Promise<BindingPlan | { binding: BindingView; replaced: string[] }> {
    const member = `token:${serviceId}`;
    const details = { principalType: 'service', principalId: serviceId, profile: input.profile, issuer: input.issuer };
    const uploaded = input.jwks === undefined ? null : await keysOf(input.jwks);
    let policy: ReturnType<typeof checkBinding>;
    // A workload's binding, which signs in at `/api/auth/workload` alone: every one but a bearer binding of today's five profiles.
    // Its policy checked whole but for `reads`, which name places and keys by path and name, found below.
    let rules: BindingPolicy | null = null;
    let wantedReads: unknown;
    try {
      policy = checkBinding(input, { allowLoopback: this.#deps.config.allowLoopback, uploaded: uploaded !== null });
      if (!isBearerProfile(policy.profile) || input.policy !== undefined || this.#deps.signin.config.useOnly) {
        if (input.policy !== undefined && (typeof input.policy !== 'object' || input.policy === null || Array.isArray(input.policy))) throw new BindingInvalid('a policy is an object');
        const { reads, ...rest } = (input.policy ?? {}) as Record<string, unknown>;
        rules = checkPolicy(policy.profile, rest, { service: member });
        PROFILE_RULES[policy.profile]?.binding(policy, rules);
        wantedReads = reads;
      }
    } catch (error) {
      if (error instanceof BindingInvalid) throw badRequest(error.message);
      throw error;
    }
    if (wantedReads !== undefined && this.#deps.config.noReads) throw badRequest('this instance lets no binding list reads (noReads): its services read plain values only');
    // Its scope's shape too, before the issuer is asked anything: what it names is checked once the bindings it replaces are known.
    if (input.scope !== undefined) parseScope(input.scope, ctx.caller.policy);
    return withRefusals(this.#deps, async () => {
      // The issuer as the vault answers now, which its change is held to (`actorAccess`): demoted meanwhile, they give it nothing.
      const { caller, accessSeq } = await issuerNow(this.#deps, ctx.caller.principal, { ctx, action: 'token.bind' });
      // Who runs the instance, or a person who reaches every grant it holds (`managesService`).
      const { standing, managed, setting } = await managedAccount(this.#deps, caller, serviceId);
      if (!managed) throw notManager(ctx, 'token.bind', details, 'trust workloads as it');
      const unknown = () => new Refusal(notFound('unknown service'), denied(ctx, 'token.bind', 'unknown_principal', { metadata: details }));
      if (standing.status !== 'active') throw unknown();
      // Keys uploaded with it, by their digest; else where its issuer's discovery says they are.
      let jwksUri: string;
      try {
        // A proof that is no ID token has no keys to discover: its URN keeps one key source per issuer.
        jwksUri = policy.issuer.startsWith('urn:')
          ? policy.issuer
          : uploaded === null
            ? await discoverKeys(this.#deps.transport, policy.issuer, { allowLoopback: this.#deps.config.allowLoopback })
            : `${UPLOADED_KEYS}${uploaded.digest}`;
      } catch (error) {
        if (error instanceof DiscoveryFailed) throw badRequest(`coffre could not use ${policy.issuer}: ${error.message}`);
        throw error;
      }
      /** The bindings it takes the place of, among those live. */
      type Replacing = BindingRow & { why: BindingPlan['replaces'][number]['why'] };
      const replacing = (live: BindingRow[]): Replacing[] => {
        const asked = new Set(input.replaces);
        const unknownReplaced = input.replaces.filter((id) => !live.some((row) => row.id === id));
        if (unknownReplaced.length > 0) throw conflict(`no live binding of ${shownMember(member)}'s is ${unknownReplaced.join(', ')}`);
        const replaces = live.flatMap((row): Replacing[] => {
          if (asked.has(row.id)) return [{ ...row, why: 'asked' }];
          return row.issuer === policy.issuer && row.jwksUri !== jwksUri ? [{ ...row, why: 'keys_moved' }] : [];
        });
        // Keys uploaded, on either side, are no move of the issuer's: the bindings that would go are still good.
        if (replaces.some((row) => row.why === 'keys_moved' && (row.jwksUri.startsWith(UPLOADED_KEYS) || jwksUri.startsWith(UPLOADED_KEYS)))) {
          throw conflict(
            `${shownMember(member)}'s other bindings on ${policy.issuer} verify with other keys: replace their keys with these first, or replace those bindings with this one`,
          );
        }
        if (live.length - replaces.length + 1 > MAX_BINDINGS) throw conflict(`a service holds at most ${MAX_BINDINGS} bindings`);
        return replaces;
      };
      const replaced = replacing(open(await this.#scopedBindings(member, standing.generation)));
      // Left out, its scope is what those it replaces reached, so that trusting a workload again never widens it.
      const inherits = input.scope === undefined && replaced.length > 0;
      const issued = await issuedScope(
        this.#deps.db, { ...ctx, caller }, setting, standing, input.scope, { action: 'token.bind', metadata: details }, inherits ? inheritedScope(replaced) : undefined,
      );
      const { byPath, withheld } = issued;
      // Its reads, each place and key found by path and name as they are now, then stored by ID (section 6.1).
      const reads = wantedReads === undefined ? [] : await resolveReads(this.#deps.db, wantedReads);
      if (rules !== null && reads.length > 0) rules = checked(() => checkPolicy(policy.profile, { ...rules, reads: readsById(reads) }, { service: member }));
      const scope = reads.length === 0 ? issued.scope : readsScope({ ...ctx, caller }, issued.scope, reads, details);
      const plan = (replaces: typeof replaced): BindingPlan => ({
        ...policy, jwksUri, keys: uploaded?.keys ?? null, scope: byPath, policy: rules === null ? null : shownPolicy(rules, reads), withheld, replaces: replaces.map(({ id, why }) => ({ id, why })),
      });
      if (options.dryRun) return plan(replaced);

      // The vault makes it, weighing who may as it weighs a service token's issue, and ends those it replaces with what
      // they issued, in one statement (PR 3a): no 0.14 head.
      return retrying(async () => {
        // Planned on those live, held beside every row not revoked, from one read (Fable on PR 3a).
        const { live, unrevoked } = await bindingsNow(this.#deps.db, this.#deps.chainKey, member, standing.generation);
        const planned = plan(replacing(open(live)));
        if (reads.length > 0 && JSON.stringify(readsById(await resolveReads(this.#deps.db, wantedReads))) !== JSON.stringify(readsById(reads))) {
          throw conflict('the keys its reads name changed while it was made: try again');
        }
        if (inherits && planned.replaces.map(({ id }) => id).join() !== replaced.map(({ id }) => id).join()) {
          throw conflict('the bindings it replaces changed while it was made: try again');
        }
        const row = {
          id: randomUUID(), principal: member, generation: standing.generation, profile: planned.profile, issuer: planned.issuer, jwksUri: planned.jwksUri,
          jwks: uploaded?.jwks ?? null, claims: canonicalClaims(planned.claims), scope: storedScope(scope), policy: rules === null ? null : policyText(rules),
          label: input.label ?? null, createdBy: ctx.caller.principal.id, createdAt: new Date(),
        };
        const ending = live.filter((candidate) => planned.replaces.some(({ id }) => id === candidate.id));
        const entries = [
          ...planned.replaces.map((replacing) => allowed(ctx, 'token.unbind', {
            metadata: { bindingId: replacing.id, principalType: 'service', principalId: serviceId, reason: replacing.why === 'asked' ? 'replaced' : 'keys_moved', by: row.id },
          })),
          allowed(ctx, 'token.bind', {
            metadata: {
              bindingId: row.id, principalType: 'service', principalId: serviceId, profile: planned.profile, issuer: planned.issuer, jwksUri: planned.jwksUri,
              ...(uploaded === null ? {} : { keys: uploaded.keys }), claims: planned.claims, scope,
              ...(rules === null ? {} : { policy: rules }), ...(reads.length === 0 ? {} : { reads: shownPolicy(rules!, reads).reads }),
              replaces: planned.replaces.map((replacing) => replacing.id),
            },
          }),
        ];
        await this.#bindingsByVault(asked(ctx, caller, accessSeq), member, row, { live: unrevoked.map(({ id }) => id), reads }, ending, planned.replaces.some(({ why }) => why === 'keys_moved') ? 'keys_moved' : 'replaced', details, entries);
        return {
          binding: view({ ...row, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null, seal: null, closedAt: null, closedBy: null }, byPath, planned.policy),
          replaced: planned.replaces.map(({ id }) => id),
        };
      });
    });
  }

  /**
   * Give a service's bindings on an issuer new keys, uploaded: when the
   * issuer rotates its keys, or when its keys are to be uploaded rather
   * than fetched. Bindings never change, so each is replaced by a new one,
   * the same but for its keys, in one step, and the old one's
   * `token.unbind` is its tombstone: the credentials it issued end with it.
   * A set that holds the old keys and the new verifies tokens of both while
   * the issuer moves from one to the other. With `dryRun`, write nothing and
   * log nothing.
   */
  async replaceKeys(
    ctx: Asker,
    serviceId: string,
    input: { issuer: string; jwks: JSONWebKeySet },
    options: { dryRun: boolean },
  ): Promise<KeysPlan | { bindings: BindingView[]; replaced: string[] }> {
    const member = `token:${serviceId}`;
    const details = { principalType: 'service', principalId: serviceId, issuer: input.issuer };
    const uploaded = await keysOf(input.jwks);
    const jwksUri = `${UPLOADED_KEYS}${uploaded.digest}`;
    return withRefusals(this.#deps, async () => {
      // The issuer as the vault answers now, which its change is held to (`actorAccess`), as in `bind`.
      const { caller, accessSeq } = await issuerNow(this.#deps, ctx.caller.principal, { ctx, action: 'token.bind' });
      const { standing, managed, setting } = await managedAccount(this.#deps, caller, serviceId);
      if (!managed) throw notManager(ctx, 'token.bind', details, 'trust workloads as it');
      const unknown = () => new Refusal(notFound('unknown service'), denied(ctx, 'token.bind', 'unknown_principal', { metadata: details }));
      if (standing.status !== 'active') throw unknown();
      /** Its live bindings on the issuer, each held to its profile as one that carries its keys. */
      const replacing = (live: BindingRow[]): BindingRow[] => {
        const on = live.filter((row) => row.issuer === input.issuer);
        if (on.length === 0) throw notFound(`no binding of ${shownMember(member)}'s trusts ${input.issuer}`);
        if (on.every((row) => row.jwksUri === jwksUri)) throw conflict(`${shownMember(member)}'s bindings on ${input.issuer} carry these keys already`);
        for (const row of on) {
          try {
            checkBinding({ profile: row.profile, issuer: row.issuer, claims: JSON.parse(row.claims) as BindingClaims }, { uploaded: true });
          } catch (error) {
            if (error instanceof BindingInvalid) throw badRequest(error.message);
            throw error;
          }
        }
        return on;
      };
      // Each binding is replaced on its own (below): those already on the new keys, which a request that stopped part way
      // left, are done, and its preview says so too (review r4).
      const replaced = replacing(open(await this.#scopedBindings(member, standing.generation))).filter((row) => row.jwksUri !== jwksUri);
      // Each reaches what the one it replaces did, of what the account still holds: replacing keys never widens a binding.
      const scopes = new Map<string, Awaited<ReturnType<typeof issuedScope>>>();
      for (const row of replaced) {
        scopes.set(row.id, await issuedScope(this.#deps.db, { ...ctx, caller }, setting, standing, undefined, { action: 'token.bind', metadata: details }, inheritedScope([row])));
      }
      const withheld = [...new Set([...scopes.values()].flatMap((issued) => issued.withheld))].sort();
      const plan: KeysPlan = { issuer: input.issuer, jwksUri, keys: uploaded.keys, replaces: replaced.map((row) => row.id), withheld };
      if (options.dryRun) return plan;
      // Each new binding's policy, its old one's, shown by path and name.
      const shown = await this.#shownPolicies(replaced);
      // Each replaced by the vault, one call each, in the order of those they replace (PR 3a); each read and retried on its
      // own, so that one that moved is asked again without undoing those done (review r1).
      const bindings: BindingView[] = [];
      const now = Date.now();
      // Those not yet on the new keys: a request again after one that stopped part way finishes what it left (review r3).
      const unfinished = replaced;
      for (const [i, planned] of unfinished.entries()) {
        bindings.push(await retrying(async () => {
          const { live, unrevoked } = await bindingsNow(this.#deps.db, this.#deps.chainKey, member, standing.generation);
          // Those on the issuer with other keys are those planned and not yet done: one made or ended meanwhile is no
          // part of this replacement, as 0.14's transaction held the whole set (review r2).
          const pending = open(live).filter((row) => row.issuer === input.issuer && row.jwksUri !== jwksUri).map((row) => row.id);
          if (pending.join() !== unfinished.slice(i).map((row) => row.id).join()) throw conflict(`the bindings on ${input.issuer} changed while their keys were replaced: try again`);
          const old = live.find((row) => row.id === planned.id)!;
          const { scope, byPath } = scopes.get(old.id)!;
          const row = {
            id: randomUUID(), principal: member, generation: standing.generation, profile: old.profile, issuer: old.issuer, jwksUri, jwks: uploaded.jwks,
            claims: old.claims, scope: storedScope(scope), policy: old.policy, label: old.label, createdBy: ctx.caller.principal.id,
            // A millisecond apart, in the order of those they replace: an exchange tries bindings oldest first, and still does.
            createdAt: new Date(now + i),
          };
          await this.#bindingsByVault(asked(ctx, caller, accessSeq), member, row, { live: unrevoked.map(({ id }) => id), reads: [] }, [old], 'keys_moved', { ...details, bindingId: old.id }, [
            allowed(ctx, 'token.unbind', { metadata: { bindingId: old.id, principalType: 'service', principalId: serviceId, reason: 'keys_replaced', by: row.id } }),
            allowed(ctx, 'token.bind', {
              metadata: {
                bindingId: row.id, principalType: 'service', principalId: serviceId, profile: old.profile, issuer: old.issuer, jwksUri, keys: uploaded.keys,
                claims: JSON.parse(old.claims) as BindingClaims, scope, replaces: [old.id],
              },
            }),
          ]);
          return view({ ...row, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null, seal: null, closedAt: null, closedBy: null }, byPath, shown(old.policy));
        }).catch((error: unknown) => {
          // Under way before this one's make: what is left is the bindings not yet replaced, this one among them. Each
          // costs a request one call, its make, the rest of its removal the scheduled run's on Workers, so each request
          // asked again replaces one more at least (reviews r8, r9), whatever runs sign in meanwhile.
          if (!(error instanceof RemovalUnderWay)) throw error;
          throw new RemovalUnderWay(unfinished.length - i, error.progressed);
        }));
      }
      return { bindings, replaced: unfinished.map((row) => row.id) };
    });
  }

  /** Remove a binding. Its end in the log (`binding.revoke`) is final: no row put back brings it back (`bindingLive`). */
  async unbind(ctx: Asker, serviceId: string, bindingId: string): Promise<{ unbound: true }> {
    const member = `token:${serviceId}`;
    const metadata = { bindingId, principalType: 'service', principalId: serviceId };
    return withRefusals(this.#deps, async () => {
      // Logged as a denial, which ends nothing.
      if (!(await managedAccount(this.#deps, ctx.caller, serviceId)).managed) throw notManager(ctx, 'token.unbind', metadata, 'remove its trust bindings');
      // The vault ends it and what it issued, in one statement (PR 3a).
      return retrying(async () => {
        // As its row is, MAC or not, ended or not: the vault ends what is there, by its seal (Fable on PR 3a).
        const row = await bindingRow(this.#deps.db, member, bindingId);
        // One a removal closed, and ended since, by the scheduled run or another request: asked again after its 202, the
        // removal is done (review r9). Its end in the log, the binding's newest change, which its row's seal must be,
        // not its columns, which a writer could set, says it ended (review r10; `bindingEnded`).
        if (row !== null && row.revokedAt !== null && row.closedAt !== null && (await bindingEnded(this.#deps.db, row.id))) {
          return { unbound: true as const };
        }
        if (row === null || row.revokedAt !== null) throw new Refusal(notFound('unknown trust binding'), denied(ctx, 'token.unbind', 'unknown_binding', { metadata }));
        await this.#bindingsByVault(asked(ctx, ctx.caller, null), member, null, null, [row], 'unbound', metadata, [allowed(ctx, 'token.unbind', { metadata: { ...metadata, reason: 'removed' } })]);
        return { unbound: true as const };
      });
    });
  }

  /**
   * A repository's, owner's or project's IDs, which bindings name rather
   * than names: GitHub's API, or a GitLab's. The pages cannot ask those
   * hosts themselves, since they may connect only to coffre; the CLI asks
   * itself. A GitHub repository resolves through the deployment's GitHub App
   * when it is installed there, private or not, and through the public API
   * otherwise. A private one neither reaches is not found, and its IDs are
   * typed in.
   *
   * Asked without signing in, GitHub answers 60 lookups an hour per
   * address, which every user of a Workers deployment shares: a 403 or a
   * 429 says the hour's are spent, as `too_many_requests`.
   */
  async lookup(ctx: Asker, input: { github?: string; gitlab?: string; gitlabUrl?: string }): Promise<WorkloadIds> {
    await this.#setsUp(ctx);
    const ask = async (url: URL, missing = notFound(`${url.hostname} did not find it: for a private one, type its IDs`)): Promise<Record<string, unknown>> => {
      try {
        const answer = await this.#deps.transport.json(url);
        return typeof answer === 'object' && answer !== null ? (answer as Record<string, unknown>) : {};
      } catch (error) {
        if (!(error instanceof FetchRefused)) throw error;
        if (error.status === 403 || error.status === 429) {
          throw new ApiError('too_many_requests', `${url.hostname} allows only so many lookups an hour without signing in, and this hour's are spent: try again later, or type the IDs`);
        }
        if (error.status === 404) throw missing;
        throw new ApiError('unavailable', `${url.hostname} did not answer (${error.message}): try again, or type the IDs`);
      }
    };
    const id = (value: unknown) => (typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : null);
    const name = (value: unknown, given: string) => (typeof value === 'string' && value.toLowerCase() === given.toLowerCase() ? value : given);
    if (input.github !== undefined && GITHUB_OWNER.test(input.github)) {
      const owner = await ask(new URL(`https://api.github.com/users/${input.github}`));
      const ownerId = id(owner.id);
      if (ownerId === null) throw notFound(`GitHub does not know ${input.github}`);
      return { github: name(owner.login, input.github), ownerId };
    }
    if (input.github !== undefined) {
      if (!GITHUB_REPOSITORY.test(input.github)) throw badRequest('a GitHub repository is <owner>/<name>, and an owner <owner>');
      const app = this.#deps.config.github;
      if (app !== null) {
        const found = await unavailable(() => app.repository(input.github!));
        if (found !== null) return { github: found.github, repositoryId: found.repositoryId, ownerId: found.ownerId };
      }
      const owner = input.github.split('/')[0]!;
      const repository = await ask(
        new URL(`https://api.github.com/repos/${input.github}`),
        // `not_installed`: the pages say this, where a 404 is otherwise theirs to word.
        app === null ? undefined : new ApiError('not_found', `GitHub did not find it, and the GitHub App is not installed on it: install it on ${owner}, or type its IDs`, 'not_installed'),
      );
      const [repositoryId, ownerId] = [id(repository.id), id((repository.owner as Record<string, unknown> | undefined)?.id)];
      if (repositoryId === null || ownerId === null) throw notFound(`GitHub does not know ${input.github}`);
      return { github: name(repository.full_name, input.github), repositoryId, ownerId };
    }
    if (input.gitlab !== undefined) {
      if (!GITLAB_PROJECT.test(input.gitlab)) throw badRequest('a GitLab project is <group>/<name>');
      const base = input.gitlabUrl ?? GITLAB_ISSUER;
      try {
        checkFetchUrl(base, 'the GitLab URL', { allowLoopback: this.#deps.config.allowLoopback, path: true, query: false });
      } catch (error) {
        if (error instanceof BindingInvalid) throw badRequest(error.message);
        throw error;
      }
      const project = await ask(new URL(`${base.replace(/\/$/, '')}/api/v4/projects/${encodeURIComponent(input.gitlab)}`));
      const [projectId, namespaceId] = [id(project.id), id((project.namespace as Record<string, unknown> | undefined)?.id)];
      if (projectId === null || namespaceId === null) throw notFound(`GitLab does not know ${input.gitlab}`);
      return { gitlab: name(project.path_with_namespace, input.gitlab), projectId, namespaceId };
    }
    throw badRequest('look up a GitHub repository or a GitLab project');
  }

  /**
   * The repositories the deployment's GitHub App is installed on, for the
   * pages' picker; `{ app: null }` when it has none. One call to coffre,
   * which asks GitHub for each installation (`GitHubApp.repositories`).
   */
  async repositories(ctx: Asker): Promise<GitHubAppRepositories | { app: null }> {
    await this.#setsUp(ctx);
    const app = this.#deps.config.github;
    return app === null ? { app: null } : unavailable(() => app.repositories());
  }

  /** Asked of GitHub or GitLab for whoever sets up any service account; what they trust, each binding's own check decides. */
  async #setsUp(ctx: Asker): Promise<void> {
    if (!setsUp(ctx.caller, await serviceSettingFor(this.#deps.vault, ctx.caller), await places(this.#deps.db))) {
      throw forbidden('only those who set up service accounts may trust workloads');
    }
  }

  /**
   * With 0.15's log, a service's bindings changed by the vault itself (T149,
   * PR 3a): `make` made, weighed there as a service token's issue is, and
   * `ends` ended with every live credential each issued, in one statement
   * (`Vault.changeBindings`), whichever made them: 0.14 too. Its entries,
   * `entries`, ride the changes that record their acts, which the
   * audit page shows. The app's own checks read
   * the end from the log (`bindingLive`), so a binding row put back stays
   * dead to them too. Refusals as the app's own are.
   */
  async #bindingsByVault(
    who: Remover,
    member: string,
    make: Parameters<typeof madeBinding>[2] | null,
    beside: { live: readonly string[]; reads: readonly ResolvedRead[] } | null,
    ends: readonly BindingRow[],
    reason: ChangeBindingsInput['reason'],
    details: Record<string, unknown>,
    entries: readonly AuditEntry[],
  ): Promise<void> {
    const { db, chainKey, vault } = this.#deps;
    if (!(await vaultBinds(vault))) throw new Error("this vault changes no binding: coffre needs one that keeps 0.15's log");
    const { ctx } = who;
    const action = make === null ? 'token.unbind' : 'token.bind';
    const budget = this.#deps.removal ?? null;
    const batchOf = budget?.batch ?? UNBIND_BATCH;
    // The binding to make, until a call has made it: a replacement's first call makes it as it closes those it replaces
    // (reviews r8, r9; Unbinding.tla's MakesAtClose), so that no request that stops leaves them closed and it not made.
    let making = make;
    // Each entry rides the change that records its act: the make's (`token.bind`) the make, in whichever call makes
    // it, and each end's (`token.unbind`, by the binding it names) that binding's end. A sweep's close is no change, and
    // carries none; ended by the scheduled run, its own entry is the end's.
    const carried = (entry: AuditEntry) => entryOf(ctx ?? { credentialId: null }, entry);
    const bound = entries.find(({ action: done }) => done === 'token.bind');
    const made = bound === undefined ? null : carried(bound);
    const unbound = new Map(entries.filter(({ action: done }) => done === 'token.unbind').map((entry) => [entry.metadata?.bindingId, entry]));
    // One the log never held, with no seal, ends with no change (`bindingsCall`), which can carry no entry: its entry is
    // an event, written through `note` once it is ended, after the vault's commit (#569). Should that fail, the end stands
    // and the request answers an error.
    const sealless = ends.flatMap((row) => (row.seal === null ? (unbound.get(row.id) ?? []) : []));
    // Whether the make is in.
    let entered = false;
    /** Whether the request is done: its make in, what is left is the removal of those it replaces (on Workers, the scheduled run's). */
    const madeIn = () => {
      if (making === null) return false;
      making = null;
      entered = true;
      return budget !== null;
    };
    const asked = async (at: Date, sealedEnds: EndedBinding[], sweep: boolean) => {
      // A Worker's request makes so many vault calls, and spends so much CPU, at most (removal.ts): past them the
      // removal is under way, its binding closed, for the next request or scheduled run to go on with.
      // What is left: the credentials still to revoke, and the bindings still to end, so that it falls with every call.
      if (budget !== null && !budget.take(AFTER_REMOVAL_CALLS)) {
        throw new RemovalUnderWay(ends.length + (await liveIssued(db, member, ends.map(({ id }) => id))), ctx !== null && (this.#removalCalls.get(ctx) ?? 0) > 0);
      }
      if (ctx !== null) this.#removalCalls.set(ctx, (this.#removalCalls.get(ctx) ?? 0) + 1);
      return vault.changeBindings!({
      actor: who.actor, via: who.via, actorAccess: who.actorAccess,
      // Through an MCP connection, held to it as `credentialStill` holds a write to it (review r3).
      connection: who.connection,
      // The binding a replacement makes, in its first call, which the vault weighs, and holds to its maker's rows (review r4).
      make: making === null ? null : madeBinding(chainKey, this.#deps.publicUrl, making, made), ends: sealedEnds, reason, revokedAt: at.getTime(), revokedBy: who.revokedBy,
      // The account's live bindings it was weighed beside, but those 0.14 made and ended just now; the keys it reads, by name.
      live: making === null ? null : [...(beside?.live ?? [])],
      reads: (beside?.reads ?? []).flatMap((read) => (read.keys === '*' ? [] : read.keys.map(({ id, key }) => ({ id, key })))),
      ...(sweep ? { sweep: true } : {}),
      ...(who.continues === undefined ? {} : { continues: who.continues }),
      policy: who.policy,
      appKey: appLogKey(chainKey).keyId,
      });
    };
    // In batches, of a vault that takes them (formal/Unbinding.tla): more live credentials than a batch, a sweep closes the
    // bindings it ends (no sign-in through them from then on) and revokes a batch, then they are read again; a batch or
    // fewer, the change ends them, every live one named; refused as `moved` (a sign-in between the read and the lock), a
    // sweep of none closes them, and they are read again. A vault older than this app, mid-deploy, ends them in one call.
    const sweeps = await vaultSweeps(vault);
    const ids = ends.map(({ id }) => id);
    // Ended as named, with the credentials each issued of `named`: every one the statement counts, MAC or not (Fable on
    // PR 3a), as one the app's check passes over would refuse the end.
    // A sweep's close carries no entry; an end, its binding's, unless it has no seal (above).
    const ended = (at: Date, named: readonly CredentialRow[], sweep: boolean) => ends.map((row) => {
      const entry = sweep || row.seal === null ? undefined : unbound.get(row.id);
      return endedBinding(chainKey, this.#deps.publicUrl, row, named.filter(({ createdBy }) => createdBy === issuedBy(row.id)), at, entry === undefined ? null : carried(entry));
    });
    let closed = false;
    // When the last sweep's batch's last credential ends: the next read starts there (review r6).
    let after: Date | null = null;
    let outcome!: Awaited<ReturnType<typeof asked>>;
    try {
    for (;;) {
      const at = new Date();
      if (!sweeps) {
        outcome = await asked(at, ended(at, await issuedCredentials(db, member, ids), false), false);
        break;
      }
      // A batch's worth and one more, by id and size alone (review r5): whether this is the last call, and which this
      // one names, chosen before any row is read whole. A credential's part of the message is its fixed fields, about
      // `CREDENTIAL_BYTES`, and its scope and places, each counted twice, as JSON in JSON escapes their quotes.
      const soonest = await issuedSoonest(db, member, ids, batchOf + 1, after);
      const chosen: string[] = [];
      let bytes = 0;
      for (const { id, bytes: wide } of soonest) {
        const size = CREDENTIAL_BYTES + 2 * wide;
        if (chosen.length === batchOf || (chosen.length > 0 && bytes + size > UNBIND_BYTES)) break;
        chosen.push(id);
        bytes += size;
      }
      if (chosen.length < soonest.length) {
        outcome = await asked(at, ended(at, await credentialRows(db, chosen), true), true);
        if (!outcome.ok) break;
        closed = true;
        after = soonest[chosen.length - 1]!.expiresAt;
        if (madeIn()) return;
        continue;
      }
      // The end names every live one: read from the start once more, so that one ending sooner than the last batch,
      // signed in before the close, is named too. Those the sweeps revoked have left the index it reads.
      if (after !== null) {
        after = null;
        continue;
      }
      const read = await credentialRows(db, chosen);
      outcome = await asked(at, ended(at, read, false), false);
      // Closed only when it ends one: a bind beside none, moved, is asked again as before (`retrying`).
      if (!outcome.ok && outcome.refused === 'moved' && !closed && ends.length > 0) {
        outcome = await asked(at, ended(at, [], true), true);
        if (!outcome.ok) break;
        closed = true;
        if (madeIn()) return;
        continue;
      }
      break;
    }
    } catch (error) {
      // The make in, its request is done, whatever stops the removal after it: asked again, a replacement would make
      // another binding (`retrying`). The binding it replaces stays closed, for the scheduled run to end.
      if (!entered) throw error;
      console.error({ event: 'removal_left', principal: member, bindings: ends.map(({ id }) => id), error: logged(error) }, 'the removal after a replacement stopped: the scheduled run goes on with it');
      return;
    }
    if (outcome.ok) {
      for (const entry of sealless) await noteEvent(vault, eventOf(entry, ctx?.credentialId ?? null));
      return;
    }
    if (entered) {
      console.error({ event: 'removal_left', principal: member, bindings: ends.map(({ id }) => id), refused: outcome.refused }, 'the removal after a replacement was refused: the scheduled run goes on with it');
      return;
    }
    if (outcome.refused === 'moved') throw new ObjectMoved();
    // The scheduled run's resume has no request to refuse: its beat reports it, and the next one asks again.
    if (ctx === null) throw new Error(`the vault refused to go on with the removal of ${ends.map(({ id }) => id).join(', ')}: ${outcome.refused}`);
    switch (outcome.refused) {
      case 'access': throw new ApiError('conflict', 'your access changed while this ran: try again', ACCESS_CHANGED);
      case 'gone': throw vaultDecided(ctx, notFound('unknown service'), action, 'unknown_principal', { metadata: details });
      // The credential the request came in on ended, or is one 0.14 made, which the vault cannot vouch for: signed in again, it can.
      case 'ended': case 'unlogged':
        throw new Refusal(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked: sign in again'), denied(ctx, action, 'credential_ended', { metadata: details }));
      case 'refused':
        throw vaultDecided(ctx, forbidden(outcome.why ?? 'not allowed to trust workloads as it'), action, 'vault_refused', { metadata: { ...details, why: outcome.why ?? null } });
      case 'policy': throw new ApiError('conflict', "the instance's roles or protected environments changed while this ran: try again", POLICY_CHANGED);
      case 'busy': throw new ApiError('unavailable', 'coffre is busy: try again shortly', 'busy', '1');
      case 'retired': throw new KeyRetired('the app\'s key is one it rotated from: a newer deployment replaces this one');
      case 'full': throw conflict(`a service holds at most ${MAX_BINDINGS} bindings`);
      // A row changed or put back around coffre, which no seal of the vault's covers: passed over, as the app passes over a
      // row its MAC fails (it signs nobody in either way), and reported.
      case 'stale': case 'tampered':
        console.error({ event: 'binding_tampered', principal: member, refused: outcome.refused }, 'a binding row is not the log\'s');
        throw vaultDecided(ctx, notFound('unknown trust binding'), action, 'unknown_binding', { metadata: details });
    }
  }

  /**
   * The scheduled run's part in removing bindings (W331, A'; formal/Unbinding.tla's `rs`): every binding a removal
   * closed and did not end, its request stopped (a Worker's budget spent, a crash, a browser closed), gone on with as
   * `system:schedule`, naming who asked, until this run's budget is spent. A closed binding signs nobody in, but what it
   * issued serves until revoked, so its end must not wait for its remover to ask again. Each change it writes records
   * whom it continues (`continues`), and the app's entry `token.unbind` names them too. How many of a binding's
   * credentials a beat ends: on a Worker, `WORKERS_BATCH` a call, as many calls as its budget allows; on Node, all.
   */
  async resumeRemovals(): Promise<{ resumed: string[]; underWay: boolean; failed: { id: string; error: string }[] }> {
    const { db, chainKey } = this.#deps;
    const resumed: string[] = [];
    // Each binding on its own (Fable on #520; reviews r12, r13): whatever goes wrong with one, a row edited around the
    // vault, a refusal, a read that fails, is its failure, reported, and the others go on, this beat and every one after.
    // Only "under way", the beat's calls spent, ends the beat.
    const failed: { id: string; error: string }[] = [];
    for (const closed of await closedBindings(db, chainKey)) {
      try {
        if (await this.#resumeOne(closed)) resumed.push(closed.id);
      } catch (error) {
        if (error instanceof RemovalUnderWay) return { resumed, underWay: true, failed };
        failed.push({ id: closed.id, error: error instanceof Error ? error.message : String(error) });
        console.error({ event: 'removal_not_resumed', binding: closed.id, error: logged(error) }, 'the scheduled run could not go on with a removal');
      }
    }
    return { resumed, underWay: false, failed };
  }

  /**
   * One binding's removal gone on with by the scheduled run: true once it ends it, false if another remover ended it
   * first. `moved`, the person's request revoking the same batch meanwhile (UnbindingRace, RevokeCAS): read again, as the
   * model's `rs` does, a few times, as `retrying` does. Anything else it throws, for `resumeRemovals` to report.
   */
  async #resumeOne(closed: BindingRow): Promise<boolean> {
    const { db } = this.#deps;
    for (let tries = 1; ; tries += 1) {
      const row = tries === 1 ? closed : await bindingRow(db, closed.principal, closed.id);
      if (row === null || row.revokedAt !== null) return false;
      // A row whose close a writer left without its remover (`closed_by` null or malformed) (review r12).
      const by = row.closedBy;
      if (by === null || !/^[a-z]+:./.test(by) || row.closedAt === null) throw new Error('its close names no remover: a row changed around coffre');
      const remover: Remover = {
        ctx: null, actor: SCHEDULE_ACTOR, via: null, actorAccess: null, connection: null,
        revokedBy: by.slice(by.indexOf(':') + 1),
        // An unbind weighs no protected environment; the policy only as its newest change stands, as the vault holds it.
        policy: { seq: (await newestVaultSeq(db, 'policy'))?.toString() ?? null, protected: [] },
        continues: { by, at: row.closedAt.getTime() },
      };
      const metadata = { bindingId: row.id, principalType: 'service', principalId: row.principal.slice('token:'.length) };
      try {
        await this.#bindingsByVault(remover, row.principal, null, null, [row], 'unbound', metadata, [{
          actorType: 'system', actorId: 'schedule', action: 'token.unbind', decision: 'allow',
          metadata: { ...metadata, reason: 'removed', removedBy: by, closedAt: row.closedAt.toISOString() },
        } as AuditEntry]);
        return true;
      } catch (error) {
        if (error instanceof ObjectMoved && tries < 3) continue;
        throw error;
      }
    }
  }

  /**
   * A CI run's ID token, for a credential of the service it names
   * (docs/design/oidc.md, section 2). Admission comes first, in the route;
   * then, in order, so that a stranger costs one bounded read at most:
   *
   * 1. the token's shape;
   * 2. the service's live bindings on its issuer, one read, which says too
   *    whether the token was spent and the newest policy change: one an
   *    older release left with its scope unsealed is none;
   * 3. its signature under that issuer's keys, then its audience, times and
   *    claims against those bindings (`verify`);
   * 4. that it is not spent yet, as that read said;
   * 5. the vault's one call (`#exchangeByVault`): the member, the binding
   *    and the token spent weighed in its statement, and the credential
   *    made, a change of the log that records the run.
   */
  async exchange(request: ExchangeRequest, meta: { requestId: string; sourceIp: string | null }): Promise<Exchanged> {
    if (inFlight >= exchangeLimit.inFlight) throw new ExchangeRefused('busy', 'too many exchanges under way: try again shortly', 429);
    inFlight++;
    try {
      return await this.#exchange(request);
    } catch (error) {
      if (error instanceof ExchangeRefused) logRefusal(error, request.service, meta.sourceIp);
      throw error;
    } finally {
      inFlight--;
    }
  }

  /**
   * Which binding of `member`, `token:<id>`, a workload's ID token matches,
   * the exchange's steps 1 to 3: its shape, the service's live bindings on
   * its issuer, then its signature under that issuer's keys, fetched or
   * carried, its audience, times and claims. Nothing written, and the token
   * not spent: whoever acts on it checks that, and spends it. Throws
   * `ExchangeRefused`, saying why as a workload's owner can act on it.
   */
  async verify(member: string, token: string): Promise<VerifiedWorkload> {
    const { db, chainKey, transport } = this.#deps;
    let decoded: DecodedToken;
    try {
      decoded = decodeWorkloadToken(token);
    } catch (error) {
      throw refused(error);
    }
    const issuer = decoded.claims.iss;
    const unbound = () => new ExchangeRefused('no_match', `no binding of ${shownMember(member)} trusts tokens from ${issuer}`);
    if (!/^token:[a-z0-9][a-z0-9._-]{0,99}$/.test(member)) throw unbound();

    // The bindings first, so that a token none can take costs this one read.
    const { bindings: loaded, spent, policySeq, newest: changes } = await exchangeCandidates(db, chainKey, member, issuer, MAX_BINDINGS, decoded.signingInputHash);
    if (loaded.length === 0 || spent === null) throw unbound();
    // Those made on this instance's URL: one made on another shadows none that was (review r1).
    const candidates = loaded.filter((binding) => madeHere(binding, this.#deps.publicUrl));
    if (candidates.length === 0) throw madeElsewhere(loaded[loaded.length - 1]!, this.#deps.publicUrl);
    // A service's bindings on one issuer share its keys; one made after the keys moved replaced the rest.
    const newest = candidates[candidates.length - 1]!;
    const expected = { issuer, audience: this.#deps.publicUrl, now: new Date() };
    let claims: Record<string, unknown>;
    try {
      claims = newest.jwks === null
        ? await verifyWithKeys(transport, newest.jwksUri, token, expected)
        // Uploaded keys: nothing to fetch, and no issuer to ask whether a token still stands, so none lives past the hour.
        : await verifyWorkloadToken(token, JSON.parse(newest.jwks) as JSONWebKeySet, { ...expected, maxLifetime: MAX_TOKEN_AGE_SECONDS });
    } catch (error) {
      if (error instanceof IssuerUnavailable) throw new ExchangeRefused('issuer_unavailable', error.message, 503, String(error.retryAfter));
      if (newest.jwks !== null && error instanceof WorkloadTokenRefused && error.reason === 'unknown_key') throw new UnknownKey(member, newest, issuer, shownKid(decoded.header));
      throw refused(error);
    }
    const binding = matching(candidates.filter((candidate) => candidate.jwksUri === newest.jwksUri), claims, member);
    return { binding, claims, token: decoded, spent, policySeq, newest: { member: changes.member, binding: changes.bindings.get(binding.id) ?? null } };
  }

  /**
   * A workload's proof, for a session bound to the key its DPoP proof
   * named (docs/design/workload-access.md, section 4.1). Admission, the
   * body, its shape and that proof come first, in the route; then, so that
   * a proof no binding can take costs one read:
   *
   * 1. the proof, by its kind (`PROOFS`), which reads the service's live
   *    bindings of its profiles once, and checks it outside any
   *    transaction;
   * 2. the binding's `sources`, a bearer token not spent yet, and the
   *    member, from the vault;
   * 3. in one transaction that holds the log's head, on database facts
   *    only: the member and the binding again, the proof
   *    spent, the proof's own commit (an enrollment's capacity), the
   *    session made and `token.exchange` logged;
   * 4. the proof's `after`, outside it.
   *
   * Its `notAfter` is the earliest of its binding's `sessionHours` and the
   * ends its proof gave; it expires `lifetimeMs` after it is made, and at
   * each renewal. One its binding has wait for approval is answered 202.
   */
  async signIn(request: SessionRequest, meta: SignInMeta): Promise<SessionIssued | SessionPending> {
    if (inFlight >= exchangeLimit.inFlight) throw new ExchangeRefused('busy', 'too many exchanges under way: try again shortly', 429);
    inFlight++;
    try {
      return await this.#signIn(request, meta);
    } catch (error) {
      if (error instanceof ExchangeRefused) logRefusal(error, request.service, meta.sourceIp);
      throw error;
    } finally {
      inFlight--;
    }
  }

  async #signIn(request: SessionRequest, meta: SignInMeta): Promise<SessionIssued | SessionPending> {
    const { db, chainKey, vault, config, publicUrl, transport } = this.#deps;
    const names = Object.keys(request.proof);
    const name = names[0] as ProofName;
    const kind = names.length === 1 && Object.hasOwn(PROOFS, name) ? PROOFS[name] : undefined;
    if (kind === undefined) throw new ExchangeRefused('malformed', `a proof is one of ${Object.keys(PROOFS).join(', ')}, by its kind: { "proof": { "oidc": "<token>" } }`);
    const member = request.service.startsWith('token:') ? request.service : `token:${request.service}`;
    const unbound = () => new ExchangeRefused('no_match', `no workload binding of ${shownMember(member)} takes this proof`);
    if (!/^token:[a-z0-9][a-z0-9._-]{0,99}$/.test(member)) throw unbound();
    const ctx: ProofContext = { db, chainKey, config, transport, publicUrl, service: member, jkt: meta.jkt, sourceIp: meta.sourceIp, requestId: meta.requestId };

    const verified = await kind.verify(request.proof[name], ctx);
    if (verified instanceof ExchangeRefused) throw verified;
    const { binding } = verified;
    if (binding.policy === null || binding.principal !== member || !kind.profiles.includes(binding.profile as WorkloadProfile)) throw unbound();
    const policy = JSON.parse(binding.policy) as BindingPolicy;
    if (config.noReads && policy.reads !== undefined) throw new ExchangeRefused('no_match', 'this instance lets no binding list reads (noReads), and this one does: bind the workload again without them');
    if (policy.sources !== undefined && (meta.sourceIp === null || !addressWithin(meta.sourceIp, policy.sources))) {
      throw new ExchangeRefused('source', meta.sourceIp === null ? 'coffre cannot tell where this request comes from, and the binding names its sources' : `${meta.sourceIp} is outside the binding's sources`);
    }
    // With 0.15's log, the vault makes the session (T149): it spends the token, and weighs the account and the binding, in
    // one call. A proof that decides in the transaction (`commit`) makes it as below.
    if (kind.commit === undefined && (await vaultMakesCredentials(vault))) {
      return this.#signInByVault(vault as CredentialsVault, { member, name, kind, verified, policy, given: request.proof[name] }, meta, ctx);
    }
    const spent = verified.spentKey;
    if (spent !== undefined && (await tokenConsumed(db, spent))) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your platform for a fresh one');
    const standing = await vault.access(member);
    if (standing.status !== 'active' || standing.generation !== binding.generation) throw unbound();
    // The environments it will reach, by path, for its answer: read before the transaction, as nothing in it decides on them.
    const known = await places(db);

    const service = member.slice('token:'.length);
    const actor = { caller: { principal: { type: 'service', id: service } }, requestId: meta.requestId, sourceIp: meta.sourceIp } as Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>;
    // The session's ends and scope, from what its proof decides under the head (`commit`), at `now`.
    const logged = await keeps015(vault);
    const shape = (committed: CommittedProof, now: number) => {
      const scope = committed.scope ?? null;
      // With 0.15's log, the scope its uses hold, its binding's reads with it, which its row then carries (`sessionScope`
      // reads the same from it): a credential's object is all its uses decide on.
      const stored = logged ? sealedSessionScope(scope, binding, policy) : scope;
      return { ...sessionEnds(kind, verified, policy, committed, now), scope, stored };
    };
    // What the proof decides under the head, as a first try takes it (nothing: the binding's), then as it decided.
    let decided: CommittedProof = {};
    /** Its `token.exchange` entry, for the session `id` the proof's decision `committed` makes, with its ends. */
    const exchanged = (id: string, committed: CommittedProof, ends: { notAfter: Date; expiresAt: Date }) => allowed(actor, 'token.exchange', {
      metadata: {
        kind: 'workload',
        credentialId: id,
        bindingId: binding.id,
        generation: binding.generation,
        proof: name,
        jkt: meta.jkt,
        expiresAt: ends.expiresAt.toISOString(),
        notAfter: ends.notAfter.toISOString(),
        ...(committed.enrollmentId === undefined ? {} : { enrollmentId: committed.enrollmentId }),
        ...(committed.pending === true ? { pending: true } : {}),
        run: runClaims(verified.claims),
      },
    });
    const made = await retrying(async () => {
    const id = randomUUID();
    const planned = shape(decided, Date.now());
    // With 0.15's log, its entry rides the session's issue, as the proof would decide it, held to that below.
    const changes = logged
      ? await AppChanges.prepare(vault, member, [credentialChange(
        null,
        { id, principal: member, kind: 'workload', scope: planned.stored, revokedAt: null, expiresAt: planned.expiresAt, notAfter: planned.notAfter, generation: binding.generation },
        entryOf({ credentialId: null }, exchanged(id, decided, planned)),
      )])
      : null;
    return audited(this.#deps, async (tx, log) => {
      const now = new Date();
      // The binding's scope, read before, is not read again: nothing writes it after its insert, and its MAC, checked here, covers it.
      if (!(await stillMember(tx, member, standing)) || (await standingBinding(tx, chainKey, binding.id, member, binding.generation)) === null) throw unbound();
      if (spent !== undefined && !(await consumeToken(tx, spent))) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your platform for a fresh one');
      const committed = kind.commit === undefined ? {} : await kind.commit(tx, verified, ctx);
      if (committed instanceof ExchangeRefused) throw committed;
      // The change was sealed for what the proof would decide: decided otherwise (an enrollment's scope and end), made again with it.
      // Its enrollment and approval too, which its carried entry names.
      if (changes !== null && ((committed.scope ?? null) !== (decided.scope ?? null) || committed.notAfter?.getTime() !== decided.notAfter?.getTime()
        || committed.enrollmentId !== decided.enrollmentId || committed.pending !== decided.pending)) {
        decided = committed;
        throw new ObjectMoved();
      }
      const { notAfter, expiresAt, scope, stored } = changes !== null ? planned : shape(committed, now.getTime());
      if (notAfter.getTime() <= now.getTime()) throw new ExchangeRefused('expired', 'the proof has expired');
      const reached = environmentsOf(readScope(scope ?? binding.scope) ?? [], known);
      const token = generateToken('workload');
      await insertSession(tx, chainKey, {
        id,
        kind: 'workload',
        tokenHash: hashToken(token),
        tokenHint: tokenHint(token),
        generation: binding.generation,
        principal: member,
        identityId: null,
        // A copy of the binding's label, however long an Owner made it: accepted (`exchangedCredential`).
        label: binding.label,
        createdBy: issuedBy(binding.id),
        expiresAt,
        revokedAt: null,
        scope: stored,
        // Where `/use/<credential>` goes when it names no environment: the one it reaches, if one.
        places: JSON.stringify(reached.map(({ id: environmentId }) => ({ environmentId, personal: false }))),
        jkt: meta.jkt,
        notAfter,
        ancestors: null,
        constraints: null,
        enrollmentId: committed.enrollmentId ?? null,
        approvedAt: null,
        approvedBy: null,
      });
      await update(tx, serviceBindings, { id: binding.id }, { lastUsedAt: now });
      // Without 0.15's log, no change carries it.
      if (changes === null) log.push(exchanged(id, committed, { notAfter, expiresAt }));
      return { id, token, expiresAt, notAfter, committed, reached };
    }, changes);
    });
    if (kind.after !== undefined) {
      // The session is made: what runs after it never unmakes it.
      await kind.after({ verified, committed: made.committed, sessionId: made.id }, ctx).catch((error: unknown) => console.error('a proof\'s after-exchange hook failed', error));
    }
    if (made.committed.pending === true) return { pending: made.id, approve: `${publicUrl}/members/${encodeURIComponent(member)}` };
    return { token: made.token, tokenType: 'DPoP', expiresAt: made.expiresAt.toISOString(), notAfter: made.notAfter.toISOString(), places: made.reached.map(({ path }) => path) };
  }

  /**
   * `#signIn` with 0.15's log, for a proof that decides nothing in a
   * transaction (oidc, aws): the vault makes the session (T149), in one
   * call. Its binding as read here, its account and the token spent once are weighed in the vault's statement, under their
   * rows' locks; no 0.14 head, and no `token.exchange` entry: its change
   * records the run (D147). The environments it reaches are read first, for
   * its row and its answer, as nothing the vault decides is made of them.
   */
  async #signInByVault(
    vault: CredentialsVault,
    proof: { member: string; name: ProofName; kind: ProofKind; verified: MatchedProof; policy: BindingPolicy; given: unknown },
    meta: SignInMeta,
    ctx: ProofContext,
  ): Promise<SessionIssued> {
    const { member, name, kind, verified, policy, given } = proof;
    const { binding } = verified;
    if (!madeHere(binding, this.#deps.publicUrl)) throw madeElsewhere(binding, this.#deps.publicUrl);
    const known = await places(this.#deps.db);
    const now = Date.now();
    const { notAfter, expiresAt } = sessionEnds(kind, verified, policy, {}, now);
    const scope = sealedSessionScope(null, binding, policy);
    const reached = environmentsOf(readScope(binding.scope) ?? [], known);
    const token = generateToken('workload');
    const row = signedSession(this.#deps.chainKey, {
      id: randomUUID(), kind: 'workload', tokenHash: hashToken(token), tokenHint: tokenHint(token), generation: binding.generation, principal: member,
      identityId: null, label: binding.label, createdBy: issuedBy(binding.id), expiresAt, revokedAt: null, scope,
      // Where `/use/<credential>` goes when it names no environment: the one it reaches, if one.
      places: JSON.stringify(reached.map(({ id: environmentId }) => ({ environmentId, personal: false }))),
      jkt: meta.jkt, notAfter, ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null,
    });
    const outcome = await vault.signIn({
      principal: member,
      binding: sealedBinding(binding, this.#deps.publicUrl),
      credential: signedInCredential(row),
      appKey: appLogKey(this.#deps.chainKey).keyId,
      spent: verified.spentKey?.toString('base64') ?? null,
      // Its proof's end is the session's hard end, held to in the statement.
      validUntil: null,
      record: { proof: name, issuer: binding.issuer, run: runClaims(verified.claims) },
      // The session's key, by the DPoP proof it signed, and the token where its binding carries its issuer's keys: the
      // vault's to verify (D148, PR 3b). A token of keys its issuer publishes, and a proof that is no ID token (an AWS
      // signed request), are the app's alone, so a compromised app could make sessions of such a binding's.
      idToken: vaultVerifies(binding) ? { token: given as string, jwks: binding.jwks! } : null,
      dpop: meta.dpop,
      // The account's and the binding's newest changes, as its proof's read found them: the vault checks and pins them (T192).
      ...(verified.newest === undefined ? {} : { newest: verified.newest }),
    });
    if (!outcome.ok) {
      if (outcome.refused === 'proof') throw proofRefusal(outcome, member, binding);
      throw signInRefusal(outcome.refused, {
        unbound: `no workload binding of ${shownMember(member)} takes this proof`,
        replayed: 'this token was exchanged already: ask your platform for a fresh one',
        expired: 'the proof has expired',
      });
    }
    if (kind.after !== undefined) {
      // The session is made: what runs after it never unmakes it.
      await kind.after({ verified, committed: {}, sessionId: row.id }, ctx).catch((error: unknown) => console.error('a proof\'s after-exchange hook failed', error));
    }
    return { token, tokenType: 'DPoP', expiresAt: expiresAt.toISOString(), notAfter: notAfter.toISOString(), places: reached.map(({ path }) => path) };
  }

  /**
   * Move a session's expiry on, by a proof of its key (section 5.4): to
   * `lifetimeMs` past the database's clock, never past its `notAfter`. Two
   * steps, as the app computes the row's MAC: the clock read, then an
   * update that holds only while the row is as it was read and more than a
   * few seconds from its end (`renewSession`), so a renewal that lost a race
   * or came late revives nothing. The proof's own check runs in the same
   * transaction, its `after` outside it. No entry of its own: the session's
   * last use shows it.
   */
  async renew(session: { row: WorkloadSession; binding: BindingRow }, meta: { requestId: string; sourceIp: string | null }): Promise<{ expiresAt: string }> {
    const { db, chainKey, config, publicUrl, transport } = this.#deps;
    const { row, binding } = session;
    const proof = proofOf(binding.profile);
    if (proof === null) throw new ExchangeRefused('no_match', 'this release renews no session of this binding\'s profile');
    const { kind } = proof;
    // With 0.15's log, the end it moves to is a change, sealed before the transaction, from the database's clock read
    // before it: in `audited`, whose head comes before the row, as every change of the app's takes them (AppHeadFirst).
    const logged = await keeps015(this.#deps.vault);
    const expiresAt = await retrying(async () => {
      const planned = logged ? Math.min((await databaseNow(db)) + kind.lifetimeMs, row.notAfter!.getTime()) : null;
      const changes = planned === null || planned <= row.expiresAt.getTime()
        ? null
        : await AppChanges.prepare(this.#deps.vault, row.principal, [credentialChange(row, { ...row, expiresAt: new Date(planned) }, null)]);
      const renew = async (tx: Transaction) => {
        const refusal = kind.renew === undefined ? null : await kind.renew.check(tx, row);
        if (refusal !== null) throw refusal;
        const until = async () => Math.min((await databaseNow(tx)) + kind.lifetimeMs, row.notAfter!.getTime());
        const next = planned ?? (await until());
        if (next <= row.expiresAt.getTime()) {
          // Planned before a wait for the head, an end that would move now is made again from now (`retrying`).
          if (planned !== null && (await until()) > row.expiresAt.getTime()) throw new ObjectMoved();
          // At its hard end already: nothing to move, and nothing revived.
          return row.expiresAt;
        }
        if (!(await renewSession(tx, chainKey, row, new Date(next)))) {
          throw new ExchangeRefused('expired', 'the session ended, or was renewed or revoked meanwhile: sign in again');
        }
        return new Date(next);
      };
      return logged ? audited(this.#deps, renew, changes) : db.transaction(renew);
    });
    if (kind.renew !== undefined) {
      const ctx: ProofContext = { db, chainKey, config, transport, publicUrl, service: row.principal, jkt: row.jkt!, sourceIp: meta.sourceIp, requestId: meta.requestId };
      await kind.renew.after({ ...row, expiresAt }, ctx).catch((error: unknown) => console.error('a proof\'s after-renewal hook failed', error));
    }
    return { expiresAt: expiresAt.toISOString() };
  }

  async #exchange(request: ExchangeRequest): Promise<Exchanged> {
    const { vault } = this.#deps;
    const member = request.service;
    const { binding, claims, token: decoded, spent, newest } = await this.verify(member, request.token);

    if (spent) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your CI for a fresh one');
    // The vault makes it: one call, no 0.14 head. Every sign-in through a binding goes there, so that each one's
    // rate is counted under its row.
    if (!(await vaultMakesCredentials(vault))) throw new Error("this vault makes no credential: coffre needs one that keeps 0.15's log");
    return this.#exchangeByVault(vault as CredentialsVault, member, binding, claims, request.token, decoded, newest);
  }

  /**
   * `#exchange` with 0.15's log: the vault makes the credential (T149), in
   * one call. The binding as read here, the account active at its
   * generation and the token spent once are weighed in
   * its statement, on their rows, under their locks (formal/Lifecycle.tla's
   * BindingLocked, MemberLocked, SpentChecked); no 0.14 head, and no
   * `token.exchange` entry: its change records the run (D147). Through a
   * binding of uploaded keys, the token goes with it, and the vault verifies
   * it again on the binding it sealed (D148, PR 3b): what decides is its
   * check, the app's a filter. Of keys its issuer publishes, the app's
   * check decides: the vault fetches nothing.
   */
  async #exchangeByVault(
    vault: CredentialsVault, member: string, binding: BindingRow, claims: Record<string, unknown>, token: string, decoded: DecodedToken, newest: SignInInput['newest'] | null,
  ): Promise<Exchanged> {
    const issuer = decoded.claims.iss;
    if (!madeHere(binding, this.#deps.publicUrl)) throw madeElsewhere(binding, this.#deps.publicUrl);
    const { row, issued } = this.#deps.signin.exchangedCredential(member.slice('token:'.length), {
      generation: binding.generation, bindingId: binding.id, label: binding.label, expiresAt: new Date(Date.now() + EXCHANGED_CREDENTIAL_MS), stored: binding.scope,
    });
    const outcome = await vault.signIn({
      principal: member,
      binding: sealedBinding(binding, this.#deps.publicUrl),
      credential: signedInCredential({ ...row, kind: 'service' }),
      appKey: appLogKey(this.#deps.chainKey).keyId,
      spent: decoded.signingInputHash.toString('base64'),
      // The token's times, held to again in the statement, as the commit under 0.14's head holds them: its `exp`, and its `iat`'s hour.
      // Whole ms, down: a token's times may be fractional seconds, which the checks before took.
      validUntil: Math.floor(Math.min((decoded.claims.exp + CLOCK_TOLERANCE_SECONDS) * 1000, (decoded.claims.iat + MAX_TOKEN_AGE_SECONDS) * 1000)),
      record: { proof: 'oidc', issuer, run: runClaims(claims) },
      idToken: vaultVerifies(binding) ? { token, jwks: binding.jwks! } : null,
      dpop: null,
      // The account's and the binding's newest changes, read beside it: the vault checks and pins them, one statement (T192).
      ...(newest == null ? {} : { newest }),
    });
    if (!outcome.ok) {
      if (outcome.refused === 'proof') throw proofRefusal(outcome, member, binding);
      // Past its times by the statement: which of them, as the commit under the head says it.
      const issued = outcome.refused === 'expired' ? issuedRefusal(decoded.claims.iat, Date.now() / 1000) : null;
      if (issued !== null) throw refused(issued);
      throw signInRefusal(outcome.refused, {
        unbound: `no binding of ${shownMember(member)} trusts tokens from ${issuer}`,
        replayed: 'this token was exchanged already: ask your CI for a fresh one',
        expired: 'the token has expired',
      });
    }
    return { token: issued.token, expiresAt: issued.expiresAt };
  }
}


/**
 * A session's ends at `now`: its hard end the earliest of its binding's
 * `sessionHours`, where its profile has them, and every end its proof gave
 * (24 hours if none did); its expiry `lifetimeMs` on, never past that.
 */
function sessionEnds(kind: ProofKind, verified: MatchedProof, policy: BindingPolicy, committed: CommittedProof, now: number): { notAfter: Date; expiresAt: Date } {
  const hours = POLICY_FIELDS[verified.binding.profile as WorkloadProfile].includes('sessionHours') ? policy.sessionHours ?? POLICY_DEFAULTS.sessionHours : null;
  const ends = [hours === null ? null : now + hours * 3_600_000, verified.notAfter?.getTime() ?? null, committed.notAfter?.getTime() ?? null]
    .filter((end): end is number => end !== null);
  const notAfter = new Date(Math.min(...(ends.length === 0 ? [now + POLICY_DEFAULTS.sessionHours * 3_600_000] : ends)));
  return { notAfter, expiresAt: new Date(Math.min(now + kind.lifetimeMs, notAfter.getTime())) };
}

/** A sign-in's row as the vault takes it (`SignInCredential`): its bytes in base64, its times in ms. */
function signedInCredential(row: {
  id: string; kind: 'service' | 'workload'; tokenHash: Buffer; tokenHint: string; label?: string | null; scope?: string | null; places?: string | null;
  expiresAt: Date; notAfter?: Date | null; jkt?: string | null; authMac: Buffer;
}): SignInCredential {
  return {
    id: row.id, kind: row.kind, tokenHash: row.tokenHash.toString('base64'), tokenHint: row.tokenHint, label: row.label ?? null,
    scope: row.scope ?? null, places: row.places ?? null, expiresAt: row.expiresAt.getTime(), notAfter: row.notAfter?.getTime() ?? null,
    jkt: row.jkt ?? null, authMac: row.authMac.toString('base64'),
  };
}

/** A sign-in the vault refused, as the workload's owner reads it: today's codes and words, each path its own. */
function signInRefusal(refused: Exclude<SignInRefusal, 'proof'>, words: Record<Exclude<SignInRefusal, 'retired' | 'unsealed' | 'proof' | 'busy'>, string>): ExchangeRefused {
  switch (refused) {
    // An instance under an app key the log moved on from, as for the seconds a deploy takes: 503, as its append would answer.
    case 'retired': throw new KeyRetired('the app\'s key is one it rotated from: a newer deployment replaces this one');
    case 'unbound': return new ExchangeRefused('no_match', words.unbound);
    // A lock the statement did not have within its `lock_timeout` (an unbind of the binding, a removal of the account):
    // nothing counts a binding's sign-ins (W331, D177), so this is a moment's wait, asked again in a second.
    case 'busy': return new ExchangeRefused('busy', 'coffre is busy: try again shortly', 503, '1');
    case 'replayed': return new ExchangeRefused('replayed', words.replayed);
    case 'expired': return new ExchangeRefused('expired', words.expired);
    // Made before the vault sealed bindings, or changed around it: a manager binds it again (PR 3a).
    case 'unsealed': return new ExchangeRefused('unsealed', 'this binding is none the vault sealed, made before it sealed them or changed since: bind it again');
    // A code this app does not know, from a vault of another release (its answer is SQL's JSON, cast): a failure, never a sign-in.
    default: throw new Error(`the vault refused a sign-in for a reason this app does not know: ${String(refused)}`);
  }
}

/**
 * Whether the vault verifies a sign-in's token through this binding itself
 * (PR 3b): when it carries its issuer's keys, uploaded with it, which its
 * seal digests. The vault asks no issuer for keys, so the tokens
 * of an issuer that publishes its keys are the app's to verify.
 */
function vaultVerifies(binding: BindingRow): boolean {
  return binding.jwksUri.startsWith(UPLOADED_KEYS) && binding.jwks !== null;
}

/**
 * Whether a binding was made on this instance's public URL, as its row's
 * sealed origin says, or before the column (PR 3b). One made on another
 * takes no token for this one: its runs ask for the URL it was made on.
 * Matching skips it, in every proof's flow, so that it shadows no binding
 * made here (reviews r1, r2). The column is not under the row's MAC: what
 * holds it is the vault's seal, which refuses a binding whose origin moved
 * (`unsealed`), so this filter only picks among bindings, never admits one.
 */
export function madeHere(binding: Pick<BindingRow, 'origin'>, publicUrl: string): boolean {
  return binding.origin === null || binding.origin === publicUrl;
}

/** The refusal of a token none of whose bindings was made on this instance's URL. */
export function madeElsewhere(binding: Pick<BindingRow, 'origin'>, publicUrl: string): ExchangeRefused {
  return new ExchangeRefused('audience', `the binding was made on ${binding.origin}, and takes no token for ${publicUrl}: bind it again here`);
}

/** The reasons the vault's check of a proof gives that the app's own gives too (`verifyRunToken`, PR 3b). */
const PROOF_REASONS: ReadonlySet<string> = new Set<ExchangeReason>([
  'malformed', 'no_match', 'signature', 'unknown_key', 'expired', 'too_old', 'too_long', 'not_yet_valid', 'audience', 'dpop',
]);

/**
 * A proof the vault refused, as the app's own check words it: a key a
 * service's uploaded keys lack alerts (`UnknownKey`), and keys that are not
 * the ones its binding's seal digests, a row changed around the vault, are
 * a binding to make again.
 */
function proofRefusal(outcome: Extract<SignInOutcome, { refused: 'proof' }>, member: string, binding: BindingRow): ExchangeRefused {
  const { reason, message, kid } = outcome;
  if (reason === 'unknown_key' && binding.jwks !== null) return new UnknownKey(member, binding, binding.issuer, kid);
  if (reason === 'keys') return new ExchangeRefused('unsealed', `${message}: bind it again`);
  return new ExchangeRefused(PROOF_REASONS.has(reason) ? (reason as ExchangeReason) : 'malformed', message);
}

/** An uploaded key set, checked (`uploadedKeys`), or a 400 saying what is wrong with it. */
async function keysOf(jwks: JSONWebKeySet): Promise<UploadedKeys> {
  try {
    return await uploadedKeys(jwks);
  } catch (error) {
    if (error instanceof KeysInvalid) throw badRequest(error.message);
    throw error;
  }
}

/** GitHub not answering the app, or refusing it, as the API answers it: 503, saying which. */
async function unavailable<T>(ask: () => Promise<T>): Promise<T> {
  try {
    return await ask();
  } catch (error) {
    if (error instanceof GitHubAppUnavailable) throw new ApiError('unavailable', `${error.message}; type its IDs meanwhile`);
    throw error;
  }
}

/** A token refused on its own terms, as an exchange answers it. */
function refused(error: unknown): ExchangeRefused {
  if (error instanceof WorkloadTokenRefused) return new ExchangeRefused(error.reason, error.message);
  throw error;
}

/**
 * The binding whose every claim the token carries (`differingClaims`). None:
 * the claims that differ from the closest binding, by name, never the
 * values it expects.
 */
function matching(bindings: BindingRow[], claims: Record<string, unknown>, member: string): BindingRow {
  let closest: string[] | null = null;
  for (const binding of bindings) {
    const differ = differingClaims(binding.profile as WorkloadProfile, JSON.parse(binding.claims) as BindingClaims, claims);
    if (differ.length === 0) return binding;
    if (closest === null || differ.length < closest.length) closest = differ;
  }
  throw new ExchangeRefused('no_match', `no binding of ${shownMember(member)} trusts these claims: ${(closest ?? []).join(', ')} differ`);
}

/** One line per reason and service a minute, in this isolate: enough to see a refusal, not a flood. An unknown key's names its issuer and key. */
function logRefusal(error: ExchangeRefused, service: string, sourceIp: string | null): void {
  const key = `${error.reason} ${String(service).slice(0, 120)}`;
  const now = Date.now();
  if ((refusalsLogged.get(key) ?? 0) > now - REFUSAL_LOG_MS) return;
  refusalsLogged.set(key, now);
  if (refusalsLogged.size > 1000) refusalsLogged.delete(refusalsLogged.keys().next().value!);
  const named = error instanceof UnknownKey ? { issuer: error.issuer, kid: error.kid } : {};
  console.error({ event: 'workload_exchange_refused', reason: error.reason, service: key.slice(error.reason.length + 1), sourceIp, ...named }, error.message);
}

/** The member still stands where `standing` said, read under the log's head (`#stillMember` in signin.ts). */
async function stillMember(tx: Transaction, member: string, standing: Access): Promise<boolean> {
  const row = await memberStanding(tx, member);
  return row !== null && row.generation === standing.generation && row.status === 'active';
}

/** A binding's `reads` as the API names them (section 6.1): each environment by path, its keys by name, or `'*'` for every one. */
export type ReadsByPath = Record<string, readonly string[] | '*'>;

/** A binding's policy as the API shows it: as stored, but its `reads` by path and name. */
export type PolicyView = Omit<BindingPolicy, 'reads'> & { reads?: ReadsByPath };

/** One environment of a binding's `reads`, found as it is now: its ID, path and project, and its keys, each found, or `'*'`. */
type ResolvedRead = { environmentId: string; path: string; projectId: string; keys: '*' | { id: string; key: string; sensitive: boolean }[] };

/** A policy's check, a refusal as a 400. */
function checked<T>(check: () => T): T {
  try {
    return check();
  } catch (error) {
    if (error instanceof BindingInvalid) throw badRequest(error.message);
    throw error;
  }
}

/**
 * `reads` as asked, by path and name, each environment and key found as it
 * is now: an environment that is not there, or a key it does not hold, is
 * refused by name, since listing a key needs the key to exist. A
 * reference held there is listed as any key it holds, by its own ID, which
 * is what the vault checks `reads` against (R71), and is as sensitive as its
 * source is now (R23).
 */
async function resolveReads(db: Queryable, wanted: unknown): Promise<ResolvedRead[]> {
  if (typeof wanted !== 'object' || wanted === null || Array.isArray(wanted)) throw badRequest('reads maps each environment, by path, to its key names or "*"');
  const entries = Object.entries(wanted as Record<string, unknown>);
  const known = await places(db);
  const resolved: ResolvedRead[] = [];
  for (const [path, keys] of entries) {
    if (keys !== '*' && !(Array.isArray(keys) && keys.every((key) => typeof key === 'string'))) {
      throw badRequest(`reads lists ${path}'s keys by name, or "*" for every one`);
    }
    const at = parsePath(path, [2]);
    const project = known.find((candidate) => candidate.slug === at.project);
    const environment = project?.environments.find((candidate) => candidate.slug === at.environment && candidate.owner === null);
    if (project === undefined || environment === undefined) throw notFound(`reads names ${path}, which is no environment`);
    if (keys === '*') {
      resolved.push({ environmentId: environment.id, path: `${project.slug}/${environment.slug}`, projectId: project.id, keys });
      continue;
    }
    const names = [...new Set(keys as string[])];
    const live = (await secretHeads(db, environment.id, { keys: names })).filter((row) => row.archivedAt === null);
    // A key with no value of its own holds one through its reference while that reads (`live`: not ended, broken
    // included, by the vault's `reference.end` under either log), of its source's nature now (R23).
    const references = await currentReferences(db, live.filter((row) => row.current === null).map((row) => row.id));
    const sourceOf = (id: string) => {
      const reference = references.get(id);
      return reference?.state === 'live' ? reference.source!.currentVersionId! : undefined;
    };
    const sensitiveSources = await sensitiveVersions(db, live.flatMap((row) => sourceOf(row.id) ?? []));
    const held = live.flatMap((row) => {
      const source = sourceOf(row.id);
      const sensitive = row.current?.sensitive ?? (source === undefined ? undefined : sensitiveSources.has(source));
      return sensitive === undefined ? [] : [{ id: row.id, key: row.key, sensitive }];
    });
    // By a set of what it holds, not each name against every row: both as long as a body and an environment let them be.
    const holds = new Set(held.map((row) => row.key));
    const missing = names.filter((name) => !holds.has(name));
    if (missing.length > 0) throw badRequest(`reads lists keys ${path} does not hold: ${missing.join(', ')}`);
    resolved.push({ environmentId: environment.id, path: `${project.slug}/${environment.slug}`, projectId: project.id, keys: held });
  }
  return resolved;
}

/** `reads` as the policy stores them, by environment and key ID, sorted, as `checkPolicy` keeps them. */
function readsById(reads: readonly ResolvedRead[]): NonNullable<BindingPolicy['reads']> {
  return Object.fromEntries(reads.map((read) => [read.environmentId, { keys: read.keys === '*' ? '*' as const : read.keys.map((key) => key.id).sort() }]));
}

/** A policy about to be stored, shown with its `reads` by path and name, as asked. */
function shownPolicy(policy: BindingPolicy, reads: readonly ResolvedRead[]): PolicyView {
  const { reads: _, ...rest } = policy;
  if (reads.length === 0) return rest;
  return { ...rest, reads: Object.fromEntries(reads.map((read) => [read.path, read.keys === '*' ? '*' : read.keys.map((key) => key.key).sort()])) };
}

/** A stored policy shown with its `reads` by path and name, as they are named now; one deleted, by its ID. */
function namedPolicy(policy: BindingPolicy, known: readonly PlaceRow[], named: ReadonlyMap<string, string>): PolicyView {
  const { reads, ...rest } = policy;
  if (reads === undefined) return rest;
  const pathOf = (id: string) => {
    for (const project of known) {
      const environment = project.environments.find((candidate) => candidate.id === id);
      if (environment !== undefined) return `${project.slug}/${environment.slug}`;
    }
    return id;
  };
  return {
    ...rest,
    reads: Object.fromEntries(Object.entries(reads).flatMap(([id, { keys }]) => (keys === undefined ? [] : [[pathOf(id), keys === '*' ? '*' : keys.map((key) => named.get(key) ?? key).sort()]]))),
  };
}

/**
 * A binding's scope with its `reads` checked against it (section 6.1):
 * each environment listed is one the scope reaches, and a sensitive key
 * listed only where its grant reads sensitive values, which an Owner of its
 * project alone gives (R32). Each such environment gets a grant of its
 * own, the project's that covers it as it holds in an environment (union
 * semantics make it no wider), so a session's `reads` attach to its grant
 * by ID with nothing to look up (`sessionScope`).
 */
function readsScope(ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>, scope: CredentialScope, reads: readonly ResolvedRead[], details: Record<string, unknown>): CredentialScope {
  for (const read of reads) {
    const covering = scope.find((grant) => grant.environmentId === read.environmentId)
      ?? scope.find((grant) => grant.environmentId === null && grant.projectId === read.projectId);
    if (covering === undefined) throw badRequest(`reads names ${read.path}, which the binding's scope does not reach`);
    const sensitive = read.keys === '*' ? [] : read.keys.filter((key) => key.sensitive);
    if (sensitive.length > 0 && covering.sensitive !== true) {
      throw new Refusal(
        forbidden(`only an Owner of ${read.path.split('/')[0]} lets a service read its sensitive values (R32): ${sensitive.map((key) => key.key).join(', ')}`),
        denied(ctx, 'token.bind', 'sensitive_read', { metadata: { ...details, path: read.path, keys: sensitive.map((key) => key.key) } }),
      );
    }
  }
  // Each listed environment a grant of its own, the project's share there where only the project's reached it; the lists themselves are each request's.
  const grants = scopeWithReads(scope, readsById(reads), new Map(reads.map((read) => [read.environmentId, read.projectId]))).map(({ reads: _, ...grant }) => grant);
  if (!isCredentialScope(grants)) throw new Error('a binding\'s reads made a scope that does not hold');
  return grants;
}

/**
 * The environments a scope reaches, by ID and path, as a handle's places:
 * each of its environments, and each environment of its projects but
 * personal configs, which no service reads. Each once, by path.
 */
export function environmentsOf(scope: CredentialScope, known: readonly PlaceRow[]): { id: string; path: string }[] {
  const reached = new Map<string, string>();
  for (const grant of scope) {
    const project = known.find((candidate) => candidate.id === grant.projectId);
    for (const environment of project?.environments ?? []) {
      if (environment.owner !== null || (grant.environmentId !== null && environment.id !== grant.environmentId)) continue;
      reached.set(environment.id, `${project!.slug}/${environment.slug}`);
    }
  }
  return [...reached].map(([id, path]) => ({ id, path })).sort((a, b) => (a.path < b.path ? -1 : 1));
}

/** A binding as an owner sees it: its policy shown as the caller names it (`namedPolicy`, `shownPolicy`). */
function view(row: Omit<BindingRow, 'origin'>, scope: ScopeByPath | null, policy: PolicyView | null): BindingView {
  return {
    id: row.id,
    profile: row.profile as WorkloadProfile,
    issuer: row.issuer,
    jwksUri: row.jwksUri,
    keys: row.jwks === null ? null : keySummaries(row.jwks),
    claims: JSON.parse(row.claims) as BindingClaims,
    scope,
    policy,
    label: row.label,
    createdAt: row.createdAt.toISOString(),
    createdBy: row.createdBy,
    lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
    removing: row.closedAt === null ? null : { since: row.closedAt.toISOString(), by: row.closedBy },
  };
}
