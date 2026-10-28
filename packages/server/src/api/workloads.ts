import { randomUUID } from 'node:crypto';

import { isCredentialScope, scopeWithReads, sealedSessionScope, type CredentialScope } from '@coffre/core/access';
import {
  addressWithin,
  BindingInvalid,
  canonicalClaims,
  claimAt,
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
  MAX_READ_KEYS,
  MAX_READ_PLACES,
  MAX_TOKEN_AGE_SECONDS,
  OIDC_PROFILES,
  POLICY_DEFAULTS,
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
import type { Access, SignInCredential, SignInRefusal, Vault } from '@coffre/core/vault';
import type { Database, Queryable, Transaction } from '@coffre/db';
import { KeyRetired } from '@coffre/db/log';
import { serviceBindings, type credentials } from '@coffre/db/schema';

import { issuedBy } from '../auth-rows.ts';
import { appLogKey } from '../db/audit.ts';
import {
  consumeToken,
  exchangeCandidates,
  exchangesSince,
  exchangeStill,
  exchangeToken,
  findBinding,
  insertBinding,
  liveBindings,
  memberStanding,
  places,
  liveCredentialsOf,
  liveCredentialsWhere,
  revokeLiveCredentials,
  secretHeads,
  standingBinding,
  tokenConsumed,
  update,
  updateAuth,
  type BindingRow,
  type PlaceRow,
} from '../db/queries.ts';
import { databaseNow, frozenTargets, insertSession, keyNames, renewSession, signedSession, workloadCandidates } from '../db/workloads.ts';
import { awsProof } from '../workloads/aws.ts';
import { discoverKeys, DiscoveryFailed } from '../workloads/discovery.ts';
import { expectedAudiences, PROFILE_RULES } from '../workloads/profiles.ts';
import { IssuerUnavailable, verifyWithKeys } from '../workloads/keys.ts';
import { FetchRefused, type WorkloadTransport } from '../workloads/transport.ts';
import { newestPolicySeq } from './caller.ts';
import { AppChanges, credentialChange, keeps015, ObjectMoved, retrying, revokes, vaultMakesCredentials, type CredentialsVault } from './changes.ts';
import type { Asker, SigninService } from './signin.ts';
import { allowed, audited, credentialStill, denied, Refusal, withRefusals, type ApiContext } from './context.ts';
import {
  inheritedScope,
  issuedScope,
  issuerNow,
  issuerStill,
  managedAccount,
  notManager,
  parseScope,
  readScope,
  scopeByPath,
  sealCredentials,
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
  // address outside the binding's `sources` or none to check, an older enrollment code, a freeze, a code at capacity.
  | 'dpop'
  | 'source'
  | 'superseded'
  | 'frozen'
  | 'full';

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
  /** When to come back, in seconds, where something sets it: an issuer's keys not fetched again for a minute. */
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
  /** What spending it records in `consumed_tokens`, for a bearer proof; none for one that names the key or repeats (section 4.1). */
  spentKey?: Buffer;
  /** A bearer token's own `exp`, which ends the session it makes (section 5.4). */
  notAfter?: Date;
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

/** How long a session lives past each renewal, unless its proof says less: an hour (section 5.4). */
export const SESSION_MS = 60 * 60 * 1000;

/** The audience a token names, alone; null for none, or several. */
function soleAudience(aud: unknown): string | null {
  if (typeof aud === 'string') return aud;
  return Array.isArray(aud) && aud.length === 1 && typeof aud[0] === 'string' ? aud[0] : null;
}

/**
 * `oidc`: a platform's ID token (section 4.2), matched against the
 * service's bindings of the ID-token profiles that carry a policy, by the
 * explicit profile list, so a binding of another proof's never matches.
 * The token's audience is held to its binding's: the key's (`keyAudience`),
 * a fixed one (Azure's), or the instance's. What is spent follows section
 * 4.1's rule: a token that names the key, or one its platform hands out
 * again (`REPEATING_PROFILES`), never; any other once, in
 * `consumed_tokens`. A token that does not name the key ends the session it
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
    const candidates = await workloadCandidates(ctx.db, ctx.chainKey, ctx.service, issuer, OIDC_PROFILES, MAX_BINDINGS);
    if (candidates.length === 0) return unbound;
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
      // Its keys are not fetched again for a minute (`workloads/keys.ts`): no sooner is any use.
      if (error instanceof IssuerUnavailable) return new ExchangeRefused('issuer_unavailable', error.message, 503, '60');
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

/** A session made: its token, sent with the key's proof; its expiry and hard end; the environments it reaches, by path. */
export type SessionIssued = { token: string; tokenType: 'DPoP'; expiresAt: string; notAfter: string; places: string[] };

/** A session made that waits for a person's approval (section 4.4): its ID, and the page that approves it. */
export type SessionPending = { pending: string; approve: string };

/** How long a credential an exchange issues lives: one `coffre run` needs it for seconds. */
export const EXCHANGED_CREDENTIAL_MS = 5 * 60 * 1000;
/** How many credentials one binding issues a minute, counted under its row (with 0.14's log, under the log's head). */
export const EXCHANGES_PER_BINDING_MINUTE = 60;
/**
 * Exchanges under way at once in this isolate or process, at most: past it,
 * 429 at once (R44). Its one writer is packages/server/test/bench/ci.ts,
 * whose one process stands in for the many isolates a burst spreads over.
 */
export const exchangeLimit = { inFlight: 32 };
let inFlight = 0;

/**
 * The claims of the run a credential was issued for, as the issuer
 * asserted them: in the exchange's entry, so that a read leads back to
 * its run. What the issuer says, not proof of which run sent the request.
 */
const RUN_CLAIMS = [
  'sub', 'jti', 'actor', 'event_name', 'ref', 'base_ref', 'head_ref', 'sha', 'repository', 'repository_id', 'run_id', 'run_attempt',
  'workflow_ref', 'job_workflow_ref', 'job_workflow_sha', 'environment',
  'project_path', 'project_id', 'namespace_id', 'pipeline_id', 'pipeline_source', 'job_id',
  'kubernetes.io.pod.name',
] as const;
const MAX_RUN_CLAIM = 256;

/** A binding's `jwks_uri` when it carries its issuer's keys: the SHA-256 of those keys (`UploadedKeys`), where a fetched set's URL would be. */
const UPLOADED = 'sha256:';

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
 * whoever acts on it spends it (`exchangeToken`). Read with the bindings,
 * whether it was spent already, and the newest policy change, for the
 * vault's answer about the service that follows (`exchangeCandidates`).
 */
export type VerifiedWorkload = { binding: BindingRow; claims: Record<string, unknown>; token: DecodedToken; spent: boolean; policySeq: bigint | null };

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

  constructor(deps: WorkloadServiceDeps) {
    this.#deps = deps;
  }

  /** The two limits every exchange passes first (`exchangeWorkloadToken` in auth-routes.ts). */
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
   * A service's live bindings, those an older release made sealed first
   * (`sealCredentials`), as a request's own credential check seals them:
   * one that inherits their scope keeps what their issuer could give,
   * sensitive values included, never less than the seal would say. A dry
   * run seals nothing, as it writes nothing: its plan inherits their
   * scopes as read, and one a release before 0.11 made reads no sensitive
   * value there, so the plan may withhold more than the binding will.
   */
  async #sealedBindings(member: string, generation: number, { dryRun }: { dryRun: boolean }): Promise<BindingRow[]> {
    const { db, chainKey, vault } = this.#deps;
    const live = await liveBindings(db, chainKey, member, generation);
    const unsealed = live.filter((row) => unsealedScope(row.scope));
    if (dryRun || unsealed.length === 0) return live;
    const policySeq = await newestPolicySeq(db);
    const access = await vault.access(member);
    if (access.status !== 'active') return live;
    await sealCredentials(db, chainKey, vault, access, policySeq, unsealed.map((row) => ({ kind: 'binding' as const, id: row.id, principal: member, createdBy: row.createdBy, scope: row.scope })));
    return liveBindings(db, chainKey, member, generation);
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
      if (!isBearerProfile(policy.profile) || input.policy !== undefined || this.#deps.config.useOnly) {
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
      // The issuer as the vault answers now, held to under the head: demoted meanwhile, they give it nothing (`issuerStill`).
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
            : `${UPLOADED}${uploaded.digest}`;
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
        if (replaces.some((row) => row.why === 'keys_moved' && (row.jwksUri.startsWith(UPLOADED) || jwksUri.startsWith(UPLOADED)))) {
          throw conflict(
            `${shownMember(member)}'s other bindings on ${policy.issuer} verify with other keys: replace their keys with these first, or replace those bindings with this one`,
          );
        }
        if (live.length - replaces.length + 1 > MAX_BINDINGS) throw conflict(`a service holds at most ${MAX_BINDINGS} bindings`);
        return replaces;
      };
      const replaced = replacing(await this.#sealedBindings(member, standing.generation, options));
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

      return retrying(async () => {
      // With 0.15's log, the credentials of those it replaces, ended with them: those it replaces now, read again on a retry.
      const changes = await this.#revokes(formatMember(ctx.caller.principal), member, async () => {
        const ending = inherits ? replaced : replacing(await liveBindings(this.#deps.db, this.#deps.chainKey, member, standing.generation));
        return ending.map(({ id }) => id);
      });
      // Its scope was weighed with the policy and the issuer as the vault answered: committed only while still so (`audited`, `issuerStill`).
      return audited({ ...this.#deps, caller }, async (tx, log) => {
        await issuerStill(tx, caller, accessSeq);
        await credentialStill(ctx, tx, 'token.bind');
        if (!(await stillMember(tx, member, standing))) throw unknown();
        const planned = plan(replacing(await liveBindings(tx, this.#deps.chainKey, member, standing.generation)));
        // The keys it reads, by name, are the ones they were as it was weighed: a rename meanwhile names another.
        if (reads.length > 0 && JSON.stringify(readsById(await resolveReads(tx, wantedReads))) !== JSON.stringify(readsById(reads))) {
          throw conflict('the keys its reads name changed while it was made: try again');
        }
        if (inherits && planned.replaces.map(({ id }) => id).join() !== replaced.map(({ id }) => id).join()) {
          throw conflict('the bindings it replaces changed while it was made: try again');
        }
        const id = randomUUID();
        const now = new Date();
        const row = {
          id,
          principal: member,
          generation: standing.generation,
          profile: planned.profile,
          issuer: planned.issuer,
          jwksUri: planned.jwksUri,
          jwks: uploaded?.jwks ?? null,
          claims: canonicalClaims(planned.claims),
          scope: storedScope(scope),
          // None on a bearer binding, which `/api/auth/oidc` takes; canonical JSON on a workload's, under the MAC (`policed_`).
          policy: rules === null ? null : policyText(rules),
          label: input.label?.slice(0, 120) ?? null,
          createdAt: now,
          createdBy: ctx.caller.principal.id,
        };
        await insertBinding(tx, this.#deps.chainKey, row);
        const ended: string[] = [];
        for (const replaced of planned.replaces) {
          ended.push(...(await this.#revoke(tx, replaced.id, `token:${serviceId}`, ctx.caller.principal.id, now)).credentials);
          log.push(allowed(ctx, 'token.unbind', {
            metadata: { bindingId: replaced.id, principalType: 'service', principalId: serviceId, reason: replaced.why === 'asked' ? 'replaced' : 'keys_moved', by: id },
          }));
        }
        log.push(allowed(ctx, 'token.bind', {
          metadata: {
            bindingId: id,
            principalType: 'service',
            principalId: serviceId,
            profile: planned.profile,
            issuer: planned.issuer,
            jwksUri: planned.jwksUri,
            ...(uploaded === null ? {} : { keys: uploaded.keys }),
            claims: planned.claims,
            scope,
            ...(rules === null ? {} : { policy: rules }),
            ...(reads.length === 0 ? {} : { reads: shownPolicy(rules!, reads).reads }),
            replaces: planned.replaces.map((replaced) => replaced.id),
          },
        }));
        changes?.expectRevoked(ended);
        return {
          binding: view({ ...row, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null, seal: null }, byPath, planned.policy),
          replaced: planned.replaces.map((replaced) => replaced.id),
        };
      }, changes);
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
    const jwksUri = `${UPLOADED}${uploaded.digest}`;
    return withRefusals(this.#deps, async () => {
      // The issuer as the vault answers now, held to under the head (`issuerStill`), as in `bind`.
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
      const replaced = replacing(await this.#sealedBindings(member, standing.generation, options));
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

      return retrying(async () => {
      const changes = await this.#revokes(formatMember(ctx.caller.principal), member, async () => plan.replaces);
      // Its scope was weighed with the policy and the issuer as the vault answered: committed only while still so (`audited`, `issuerStill`).
      return audited({ ...this.#deps, caller }, async (tx, log) => {
        await issuerStill(tx, caller, accessSeq);
        await credentialStill(ctx, tx, 'token.bind');
        if (!(await stillMember(tx, member, standing))) throw unknown();
        const live = replacing(await liveBindings(tx, this.#deps.chainKey, member, standing.generation));
        if (live.map((row) => row.id).join() !== plan.replaces.join()) throw conflict(`the bindings on ${input.issuer} changed while their keys were replaced: try again`);
        const now = new Date();
        const bindings: BindingView[] = [];
        const ended: string[] = [];
        for (const [i, old] of live.entries()) {
          const id = randomUUID();
          const { scope, byPath } = scopes.get(old.id)!;
          const row = {
            id,
            principal: member,
            generation: standing.generation,
            profile: old.profile,
            issuer: old.issuer,
            jwksUri,
            jwks: uploaded.jwks,
            claims: old.claims,
            scope: storedScope(scope),
            policy: old.policy,
            label: old.label,
            // A millisecond apart, in the order of those they replace: an exchange tries bindings oldest first, and still does.
            createdAt: new Date(now.getTime() + i),
            createdBy: ctx.caller.principal.id,
          };
          await insertBinding(tx, this.#deps.chainKey, row);
          ended.push(...(await this.#revoke(tx, old.id, member, ctx.caller.principal.id, now)).credentials);
          log.push(allowed(ctx, 'token.unbind', {
            metadata: { bindingId: old.id, principalType: 'service', principalId: serviceId, reason: 'keys_replaced', by: id },
          }));
          log.push(allowed(ctx, 'token.bind', {
            metadata: {
              bindingId: id,
              principalType: 'service',
              principalId: serviceId,
              profile: old.profile,
              issuer: old.issuer,
              jwksUri,
              keys: uploaded.keys,
              claims: JSON.parse(old.claims) as BindingClaims,
              scope,
              replaces: [old.id],
            },
          }));
          bindings.push(view({ ...row, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null, seal: null }, byPath, shown(old.policy)));
        }
        changes?.expectRevoked(ended);
        return { bindings, replaced: plan.replaces };
      }, changes);
      });
    });
  }

  /** Remove a binding. Its successful `token.unbind` is its tombstone: no row put back brings it back. */
  async unbind(ctx: Asker, serviceId: string, bindingId: string): Promise<{ unbound: true }> {
    const member = `token:${serviceId}`;
    const metadata = { bindingId, principalType: 'service', principalId: serviceId };
    return withRefusals(this.#deps, async () => {
      // Logged as a denial, which no tombstone check counts.
      if (!(await managedAccount(this.#deps, ctx.caller, serviceId)).managed) throw notManager(ctx, 'token.unbind', metadata, 'remove its trust bindings');
      return retrying(async () => {
        const changes = await this.#revokes(formatMember(ctx.caller.principal), member, async () => [bindingId]);
        // Who manages it was weighed with the policy as the caller was loaded: committed only while still so (`audited`).
        return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
          const row = await findBinding(tx, this.#deps.chainKey, member, bindingId);
          const live = row !== null && row.revokedAt === null
            && (await liveBindings(tx, this.#deps.chainKey, member, row.generation)).some((candidate) => candidate.id === bindingId);
          const ended = live ? await this.#revoke(tx, bindingId, member, ctx.caller.principal.id, new Date()) : null;
          if (ended === null || ended.revoked === 0) {
            throw new Refusal(notFound('unknown trust binding'), denied(ctx, 'token.unbind', 'unknown_binding', { metadata }));
          }
          changes?.expectRevoked(ended.credentials);
          log.push(allowed(ctx, 'token.unbind', { metadata: { ...metadata, reason: 'removed' } }));
          return { unbound: true as const };
        }, changes);
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

  /** Revoke a binding, and every credential it issued that still lives: they die with it. */
  /**
   * Revoke a binding, and the credentials it issued that are still live: at
   * most a few minutes' worth, however long its history. Every use of a
   * credential checks its binding too, so these rows are belt and braces;
   * the expired ones are dead already and are left as they are.
   */
  async #revoke(tx: Transaction, id: string, member: string, by: string, at: Date): Promise<{ revoked: number; credentials: string[] }> {
    const revoked = await updateAuth(tx, this.#deps.chainKey, serviceBindings, { id, revokedAt: null }, { revokedAt: at, revokedBy: by });
    const credentials = await revokeLiveCredentials(tx, this.#deps.chainKey, { principal: member, createdBy: issuedBy(id), at }, { revokedAt: at, revokedBy: by });
    return { revoked, credentials };
  }

  /**
   * The changes revoking these bindings makes to 0.15's log: one per live
   * credential each issued, as `#revoke` finds them, read before the
   * transaction (`AppChanges.expectRevoked` holds the two to each other).
   */
  async #revokes(actor: string, member: string, bindings: () => Promise<readonly string[]>): Promise<AppChanges | null> {
    return AppChanges.prepare(this.#deps.vault, actor, async () => {
      const at = new Date();
      const live = await Promise.all((await bindings()).map((id) => liveCredentialsWhere(this.#deps.db, this.#deps.chainKey, liveCredentialsOf({ principal: member, createdBy: issuedBy(id), at }))));
      return revokes(live.flat());
    });
  }

  /**
   * A CI run's ID token, for a credential of the service it names
   * (docs/design/oidc.md, section 2). Admission comes first, in the route;
   * then, in order, so that a stranger costs one bounded read at most:
   *
   * 1. the token's shape;
   * 2. the service's live bindings on its issuer, one read, which says too
   *    whether the token was spent and the newest policy change;
   * 3. its signature under that issuer's keys, then its audience, times and
   *    claims against those bindings (`verify`);
   * 4. that it is not spent yet, as that read said;
   * 5. the member, from the vault, outside any transaction, and a binding
   *    0.4 made sealed with what it holds (`sealCredentials`);
   * 6. in one transaction that holds the log's head: the member, the
   *    binding and its rate again, one read (`exchangeStill`), the times
   *    again, the token spent, the credential issued and the binding
   *    stamped, one write (`exchangeToken`), and `token.exchange` logged,
   *    or none of it.
   */
  async exchange(request: ExchangeRequest, meta: { requestId: string; sourceIp: string | null }): Promise<Exchanged> {
    if (inFlight >= exchangeLimit.inFlight) throw new ExchangeRefused('busy', 'too many exchanges under way: try again shortly', 429);
    inFlight++;
    try {
      return await this.#exchange(request, meta);
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
    const { bindings: candidates, spent, policySeq } = await exchangeCandidates(db, chainKey, member, issuer, MAX_BINDINGS, decoded.signingInputHash);
    if (candidates.length === 0 || spent === null) throw unbound();
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
      if (error instanceof IssuerUnavailable) throw new ExchangeRefused('issuer_unavailable', error.message, 503, '60');
      if (newest.jwks !== null && error instanceof WorkloadTokenRefused && error.reason === 'unknown_key') throw new UnknownKey(member, newest, issuer, shownKid(decoded.header));
      throw refused(error);
    }
    const binding = matching(candidates.filter((candidate) => candidate.jwksUri === newest.jwksUri), claims, member);
    return { binding, claims, token: decoded, spent, policySeq };
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
   *    only: the member and the binding again, no freeze, the binding's
   *    rate, the proof spent, the proof's own commit (an enrollment's
   *    capacity), the session made and `token.exchange` logged;
   * 4. the proof's `after`, outside it.
   *
   * Its `notAfter` is the earliest of its binding's `sessionHours` and the
   * ends its proof gave; it expires `lifetimeMs` after it is made, and at
   * each renewal. One its binding has wait for approval is answered 202.
   */
  async signIn(request: SessionRequest, meta: { requestId: string; sourceIp: string | null; jkt: string }): Promise<SessionIssued | SessionPending> {
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

  async #signIn(request: SessionRequest, meta: { requestId: string; sourceIp: string | null; jkt: string }): Promise<SessionIssued | SessionPending> {
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
    // With 0.15's log, the vault makes the session (T149): it spends the token, and weighs the account, the binding, its
    // freezes and its rate, in one call. A proof that decides in the transaction (`commit`) makes it as below.
    if (kind.commit === undefined && (await vaultMakesCredentials(vault))) return this.#signInByVault(vault as CredentialsVault, { member, name, kind, verified, policy }, meta, ctx);
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
    const made = await retrying(async () => {
    const id = randomUUID();
    const planned = shape(decided, Date.now());
    const changes = logged
      ? await AppChanges.prepare(vault, member, [credentialChange(null, { id, principal: member, kind: 'workload', scope: planned.stored, revokedAt: null, expiresAt: planned.expiresAt, notAfter: planned.notAfter, generation: binding.generation })])
      : null;
    return audited(this.#deps, async (tx, log) => {
      const now = new Date();
      if (!(await stillMember(tx, member, standing)) || (await standingBinding(tx, chainKey, binding.id, member, binding.generation)) === null) throw unbound();
      if ((await frozenTargets(tx, ['instance', member, `binding:${binding.id}`])).length > 0) {
        throw new ExchangeRefused('frozen', `${shownMember(member)} is frozen: a manager stopped its use, and no session is made until they lift it`);
      }
      const recent = await exchangesSince(tx, member, issuedBy(binding.id), new Date(now.getTime() - 60_000), EXCHANGES_PER_BINDING_MINUTE);
      if (recent >= EXCHANGES_PER_BINDING_MINUTE) {
        throw new ExchangeRefused('busy', `this binding made ${EXCHANGES_PER_BINDING_MINUTE} sessions in the last minute: try again shortly`, 429);
      }
      if (spent !== undefined && !(await consumeToken(tx, spent))) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your platform for a fresh one');
      const committed = kind.commit === undefined ? {} : await kind.commit(tx, verified, ctx);
      if (committed instanceof ExchangeRefused) throw committed;
      // The change was sealed for what the proof would decide: decided otherwise (an enrollment's scope and end), made again with it.
      if (changes !== null && ((committed.scope ?? null) !== (decided.scope ?? null) || committed.notAfter?.getTime() !== decided.notAfter?.getTime())) {
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
      log.push(allowed(actor, 'token.exchange', {
        metadata: {
          kind: 'workload',
          credentialId: id,
          bindingId: binding.id,
          generation: binding.generation,
          proof: name,
          jkt: meta.jkt,
          expiresAt: expiresAt.toISOString(),
          notAfter: notAfter.toISOString(),
          ...(committed.enrollmentId === undefined ? {} : { enrollmentId: committed.enrollmentId }),
          ...(committed.pending === true ? { pending: true } : {}),
          run: runClaims(verified.claims),
        },
      }));
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
   * call. Its binding as read here, its account, its freezes, its rate and
   * the token spent once are weighed in the vault's statement, under their
   * rows' locks; no 0.14 head, and no `token.exchange` entry: its change
   * records the run (D147). The environments it reaches are read first, for
   * its row and its answer, as nothing the vault decides is made of them.
   */
  async #signInByVault(
    vault: CredentialsVault,
    proof: { member: string; name: ProofName; kind: ProofKind; verified: MatchedProof; policy: BindingPolicy },
    meta: { requestId: string; sourceIp: string | null; jkt: string },
    ctx: ProofContext,
  ): Promise<SessionIssued> {
    const { member, name, kind, verified, policy } = proof;
    const { binding } = verified;
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
      binding: { id: binding.id, generation: binding.generation, profile: binding.profile, scope: binding.scope, policy: binding.policy },
      credential: signedInCredential(row),
      appKey: appLogKey(this.#deps.chainKey).keyId,
      spent: verified.spentKey?.toString('base64') ?? null,
      // Its proof's end is the session's hard end, held to in the statement.
      validUntil: null,
      record: { proof: name, issuer: binding.issuer, run: runClaims(verified.claims) },
    });
    if (!outcome.ok) {
      throw signInRefusal(outcome.refused, {
        unbound: `no workload binding of ${shownMember(member)} takes this proof`,
        frozen: `${shownMember(member)} is frozen: a manager stopped its use, and no session is made until they lift it`,
        busy: `this binding made ${EXCHANGES_PER_BINDING_MINUTE} sessions in the last minute: try again shortly`,
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
        : await AppChanges.prepare(this.#deps.vault, row.principal, [credentialChange(row, { ...row, expiresAt: new Date(planned) })]);
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

  async #exchange(request: ExchangeRequest, meta: { requestId: string; sourceIp: string | null }): Promise<Exchanged> {
    const { db, chainKey, vault } = this.#deps;
    const member = request.service;
    const { binding, claims, token: decoded, spent, policySeq } = await this.verify(member, request.token);
    const issuer = decoded.claims.iss;
    const unbound = () => new ExchangeRefused('no_match', `no binding of ${shownMember(member)} trusts tokens from ${issuer}`);

    if (spent) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your CI for a fresh one');
    // With 0.15's log, the vault makes it (T149): one call, no 0.14 head. Every sign-in through a binding goes there, so
    // that each one's rate is counted under its row: one 0.4 made, its scope unsealed, is sealed first, and read again.
    const byVault = await vaultMakesCredentials(vault);
    if (byVault && !unsealedScope(binding.scope)) return this.#exchangeByVault(vault as CredentialsVault, member, binding, claims, decoded);
    const standing = await vault.access(member);
    if (standing.status !== 'active' || standing.generation !== binding.generation) throw unbound();
    // One an older release made after the app sealed its own: sealed with the account's grants the vault just answered, before a run's credential reads it.
    if (unsealedScope(binding.scope)) {
      await sealCredentials(db, chainKey, vault, standing, policySeq, [{ kind: 'binding', id: binding.id, principal: member, createdBy: binding.createdBy, scope: binding.scope }]);
    }
    if (byVault) {
      const sealed = await findBinding(db, chainKey, member, binding.id);
      if (sealed === null || unsealedScope(sealed.scope)) throw unbound();
      return this.#exchangeByVault(vault as CredentialsVault, member, sealed, claims, decoded);
    }

    const service = member.slice('token:'.length);
    const ctx = { caller: { principal: { type: 'service', id: service } }, requestId: meta.requestId, sourceIp: meta.sourceIp } as Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>;
    return retrying(async () => {
    // With 0.15's log, the credential is a change of it, and carries its binding's scope, as stored: its uses decide on
    // it alone (0.14 reads the binding's, which this is), and the binding's end revokes it, a change too (`#revoke`).
    const scoped = (await keeps015(vault)) ? (unsealedScope(binding.scope) ? (await findBinding(db, chainKey, member, binding.id))?.scope ?? null : binding.scope) : undefined;
    const { row, issued: credential } = this.#deps.signin.exchangedCredential(service, {
      generation: binding.generation, bindingId: binding.id, label: binding.label, expiresAt: new Date(Date.now() + EXCHANGED_CREDENTIAL_MS),
      ...(scoped === undefined ? {} : { scope: readScope(scoped) ?? [] }),
    });
    const changes = await AppChanges.prepare(vault, member, [credentialChange(null, row)]);
    return audited(this.#deps, async (tx, log) => {
      const now = new Date();
      // The member, the binding and its rate, in one read: every statement here holds the head, which every append waits for.
      const still = await exchangeStill(tx, chainKey, binding, new Date(now.getTime() - 60_000), EXCHANGES_PER_BINDING_MINUTE);
      if (!still.stands) throw unbound();
      // The scope the credential carries is the binding's still.
      if (scoped !== undefined && still.scope !== scoped) throw new ObjectMoved();
      // The times again, should the request have waited.
      const seconds = now.getTime() / 1000;
      if (decoded.claims.exp <= seconds - CLOCK_TOLERANCE_SECONDS) throw new ExchangeRefused('expired', 'the token has expired');
      const issued = issuedRefusal(decoded.claims.iat, seconds);
      if (issued !== null) throw refused(issued);
      if (still.recent >= EXCHANGES_PER_BINDING_MINUTE) {
        throw new ExchangeRefused('busy', `this binding issued ${EXCHANGES_PER_BINDING_MINUTE} credentials in the last minute: try again shortly`, 429);
      }
      // The token spent, and only then the credential issued and the binding's last use stamped.
      if (!(await exchangeToken(tx, decoded.signingInputHash, row, binding.id, now))) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your CI for a fresh one');
      log.push(allowed(ctx, 'token.exchange', {
        metadata: {
          credentialId: credential.id,
          bindingId: binding.id,
          generation: binding.generation,
          issuer,
          expiresAt: credential.expiresAt,
          run: runClaims(claims),
        },
      }));
      return { token: credential.token, expiresAt: credential.expiresAt };
    }, changes);
    });
  }

  /**
   * `#exchange` with 0.15's log: the vault makes the credential (T149), in
   * one call. The binding as read here, the account active at its
   * generation, the binding's rate and the token spent once are weighed in
   * its statement, on their rows, under their locks (formal/Lifecycle.tla's
   * BindingLocked, MemberLocked, SpentChecked); no 0.14 head, and no
   * `token.exchange` entry: its change records the run (D147).
   */
  async #exchangeByVault(vault: CredentialsVault, member: string, binding: BindingRow, claims: Record<string, unknown>, decoded: DecodedToken): Promise<Exchanged> {
    const issuer = decoded.claims.iss;
    const { row, issued } = this.#deps.signin.exchangedCredential(member.slice('token:'.length), {
      generation: binding.generation, bindingId: binding.id, label: binding.label, expiresAt: new Date(Date.now() + EXCHANGED_CREDENTIAL_MS), stored: binding.scope,
    });
    const outcome = await vault.signIn({
      principal: member,
      binding: { id: binding.id, generation: binding.generation, profile: binding.profile, scope: binding.scope, policy: binding.policy },
      credential: signedInCredential({ ...row, kind: 'service' }),
      appKey: appLogKey(this.#deps.chainKey).keyId,
      spent: decoded.signingInputHash.toString('base64'),
      // The token's times, held to again in the statement, as the commit under 0.14's head holds them: its `exp`, and its `iat`'s hour.
      // Whole ms, down: a token's times may be fractional seconds, which the checks before took.
      validUntil: Math.floor(Math.min((decoded.claims.exp + CLOCK_TOLERANCE_SECONDS) * 1000, (decoded.claims.iat + MAX_TOKEN_AGE_SECONDS) * 1000)),
      record: { proof: 'oidc', issuer, run: runClaims(claims) },
    });
    if (!outcome.ok) {
      // Past its times by the statement: which of them, as the commit under the head says it.
      const issued = outcome.refused === 'expired' ? issuedRefusal(decoded.claims.iat, Date.now() / 1000) : null;
      if (issued !== null) throw refused(issued);
      throw signInRefusal(outcome.refused, {
        unbound: `no binding of ${shownMember(member)} trusts tokens from ${issuer}`,
        busy: `this binding issued ${EXCHANGES_PER_BINDING_MINUTE} credentials in the last minute: try again shortly`,
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
function signInRefusal(refused: SignInRefusal, words: Record<Exclude<SignInRefusal, 'frozen' | 'retired'>, string> & { frozen?: string }): ExchangeRefused {
  switch (refused) {
    // An instance under an app key the log moved on from, as for the seconds a deploy takes: 503, as its append would answer.
    case 'retired': throw new KeyRetired('the app\'s key is one it rotated from: a newer deployment replaces this one');
    case 'unbound': return new ExchangeRefused('no_match', words.unbound);
    case 'busy': return new ExchangeRefused('busy', words.busy, 429);
    case 'replayed': return new ExchangeRefused('replayed', words.replayed);
    case 'expired': return new ExchangeRefused('expired', words.expired);
    case 'frozen': return new ExchangeRefused('frozen', words.frozen ?? words.unbound);
  }
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

/** The run's claims, as the issuer stated them: those that say which run, each bounded. */
function runClaims(claims: Record<string, unknown>): Record<string, string | number> {
  const run: Record<string, string | number> = {};
  for (const name of RUN_CLAIMS) {
    const value = claimAt(claims, name);
    if (typeof value === 'string') run[name] = value.slice(0, MAX_RUN_CLAIM);
    else if (typeof value === 'number' && Number.isFinite(value)) run[name] = value;
  }
  return run;
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
 * refused by name, since listing a key needs the key to exist. Its own
 * keys only: a reference reads what its source holds, where the vault
 * checks `reads`, by its source's ID.
 */
async function resolveReads(db: Queryable, wanted: unknown): Promise<ResolvedRead[]> {
  if (typeof wanted !== 'object' || wanted === null || Array.isArray(wanted)) throw badRequest('reads maps each environment, by path, to its key names or "*"');
  const entries = Object.entries(wanted as Record<string, unknown>);
  if (entries.length > MAX_READ_PLACES) throw badRequest(`reads names at most ${MAX_READ_PLACES} environments`);
  const known = await places(db);
  const resolved: ResolvedRead[] = [];
  for (const [path, keys] of entries) {
    if (keys !== '*' && !(Array.isArray(keys) && keys.length <= MAX_READ_KEYS && keys.every((key) => typeof key === 'string' && key.length <= 256))) {
      throw badRequest(`reads lists ${path}'s keys by name, at most ${MAX_READ_KEYS}, or "*" for every one`);
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
    const held = (await secretHeads(db, environment.id, { keys: names })).filter((row) => row.archivedAt === null && row.current !== null);
    const missing = names.filter((name) => !held.some((row) => row.key === name));
    if (missing.length > 0) throw badRequest(`reads lists keys ${path} does not hold: ${missing.join(', ')}`);
    resolved.push({ environmentId: environment.id, path: `${project.slug}/${environment.slug}`, projectId: project.id, keys: held.map((row) => ({ id: row.id, key: row.key, sensitive: row.current!.sensitive })) });
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
function view(row: BindingRow, scope: ScopeByPath | null, policy: PolicyView | null): BindingView {
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
  };
}
