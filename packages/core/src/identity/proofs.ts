import { compactVerify, createLocalJWKSet, errors, type JSONWebKeySet } from 'jose';

import { expectedAudiences, PROFILE_RULES } from './profiles.ts';
import { CLOCK_TOLERANCE_SECONDS, decodeWorkloadToken, issuedRefusal, MAX_TOKEN_AGE_SECONDS, WORKLOAD_ALGORITHMS, WorkloadTokenRefused, type DecodedToken } from './workload-token.ts';
import {
  addressWithin, BEARER_PROFILES, claimAt, differingClaims, OIDC_PROFILES, POLICY_DEFAULTS, POLICY_FIELDS, REPEATING_PROFILES,
  type BindingClaims, type BindingPolicy, type WorkloadProfile,
} from './workloads.ts';

/**
 * A platform's proof held to a service's bindings (docs/design/0.16.md, "A
 * workload signing in"). The app verifies a token's signature, or asks AWS,
 * since only it reaches the platform; everything else read the binding's
 * row, which only the vault can trust. So the vault decides it, on its own
 * rows and its own clock, with these functions: rows and claims in, a
 * binding or a refusal's word out. No I/O, and no clock but the one passed
 * in, in milliseconds.
 *
 * Example: Ada's `deploy` service has two GitHub bindings on
 * `token.actions.githubusercontent.com`, one for `main` made in March and
 * one for every branch made in May. A run on `main` matches both; the
 * March one, the oldest, issues its credential, with the scope its maker
 * gave it. A run on `feature/x` matches May's alone.
 */

/**
 * Why a proof is refused, in the vault's words. `no_match`: no binding of
 * the service takes it. `audience`, `expired`, `too_old`, `malformed`: the
 * token is not for this instance or this key, is past its time, or breaks
 * its profile's rule. `unknown_signer`: a binding carries its keys, and they
 * lack the one the token names.
 */
export type ExchangeRefusal = 'no_match' | 'audience' | 'expired' | 'too_old' | 'malformed' | 'unknown_signer';
export type ExchangeRefused = { refused: ExchangeRefusal };

/** A trust binding as a decision reads it: the columns of its row that say what it takes. */
export type ProofBinding = {
  id: string;
  profile: string;
  issuer: string;
  /** Where its issuer's keys are fetched from, or `sha256:<hex>` of those it carries (`CARRIED`). */
  jwksUri: string;
  /** The keys it carries, a JWKS as JSON: null when they are fetched. */
  jwks: string | null;
  /** JSON, sorted by claim name (`canonicalClaims`). */
  claims: string;
  /** Canonical JSON (`policyText`): null on a binding that issues a CI run's token, which no session is made from. */
  policy: string | null;
  createdAt: Date;
};

/** A binding's `jwks_uri` when it carries its issuer's keys: the SHA-256 of those keys, where a fetched set's URL would be. */
export const CARRIED = 'sha256:';

/**
 * The keys a token was verified under, as the app says: its issuer, and
 * their address, the URL it fetched them from. For a binding that carries
 * its keys the address is theirs, `sha256:<hex>`, and the vault verifies the
 * signature itself (`signatureRefusal`).
 */
export type VerifiedUnder = { issuer: string; jwksUri: string };

/**
 * What a proof is traded for: a CI run's five-minute token (`run`), from a
 * binding with no policy, or a workload's session bound to a key
 * (`session`), from one with a policy.
 */
export type ProofFor = { kind: 'run' } | { kind: 'session'; jkt: string };

/** A token's claims and the hash of what was signed, or `malformed`. */
export function readIdToken(token: string): DecodedToken | ExchangeRefused {
  try {
    return decodeWorkloadToken(token);
  } catch (error) {
    if (error instanceof WorkloadTokenRefused) return { refused: 'malformed' };
    throw error;
  }
}

/** A binding's policy as its row holds it: null for none, undefined for one that does not read as a policy, which takes nothing. */
export function policyOf(binding: Pick<ProofBinding, 'policy'>): BindingPolicy | null | undefined {
  if (binding.policy === null) return null;
  try {
    const policy: unknown = JSON.parse(binding.policy);
    return typeof policy === 'object' && policy !== null && !Array.isArray(policy) ? (policy as BindingPolicy) : undefined;
  } catch {
    return undefined;
  }
}

/** Whether a binding issues what a proof is traded for: a CI run's token from a bearer profile with no policy, a session from an ID-token profile with one. */
export function issues(binding: Pick<ProofBinding, 'profile' | 'policy'>, wanted: ProofFor['kind']): boolean {
  const profiles: readonly string[] = wanted === 'run' ? BEARER_PROFILES : OIDC_PROFILES;
  return profiles.includes(binding.profile) && (wanted === 'run' ? binding.policy === null : policyOf(binding) != null);
}

/** The audience a token names, alone; null for none, or several. */
export function soleAudience(aud: unknown): string | null {
  if (typeof aud === 'string') return aud;
  return Array.isArray(aud) && aud.length === 1 && typeof aud[0] === 'string' ? aud[0] : null;
}

/**
 * The audiences a binding takes: this instance's URL for a CI run's; for a
 * session's, its policy's, the session's key or its profile's
 * (`expectedAudiences`). None for one whose policy does not read.
 */
export function audiencesOf(binding: Pick<ProofBinding, 'profile' | 'policy'>, publicUrl: string, wanted: ProofFor): string[] {
  const policy = policyOf(binding);
  if (wanted.kind === 'run') return policy === null ? [publicUrl] : [];
  return policy == null ? [] : expectedAudiences(binding.profile as WorkloadProfile, policy, { publicUrl, jkt: wanted.jkt });
}

/**
 * Which audience a token is held to, and the bindings that take it: the
 * token's own if some binding takes it, otherwise the instance's, 0.14's
 * rule. A token none takes is refused `audience` once its times are checked.
 */
export function audienceTried<B extends ProofBinding>(aud: unknown, bindings: readonly B[], publicUrl: string, wanted: ProofFor): { audience: string; taking: B[] } {
  const named = soleAudience(aud);
  const audience = named !== null && bindings.some((binding) => audiencesOf(binding, publicUrl, wanted).includes(named)) ? named : publicUrl;
  return { audience, taking: bindings.filter((binding) => audiencesOf(binding, publicUrl, wanted).includes(audience)) };
}

/**
 * A token's times on the vault's clock, `now` in milliseconds, each within
 * the clock tolerance, as 0.14 held them: not before its `nbf`, to jose's
 * whole second; before its `exp`, to the millisecond, as 0.14's exchange
 * checked it again; issued `maxAge` seconds ago at most (an hour,
 * or any age for a token its platform hands out again), and, where a binding
 * carries its keys, living `maxLifetime` seconds at most.
 */
export function timesRefusal(claims: DecodedToken['claims'], now: number, { maxAge = MAX_TOKEN_AGE_SECONDS, maxLifetime = null }: { maxAge?: number | null; maxLifetime?: number | null } = {}): ExchangeRefusal | null {
  const seconds = Math.floor(now / 1000);
  // 0.14's `not_yet_valid` and `too_long` are `too_old` here, as a token issued in the future already was: past its time.
  if (typeof claims.nbf === 'number' && claims.nbf > seconds + CLOCK_TOLERANCE_SECONDS) return 'too_old';
  if (claims.exp <= now / 1000 - CLOCK_TOLERANCE_SECONDS) return 'expired';
  if (issuedRefusal(claims.iat, now / 1000, maxAge ?? Infinity) !== null) return 'too_old';
  if (maxLifetime !== null && claims.exp - claims.iat > maxLifetime) return 'too_old';
  return null;
}

/** The oldest of `bindings` whose every claim the token carries (`differingClaims`), in the order the bindings' index reads them. */
export function oldestMatching<B extends Pick<ProofBinding, 'id' | 'profile' | 'claims' | 'createdAt'>>(bindings: readonly B[], claims: Record<string, unknown>): B | null {
  const ordered = [...bindings].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return ordered.find((binding) => {
    let expected: unknown;
    try {
      expected = JSON.parse(binding.claims);
    } catch {
      return false;
    }
    return typeof expected === 'object' && expected !== null && !Array.isArray(expected) && differingClaims(binding.profile as WorkloadProfile, expected as BindingClaims, claims).length === 0;
  }) ?? null;
}

/** Why a token its binding matched still breaks its profile's own rule (`PROFILE_RULES`: Azure's version, Kubernetes' subject), or null. */
export function profileRefusal(binding: Pick<ProofBinding, 'profile' | 'issuer' | 'claims'>, policy: BindingPolicy, claims: Record<string, unknown>): 'malformed' | null {
  const rule = PROFILE_RULES[binding.profile as WorkloadProfile];
  if (rule === undefined) return null;
  return rule.token(claims, { issuer: binding.issuer, claims: JSON.parse(binding.claims) as BindingClaims, policy }) === null ? null : 'malformed';
}

/**
 * Whether a proof is spent once it is traded, by the SHA-256 of what was
 * signed: a CI run's token always; a session's token unless it names the
 * session's key, which works for no other, or its platform hands the same
 * one out again (`REPEATING_PROFILES`), which spending would refuse.
 */
export function spends(binding: Pick<ProofBinding, 'profile'>, policy: BindingPolicy | null, wanted: ProofFor['kind']): boolean {
  if (wanted === 'run') return true;
  return policy?.keyAudience !== true && !REPEATING_PROFILES.includes(binding.profile as WorkloadProfile);
}

/**
 * A session's hard end, in milliseconds: the earliest of its binding's
 * `sessionHours` after `at`, where its profile has them (24 unless said),
 * and, unless the token names the session's key, the token's own `exp`, so
 * that a copy of it buys no more than the platform's lifetime. `exp` is in
 * seconds, null for a proof that is no token. A session whose end is not
 * after `at` is refused `expired`.
 */
export function hardEnd(binding: Pick<ProofBinding, 'profile'>, policy: BindingPolicy, at: number, exp: number | null): number {
  const fields = POLICY_FIELDS[binding.profile as WorkloadProfile] ?? [];
  const hours = fields.includes('sessionHours') ? (policy.sessionHours ?? POLICY_DEFAULTS.sessionHours) : null;
  const ends = [hours === null ? null : at + hours * 3_600_000, policy.keyAudience === true || exp === null ? null : exp * 1000].filter((end): end is number => end !== null);
  return Math.min(...(ends.length === 0 ? [at + POLICY_DEFAULTS.sessionHours * 3_600_000] : ends));
}

/**
 * Why a session is refused at its sign-in, from its binding's policy and the
 * request's address: the deployment lets no binding list reads (`noReads`)
 * and this one does, or it names its sources and the request came from
 * outside them, or from nowhere the app could tell. Both are `no_match`, as
 * the design's refusals have it; 0.14 answered the second `source`.
 */
export function sessionRefusal(policy: BindingPolicy, ip: string | null, { noReads }: { noReads: boolean }): 'no_match' | null {
  if (noReads && policy.reads !== undefined) return 'no_match';
  if (policy.sources !== undefined && (ip === null || !addressWithin(ip, policy.sources))) return 'no_match';
  return null;
}

/** An ID token held to a service's bindings: the binding it is traded at, its claims and policy, and the hash it spends, if any. */
export type IdTokenMatch<B extends ProofBinding> = { binding: B; policy: BindingPolicy | null; claims: DecodedToken['claims']; spends: Buffer | null };

/**
 * An ID token whose signature verified under `under`, held to the
 * service's live bindings, in 0.14's order:
 *
 * 1. of the bindings that issue what it is traded for (`issues`), those
 *    on its issuer under the keys it was verified under;
 * 2. the audience tried, and the bindings that take it (`audienceTried`);
 * 3. its times (`timesRefusal`): any age for a token its platform hands
 *    out again, where a binding that takes it is of such a platform, and
 *    an hour's lifetime at most under keys a binding carries;
 * 4. that audience, the token's own, alone;
 * 5. the oldest whose claims match (`oldestMatching`);
 * 6. an hour's age after all, if the binding that matched is of a
 *    platform that hands out no token twice;
 * 7. its profile's own rule (`profileRefusal`).
 *
 * `bindings` are the sealed rows the read found: a decision that picks the
 * oldest of several refuses before this if any row it read is not the
 * vault's, since one passed over would let a later one answer.
 */
export function matchIdToken<B extends ProofBinding>(token: DecodedToken, bindings: readonly B[], { under, publicUrl, wanted, now }: { under: VerifiedUnder; publicUrl: string; wanted: ProofFor; now: number }): IdTokenMatch<B> | ExchangeRefused {
  const { claims } = token;
  const candidates = bindings.filter((binding) => issues(binding, wanted.kind) && binding.issuer === under.issuer && binding.jwksUri === under.jwksUri && claims.iss === under.issuer);
  if (candidates.length === 0) return { refused: 'no_match' };
  const { audience, taking } = audienceTried(claims.aud, candidates, publicUrl, wanted);
  const repeats = taking.some((binding) => REPEATING_PROFILES.includes(binding.profile as WorkloadProfile));
  // Keys a binding carries: no issuer to ask whether a token still stands, so none lives past the hour.
  const times = timesRefusal(claims, now, { maxAge: repeats ? null : MAX_TOKEN_AGE_SECONDS, maxLifetime: under.jwksUri.startsWith(CARRIED) ? MAX_TOKEN_AGE_SECONDS : null });
  if (times !== null) return { refused: times };
  if (soleAudience(claims.aud) !== audience || taking.length === 0) return { refused: 'audience' };
  const binding = oldestMatching(taking, claims);
  if (binding === null) return { refused: 'no_match' };
  const policy = policyOf(binding)!;
  // A token its platform hands out again is as old as the platform's cache; one of another platform beside it is an hour old at most.
  if (repeats && !REPEATING_PROFILES.includes(binding.profile as WorkloadProfile) && issuedRefusal(claims.iat, now / 1000) !== null) return { refused: 'too_old' };
  if (policy !== null && profileRefusal(binding, policy, claims) !== null) return { refused: 'malformed' };
  return { binding, policy, claims, spends: spends(binding, policy, wanted.kind) ? token.signingInputHash : null };
}

/**
 * Whether a token's signature verifies under keys a binding carries, a JWKS
 * as its row holds it: null if it does, `unknown_signer` when the set lacks
 * the key the token names, and `malformed` for any other failure, a
 * signature that does not verify under it included. The algorithms are
 * fixed, and nothing is taken from the header but `alg` and `kid`; a set
 * with several keys the header could name tries each. A token that does
 * not read as one (`readIdToken`), an unencoded payload's included, is
 * `malformed` before any key is tried. It checks no claim: the times and
 * the audience are `matchIdToken`'s.
 */
export async function signatureRefusal(token: string, jwks: string): Promise<'unknown_signer' | 'malformed' | null> {
  if ('refused' in readIdToken(token)) return 'malformed';
  let keys: JSONWebKeySet;
  try {
    keys = JSON.parse(jwks) as JSONWebKeySet;
  } catch {
    return 'malformed';
  }
  const options = { algorithms: [...WORKLOAD_ALGORITHMS] };
  try {
    await compactVerify(token, createLocalJWKSet(keys), options);
    return null;
  } catch (error) {
    if (error instanceof errors.JWKSNoMatchingKey) return 'unknown_signer';
    if (!(error instanceof errors.JWKSMultipleMatchingKeys)) return 'malformed';
    for await (const key of error) {
      try {
        await compactVerify(token, key, options);
        return null;
      } catch {
        // The next key the header could name.
      }
    }
    return 'malformed';
  }
}

/**
 * The claims of the run a credential was issued for, as its issuer stated
 * them: those that say which run, each bounded, in the exchange's entry and
 * the credential's row, so that a read leads back to its run. What the
 * issuer says, not proof of which run sent the request.
 */
export const RUN_CLAIMS = [
  'sub', 'jti', 'actor', 'event_name', 'ref', 'base_ref', 'head_ref', 'sha', 'repository', 'repository_id', 'run_id', 'run_attempt',
  'workflow_ref', 'job_workflow_ref', 'job_workflow_sha', 'environment',
  'project_path', 'project_id', 'namespace_id', 'pipeline_id', 'pipeline_source', 'job_id',
  'kubernetes.io.pod.name',
] as const;
export const MAX_RUN_CLAIM = 256;

/** The run's claims, as the issuer stated them: each a string of 256 characters at most, or a finite number. */
export function runClaims(claims: Record<string, unknown>): Record<string, string | number> {
  const run: Record<string, string | number> = {};
  for (const name of RUN_CLAIMS) {
    const value = claimAt(claims, name);
    if (typeof value === 'string') run[name] = value.slice(0, MAX_RUN_CLAIM);
    else if (typeof value === 'number' && Number.isFinite(value)) run[name] = value;
  }
  return run;
}
