import { expectedAudiences, PROFILE_RULES } from './profile-rules.ts';
import { CLOCK_TOLERANCE_SECONDS, decodeWorkloadToken, MAX_TOKEN_AGE_SECONDS, uploadedKeys, verifyWorkloadToken, WorkloadTokenRefused, type JSONWebKeySet } from './workload-token.ts';
import { claimAt, differingClaims, REPEATING_PROFILES, type BindingClaims, type BindingPolicy, type WorkloadProfile } from './workloads.ts';

/**
 * The claims of the run a credential was issued for, as the issuer
 * asserted them: in the sign-in's record, so that a read leads back to its
 * run. What the issuer says, not proof of which run sent the request.
 */
export const RUN_CLAIMS = [
  'sub', 'jti', 'actor', 'event_name', 'ref', 'base_ref', 'head_ref', 'sha', 'repository', 'repository_id', 'run_id', 'run_attempt',
  'workflow_ref', 'job_workflow_ref', 'job_workflow_sha', 'environment',
  'project_path', 'project_id', 'namespace_id', 'pipeline_id', 'pipeline_source', 'job_id',
  'kubernetes.io.pod.name',
] as const;
const MAX_RUN_CLAIM = 256;

/** A binding's `jwks_uri` when it carries its issuer's keys: the SHA-256 of those keys (`UploadedKeys`), where a fetched set's URL would be. */
export const UPLOADED_KEYS = 'sha256:';

/** The run's claims, as the issuer stated them: those that say which run, each bounded. */
export function runClaims(claims: Record<string, unknown>): Record<string, string | number> {
  const run: Record<string, string | number> = {};
  for (const name of RUN_CLAIMS) {
    const value = claimAt(claims, name);
    if (typeof value === 'string') run[name] = value.slice(0, MAX_RUN_CLAIM);
    else if (typeof value === 'number' && Number.isFinite(value)) run[name] = value;
  }
  return run;
}

/** A token's one audience, or null for none or several: a token for several parties is no single party's. */
export function soleAudience(aud: unknown): string | null {
  if (typeof aud === 'string') return aud;
  return Array.isArray(aud) && aud.length === 1 && typeof aud[0] === 'string' ? aud[0] : null;
}

/**
 * A binding as the vault weighs a sign-in through it (T149, PR 3b): its
 * sealed object's columns, the instance it was made on (`origin`), and the
 * keys uploaded with it as its row keeps them, which must be the ones its
 * `jwksUri` digests. Only such a binding's: the vault fetches nothing, so
 * the tokens of an issuer that publishes its keys are the app's to verify.
 */
export type RunBinding = {
  profile: WorkloadProfile;
  issuer: string;
  origin: string;
  jwksUri: string;
  jwks: string;
  claims: string;
  policy: string | null;
};

/** Why a run's proof buys nothing, as the app's refusals say it (`ExchangeReason`), with the key a refused token named. */
export class RunProofRefused extends Error {
  readonly reason: string;
  readonly kid: string | null;
  constructor(reason: string, message: string, kid: string | null = null) {
    super(message);
    this.name = 'RunProofRefused';
    this.reason = reason;
    this.kid = kid;
  }
}

/** What a run's proof says, verified: what the credential it buys is held to. */
export type RunProof = {
  claims: Record<string, unknown>;
  /** The run's claims, for the sign-in's record. */
  run: Record<string, string | number>;
  /** The token's signing input's hash, spent once; null for a token its platform hands out again, or one that names the session's key. */
  spent: Buffer | null;
  /** The last instant the token holds by its own times, ms: a CI run's (its `exp`, its `iat`'s hour); null for a workload's session. */
  validUntil: number | null;
  /** A workload's session's hard end by the token, ms (its `exp`); null when the token names the session's key, or for a CI run. */
  notAfter: number | null;
};

/** A token's `kid`, at most 64 characters, for a refusal and the alert it raises; the token is unverified. */
function shownKid(header: Record<string, unknown>): string | null {
  return typeof header.kid === 'string' ? header.kid.slice(0, 64) : null;
}

/**
 * Verify a CI run's or a workload's ID token against one binding, sealed
 * (D148), whose keys were uploaded with it: the vault's own check, which
 * no app can steer, and which asks no one. The binding's keys, held to the
 * digest its seal covers (a key they lack is refused, never looked for),
 * its issuer, its audience (the instance it was made on, or, for a
 * platform whose caller names the session's key, that key: `jkt`, from the
 * DPoP proof the vault verified, never from the app), the token's times,
 * the binding's claims and its profile's rules. Throws `RunProofRefused`.
 */
export async function verifyRunToken(
  token: string,
  binding: RunBinding,
  context: { now: Date; workload: { jkt: string } | null },
): Promise<RunProof> {
  let decoded: ReturnType<typeof decodeWorkloadToken>;
  try {
    decoded = decodeWorkloadToken(token);
  } catch (error) {
    throw refusedBy(error);
  }
  const { claims: unverified, header } = decoded;
  if (unverified.iss !== binding.issuer) throw new RunProofRefused('no_match', `the token is from ${unverified.iss}, which this binding does not trust`);
  const policy = binding.policy === null ? null : (JSON.parse(binding.policy) as BindingPolicy);
  if ((context.workload === null) !== (policy === null)) throw new RunProofRefused('no_match', 'a CI run signs in through a binding with no policy, a workload through one with');
  // The audience the binding takes: the instance's, or, for a workload, its profile's (the session's key among them).
  const accepted = context.workload === null
    ? [binding.origin]
    : expectedAudiences(binding.profile, policy!, { publicUrl: binding.origin, jkt: context.workload.jkt });
  const named = soleAudience(unverified.aud);
  const audience = named !== null && accepted.includes(named) ? named : accepted[0]!;
  const repeating = context.workload !== null && REPEATING_PROFILES.includes(binding.profile);
  const expected = { issuer: binding.issuer, audience, now: context.now, ...(repeating ? { maxAge: null } : {}) };
  let claims: Record<string, unknown>;
  try {
    // The very keys its seal digests, never others the app names (a forged set).
    const uploaded = await uploadedKeys(JSON.parse(binding.jwks) as unknown);
    if (`${UPLOADED_KEYS}${uploaded.digest}` !== binding.jwksUri) throw new RunProofRefused('keys', 'the keys are not those the binding was made with');
    // No issuer to ask whether a token still stands, so none lives past the hour.
    claims = await verifyWorkloadToken(token, JSON.parse(uploaded.jwks) as JSONWebKeySet, { ...expected, maxLifetime: MAX_TOKEN_AGE_SECONDS });
  } catch (error) {
    if (error instanceof RunProofRefused) throw error;
    if (error instanceof WorkloadTokenRefused && error.reason === 'unknown_key') {
      throw new RunProofRefused('unknown_key', error.message, shownKid(header));
    }
    throw refusedBy(error);
  }
  const differ = differingClaims(binding.profile, JSON.parse(binding.claims) as BindingClaims, claims);
  if (differ.length > 0) throw new RunProofRefused('no_match', `the binding does not trust these claims: ${differ.join(', ')} differ`);
  if (context.workload !== null) {
    const ruled = PROFILE_RULES[binding.profile]?.token(claims, { issuer: binding.issuer, claims: JSON.parse(binding.claims) as BindingClaims, policy: policy! }) ?? null;
    if (ruled !== null) throw new RunProofRefused('no_match', ruled);
  }
  const run = runClaims(claims);
  if (context.workload === null) {
    // The token's own times, held to again in the statement: its `exp`, and its `iat`'s hour, whole ms, down.
    const validUntil = Math.floor(Math.min((decoded.claims.exp + CLOCK_TOLERANCE_SECONDS) * 1000, (decoded.claims.iat + MAX_TOKEN_AGE_SECONDS) * 1000));
    return { claims, run, spent: decoded.signingInputHash, validUntil, notAfter: null };
  }
  // A token that names the session's key, or one its platform hands out again, is never spent; any other once. One that
  // does not name the key ends the session at its own `exp`.
  const namesKey = policy!.keyAudience === true;
  return {
    claims, run,
    spent: namesKey || repeating ? null : decoded.signingInputHash,
    validUntil: null,
    notAfter: namesKey ? null : decoded.claims.exp * 1000,
  };
}

function refusedBy(error: unknown): RunProofRefused {
  if (error instanceof WorkloadTokenRefused) return new RunProofRefused(error.reason, error.message);
  if (error instanceof RunProofRefused) return error;
  return new RunProofRefused('malformed', (error as Error)?.message ?? 'the token is not one coffre reads');
}
