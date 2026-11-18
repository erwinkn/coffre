import {
  audiencesOf,
  CARRIED,
  decodeWorkloadToken,
  differingClaims,
  generateToken,
  hashToken,
  MAX_BINDINGS,
  OIDC_PROFILES,
  PROFILE_URNS,
  REPEATING_PROFILES,
  soleAudience,
  verifyProof,
  WorkloadTokenRefused,
  type BindingClaims,
  type DecodedToken,
  type VerifiedUnder,
  type WorkloadProfile,
  type WorkloadsConfig,
} from '@coffre/core/identity';
import { isServiceMember, shownMember } from '@coffre/core/schemas';
import type { WorkloadProof } from '@coffre/core/vault';
import { z } from 'zod';

import { unknownKeyAlert } from './alerts.ts';
import { ApiError, noteTampered, notFound, refusal, UNAVAILABLE_RETRY_AFTER } from './api/errors.ts';
import { presented } from './auth.ts';
import { issuerBindings, type IssuerBinding } from './db/queries/bindings.ts';
import { environmentPaths } from './db/queries/places.ts';
import { errorResponse, jsonResponse, readLimitedJson } from './http.ts';
import { logged } from '@coffre/db/dialect';
import type { CoffreRuntime } from './runtime.ts';
import { dpopToken, provenSession, SessionRefused, sessionStopped, signedUrl, withNonce } from './sessions.ts';
import { checkAwsRequest, readStsAnswer, stsFetch, StsUnavailable } from './workloads/aws.ts';
import { IssuerUnavailable, verifyWithKeys } from './workloads/keys.ts';

/**
 * POST /api/auth/oidc: a CI run's ID token, for a five-minute token of the
 * service it names (docs/design/0.16.md, "A workload signing in"). `{
 * service, token }` answers `{ token, expiresAt }`.
 *
 * The app does what only it can, and decides nothing:
 *
 * 1. admission, before anything else: one limit per source address and one
 *    for all, a limiter that fails refusing; then the body, read only to its
 *    limit;
 * 2. the token's issuer, read from it unverified, and the service's live
 *    bindings on that issuer, one statement: a token none can take costs
 *    that read, and no vault call;
 * 3. its signature, under the keys of the newest binding that takes CI
 *    runs, fetched from where the binding says (`verifyWithKeys`); for one
 *    that carries its keys, the vault verifies it, under its own row's;
 * 4. one `token.exchange`, which reads the bindings again, on its own rows,
 *    and decides.
 *
 * Every refusal is 401 with its reason, as 0.14 answered, but too many at
 * once (429) and the issuer's keys out of reach (503), which are the app's.
 * A token signed by a key the binding's own keys lack is the deployment's
 * alert, once an hour per service at most, counted in the service's gate
 * (`unknownKeyAlert`). Each refusal is one line of the log, once a minute
 * per reason and service, in this isolate.
 *
 * 0.14.7's 60 credentials a minute per binding is not kept (D177): the
 * limit per source address bounds a flood.
 */
export async function exchangeToken(request: Request, runtime: CoffreRuntime, sourceIp: string | null, track: (work: Promise<unknown>) => void = () => {}, asked: ExchangeAsked = (body) => body): Promise<Response> {
  const workloads = runtime.auth.mode === 'signin' ? runtime.auth.signin.workloads : null;
  if (workloads === null) return errorResponse(notFound('this instance trusts no workloads'));
  // A strict instance issues no bearer credential to a service: its workloads sign in with a key.
  if (workloads.useOnly) {
    return jsonResponse({ error: 'gone', reason: 'use_only', message: 'this instance signs services in at /api/auth/workload, with a key (useOnly): it issues no bearer credential' }, 410);
  }
  const refused = await admission(workloads, sourceIp);
  if (refused !== null) return refused;
  if (inFlight >= MAX_IN_FLIGHT) return refuse('busy', 'too many exchanges under way: try again shortly', 429);
  inFlight++;
  try {
    return await exchanged(request, runtime, workloads, sourceIp, track, asked);
  } catch (error) {
    return errorResponse(error);
  } finally {
    inFlight--;
  }
}

/**
 * What a request's body asks for, `{ service, token }`, in the words of
 * whoever sent it: the API's own, or a plugin's (`PluginContext.exchange`),
 * Vault's `{ role, jwt }`. Read after admission, from the body read to its
 * limit; what it gives is held to `exchangeBody` as the API's is.
 */
export type ExchangeAsked = (body: unknown) => unknown;

/** An exchange's body: the service and the token, and nothing else, in at most this many bytes. */
const EXCHANGE_BODY_BYTES = 16 * 1024;
const exchangeBody = z.object({ service: z.string().max(256), token: z.string().max(8 * 1024) }).strict();

/** Exchanges under way at once in this isolate or process. */
const MAX_IN_FLIGHT = 32;
let inFlight = 0;

const REFUSED_CODE = { 401: 'unauthenticated', 429: 'too_many_requests', 503: 'unavailable' } as const;

/** An exchange refused, as its client reads it: 401 with the reason, or 429 and 503 with when to come back (`Retry-After`). */
function refuse(reason: string, message: string, status: 401 | 429 | 503 = 401, retryAfter?: string): Response {
  const later = retryAfter ?? (status === 503 ? UNAVAILABLE_RETRY_AFTER : '60');
  return jsonResponse({ error: REFUSED_CODE[status], reason, message }, status, status === 401 ? {} : { 'retry-after': later });
}

/** Both limits, before anything else. A limiter that fails refuses, and never lets a request through. Null when admitted. */
async function admission(workloads: WorkloadsConfig, sourceIp: string | null): Promise<Response | null> {
  try {
    const [source, total] = await Promise.all([
      workloads.limits.perSource.limit({ key: `source:${sourceIp ?? 'unknown'}` }),
      workloads.limits.total.limit({ key: 'total' }),
    ]);
    return source.success && total.success ? null : refuse('busy', 'too many exchanges: try again in a minute', 429);
  } catch (error) {
    console.error('workload limiter failed', logged(error));
    return refuse('busy', 'coffre cannot count exchanges right now: try again shortly', 503);
  }
}

/** What each of the vault's refusals tells a CI run, never what a binding expects. */
const WORDS: Record<string, string> = {
  audience: 'the token is not for this instance: its audience is not one a binding of the service takes',
  expired: 'the token has expired: ask your CI for a fresh one',
  too_old: 'the token is out of its time: issued over an hour ago, not valid yet, or valid for longer than the binding allows: ask your CI for a fresh one',
  malformed: "the token breaks its platform's rules, or its signature does not hold",
  replayed: 'this token was exchanged already: ask your CI for a fresh one',
  unknown_signer: "the token is signed by a key the binding's keys lack: if its issuer rotated them, upload them again",
};
/** The vault's words a run is told in 0.14.7's: `unknown_key` is a secret's key in the vault's, a signing key's on the wire. */
const SAID: Record<string, string> = { unknown_signer: 'unknown_key' };

async function exchanged(request: Request, runtime: CoffreRuntime, workloads: WorkloadsConfig, sourceIp: string | null, track: (work: Promise<unknown>) => void, asked: ExchangeAsked): Promise<Response> {
  const body = exchangeBody.parse(asked(await readLimitedJson(request, EXCHANGE_BODY_BYTES)));
  let decoded: DecodedToken;
  try {
    decoded = decodeWorkloadToken(body.token);
  } catch (error) {
    if (error instanceof WorkloadTokenRefused) {
      if (isServiceMember(body.service)) logRefusal(RUN, error.reason, body.service, sourceIp, {});
      return refuse(error.reason, error.message);
    }
    throw error;
  }
  const service = body.service;
  const issuer = decoded.claims.iss;
  const unbound = () => {
    logRefusal(RUN, 'no_match', service, sourceIp, {});
    return refuse('no_match', `no binding of ${shownMember(service)} trusts tokens from ${issuer}`);
  };
  if (!isServiceMember(service)) return unbound();
  // The rows the vault's exchange reads, in its order: past `MAX_BINDINGS` it takes none, and nor does the app.
  const live = await issuerBindings(runtime.db, service, issuer, MAX_BINDINGS + 1);
  const taking = live.length > MAX_BINDINGS ? [] : live.filter((binding) => binding.bearer);
  // A service's bindings on one issuer share its keys: one made after they moved replaced the rest.
  const newest = taking.at(-1);
  if (newest === undefined) return unbound();
  const under: VerifiedUnder = { issuer, jwksUri: newest.jwksUri };
  let claims: Record<string, unknown> | null = null;
  // Keys the binding carries are the vault's to verify under, on its own row: the app has no row it can trust.
  // Which those are, the address says, as the vault reads it (`CARRIED`): never the unchecked `jwks` column, which a row's writer could empty for the app alone.
  if (!newest.jwksUri.startsWith(CARRIED)) {
    try {
      claims = await verifyWithKeys(runtime.transport, newest.jwksUri, body.token, { issuer, audience: runtime.publicUrl, now: new Date() });
    } catch (error) {
      // Its keys are not fetched again until then (`workloads/keys.ts`): no sooner is any use.
      if (error instanceof IssuerUnavailable) return refuse('issuer_unavailable', error.message, 503, String(error.retryAfter));
      if (error instanceof WorkloadTokenRefused) {
        logRefusal(RUN, error.reason, service, sourceIp, {});
        return refuse(error.reason, error.message);
      }
      throw error;
    }
  }
  const token = generateToken('service');
  const requestId = crypto.randomUUID();
  const answer = await runtime.vault.change<'token.exchange'>({
    op: 'token.exchange',
    request: requestId,
    ip: sourceIp,
    service,
    token: body.token,
    under,
    publicUrl: runtime.publicUrl,
    credential: hashToken(token).toString('hex'),
  });
  if (!('refused' in answer)) return jsonResponse({ token, expiresAt: answer.answer.expiresAt });
  const reason = answer.refused;
  logRefusal(RUN, reason, service, sourceIp, reason === 'unknown_signer' ? { issuer, kid: shownKid(decoded.header) } : {});
  if (reason === 'unknown_signer') await unknownKeyAlert(workloads, runtime.gates, { service, binding: newest, issuer, kid: shownKid(decoded.header) }, sourceIp, track);
  if (reason === 'no_match') {
    // Which claims differ from the closest binding, by name, never the values it expects: told only of a token whose signature the app verified.
    const differ = claims === null ? null : closest(taking.filter((binding) => binding.jwksUri === newest.jwksUri), claims);
    return refuse('no_match', differ === null || differ.length === 0 ? `no binding of ${shownMember(service)} trusts this token` : `no binding of ${shownMember(service)} trusts these claims: ${differ.join(', ')} differ`);
  }
  return vaultRefused(reason, WORDS, 'POST /api/auth/oidc', requestId);
}

/** A refusal of the vault's, in `words` where they have it; a fault, `tampered` or `adopting`, as the API answers it. */
function vaultRefused(reason: string, words: Record<string, string>, route: string, requestId: string): Response {
  if (Object.hasOwn(words, reason)) return refuse(SAID[reason] ?? reason, words[reason]!);
  const error = refusal(reason);
  noteTampered(error, route, requestId);
  return error instanceof ApiError && error.code === 'vault_refused' ? refuse(reason, error.message) : errorResponse(error);
}

/** A workload's sign-in's body: the service, by its name or `token:<name>`, and one proof by its kind. */
const sessionBody = z.object({
  service: z.string().max(256),
  proof: z.record(z.string().max(32), z.unknown()).refine((proof) => Object.keys(proof).length === 1, 'a proof names one kind: { "oidc": "<token>" }'),
}).strict();

/** How far a sign-in's DPoP proof's `iat` may be from now: it carries no nonce, so its clock bounds it. */
const SIGNIN_SKEW_SECONDS = 60;

/** What each of the vault's refusals tells a workload signing in: a CI run's words, and a freeze, as 0.14.7 told it. */
const SESSION_WORDS: Record<string, string> = {
  ...WORDS,
  frozen: 'frozen: a manager stopped this service, its binding or every workload, and no session is made until they lift it',
};

/**
 * POST /api/auth/workload: a workload's proof, a platform's ID token or a
 * signed `GetCallerIdentity`, for a session bound to the key its DPoP proof
 * names (docs/design/0.16.md, "A workload signing in"). `{ service, proof:
 * { oidc: "<token>" } }` or `{ …, proof: { aws: { url, headers, body } } }`
 * answers `{ token, tokenType: 'DPoP', expiresAt, notAfter, places }`, the
 * places by path, with the gate's nonce (`DPoP-Nonce`) for its first
 * request.
 *
 * As at `/api/auth/oidc`, the app does what only it can, and decides
 * nothing:
 *
 * 1. admission, then the body, read only to its limit;
 * 2. the `DPoP` header: signed by the key, for this method and URL, within
 *    a minute; no nonce and no `ath`, since the platform's proof names the
 *    key or is spent;
 * 3. the service's live bindings on the proof's issuer, one statement: a
 *    proof none can take costs that read, and no call out or to the vault;
 * 4. an ID token's signature under the newest one's keys, fetched, and its
 *    audience, the key's where a binding names it (`audiencesOf`); or STS,
 *    asked whose credentials signed the AWS request (`workloads/aws.ts`);
 * 5. one `workload.signin`, which reads the bindings again and decides;
 * 6. the places, named by path, one statement, and the gate's nonce.
 */
export async function signInWorkload(request: Request, runtime: CoffreRuntime, sourceIp: string | null, track: (work: Promise<unknown>) => void = () => {}): Promise<Response> {
  const workloads = runtime.auth.mode === 'signin' ? runtime.auth.signin.workloads : null;
  if (workloads === null) return errorResponse(notFound('this instance trusts no workloads'));
  // No gate, no session that could be used: nothing is spent for one.
  if (runtime.gates === null) return errorResponse(new ApiError('unavailable', 'this deployment runs no workload gate, so it takes no workload session', 'no_gate'));
  const refused = await admission(workloads, sourceIp);
  if (refused !== null) return refused;
  if (inFlight >= MAX_IN_FLIGHT) return refuse('busy', 'too many exchanges under way: try again shortly', 429);
  inFlight++;
  try {
    return await signedIn(request, runtime, workloads, sourceIp, track);
  } catch (error) {
    return errorResponse(error);
  } finally {
    inFlight--;
  }
}

async function signedIn(request: Request, runtime: CoffreRuntime, workloads: WorkloadsConfig, sourceIp: string | null, track: (work: Promise<unknown>) => void): Promise<Response> {
  const body = sessionBody.parse(await readLimitedJson(request, EXCHANGE_BODY_BYTES));
  const header = request.headers.get('dpop');
  if (header === null) return refuse('dpop', 'a DPoP header, a proof signed by the key the session will be bound to, comes with the sign-in');
  const dpop = await verifyProof(header, { method: request.method, url: signedUrl(request, runtime.publicUrl), skewSeconds: SIGNIN_SKEW_SECONDS });
  if (!dpop.ok) return refuse('dpop', `the DPoP proof does not hold: ${dpop.message}`);
  const key = dpop.jkt;
  const service = body.service.startsWith('token:') ? body.service : `token:${body.service}`;
  const [kind] = Object.keys(body.proof) as [string];
  const given = body.proof[kind];
  const said = (reason: string, message: string, status?: 401 | 503) => {
    if (isServiceMember(service)) logRefusal(SIGNIN, reason, service, sourceIp, {});
    return refuse(reason, message, status);
  };
  if (kind !== 'oidc' && kind !== 'aws') return said('malformed', 'a proof is oidc or aws, by its kind: { "proof": { "oidc": "<token>" } }');
  const unbound = (why = `no workload binding of ${shownMember(service)} takes this proof`) => said('no_match', why);
  if (!isServiceMember(service)) return unbound();

  let proof: WorkloadProof;
  let signer: { binding: IssuerBinding; issuer: string; decoded: DecodedToken } | null = null;
  if (kind === 'oidc') {
    if (typeof given !== 'string' || given.length > 8 * 1024) return said('malformed', "an oidc proof is the platform's ID token");
    let decoded: DecodedToken;
    try {
      decoded = decodeWorkloadToken(given);
    } catch (error) {
      if (error instanceof WorkloadTokenRefused) return said(error.reason, error.message);
      throw error;
    }
    const issuer = decoded.claims.iss;
    // The rows the vault's sign-in reads, in its order: a workload's bindings, of an ID token's profiles; past `MAX_BINDINGS`, none.
    const live = await issuerBindings(runtime.db, service, issuer, MAX_BINDINGS + 1);
    const taking = live.length > MAX_BINDINGS ? [] : live.filter((binding) => binding.policy !== null && OIDC_PROFILES.includes(binding.profile as WorkloadProfile));
    const newest = taking.at(-1);
    if (newest === undefined) return unbound(`no workload binding of ${shownMember(service)} trusts tokens from ${issuer}`);
    if (!newest.jwksUri.startsWith(CARRIED)) {
      // The audience the token names, where a binding under these keys takes it (the key's, `#jkt=`); else the instance's, which then refuses it.
      const sharing = taking.filter((binding) => binding.jwksUri === newest.jwksUri);
      const wanted = { kind: 'session', jkt: key } as const;
      const named = soleAudience(decoded.claims.aud);
      const audience = named !== null && sharing.some((binding) => audiencesOf(binding, runtime.publicUrl, wanted).includes(named)) ? named : runtime.publicUrl;
      const taken = sharing.filter((binding) => audiencesOf(binding, runtime.publicUrl, wanted).includes(audience));
      // A token its platform hands out again is as old as its platform's cache: the vault holds it to its own `exp`.
      const repeats = taken.some((binding) => REPEATING_PROFILES.includes(binding.profile as WorkloadProfile));
      try {
        await verifyWithKeys(runtime.transport, newest.jwksUri, given, { issuer, audience, now: new Date(), ...(repeats ? { maxAge: null } : {}) });
      } catch (error) {
        if (error instanceof IssuerUnavailable) return refuse('issuer_unavailable', error.message, 503, String(error.retryAfter));
        if (error instanceof WorkloadTokenRefused) return said(error.reason, error.message);
        throw error;
      }
      // Its signature holds, and no binding takes its audience: as 0.14.7 told it, with no vault call.
      if (taken.length === 0) return said('audience', `the token is for ${audience}, which no workload binding of ${shownMember(service)} on ${issuer} takes: a platform that lets its caller choose names the session's key, ${runtime.publicUrl}#jkt=<thumbprint>`);
    }
    proof = { oidc: { token: given, under: { issuer, jwksUri: newest.jwksUri } } };
    signer = { binding: newest, issuer, decoded };
  } else {
    const checked = checkAwsRequest(given, { publicUrl: runtime.publicUrl, jkt: key, now: Date.now() });
    if ('refused' in checked) return said(checked.refused, checked.message);
    // A proof no binding could take asks STS nothing.
    const live = await issuerBindings(runtime.db, service, PROFILE_URNS.aws, MAX_BINDINGS + 1);
    if (live.length > MAX_BINDINGS || !live.some((binding) => binding.policy !== null && binding.profile === 'aws')) return unbound(`${shownMember(service)} has no aws binding`);
    let answer: ReturnType<typeof readStsAnswer>;
    try {
      answer = readStsAnswer(await (runtime.transport.sts ?? stsFetch())(checked));
    } catch (error) {
      if (!(error instanceof StsUnavailable)) throw error;
      console.error({ event: 'sts_unavailable', region: checked.region, error: error.message }, 'STS could not check an aws proof');
      return refuse('issuer_unavailable', 'STS could not be asked about the aws proof: try again', 503);
    }
    if ('refused' in answer) return said(answer.refused, answer.message);
    proof = { aws: answer };
  }

  const token = generateToken('workload');
  const requestId = crypto.randomUUID();
  const answer = await runtime.vault.change<'workload.signin'>({
    op: 'workload.signin',
    request: requestId,
    ip: sourceIp,
    service,
    proof,
    key,
    publicUrl: runtime.publicUrl,
    credential: hashToken(token).toString('hex'),
  });
  if ('refused' in answer) {
    const reason = answer.refused;
    logRefusal(SIGNIN, reason, service, sourceIp, reason === 'unknown_signer' && signer !== null ? { issuer: signer.issuer, kid: shownKid(signer.decoded.header) } : {});
    if (reason === 'unknown_signer' && signer !== null) await unknownKeyAlert(workloads, runtime.gates, { service, binding: signer.binding, issuer: signer.issuer, kid: shownKid(signer.decoded.header) }, sourceIp, track);
    if (reason === 'no_match') return unbound();
    return vaultRefused(reason, SESSION_WORDS, 'POST /api/auth/workload', requestId);
  }
  const made = answer.answer;
  const places = await environmentPaths(runtime.db, made.places);
  const nonce = await gateNonce(runtime, service);
  return jsonResponse({ token, tokenType: 'DPoP', expiresAt: made.expiresAt, notAfter: made.notAfter, places }, 200, nonce === null ? {} : { 'dpop-nonce': nonce });
}

/** The gate's current nonce, for an answer that admits no proof; null when it cannot say, which costs the workload one retry. */
async function gateNonce(runtime: CoffreRuntime, service: string): Promise<string | null> {
  try {
    return await runtime.gates!(service).nonce();
  } catch (error) {
    console.error('the workload gate failed', logged(error));
    return null;
  }
}

/**
 * POST /api/auth/workload/renew: a session's expiry moved on, an hour from
 * now and never past its hard end, by a proof of its key: `{ expiresAt }`,
 * with the gate's nonce. The request is held to its session as any of its
 * requests is (`provenSession`: one statement and its gate), then one
 * `workload.renew`, which decides. A frozen session renews, so that lifting
 * the freeze restores it; a narrowed one does not, as it ends with its
 * parent; one within five seconds of its end is `expired`.
 */
export async function renewWorkload(request: Request, runtime: CoffreRuntime, sourceIp: string | null): Promise<Response> {
  // Behind Access a workload's session is a machine's credential, which the API refuses.
  const token = runtime.auth.mode === 'cloudflare' ? null : dpopToken(request);
  if (token === null) return errorResponse(new ApiError('unauthenticated', "this takes a workload's session, Authorization: DPoP coffre_wl_…, with its key's proof"));
  let nonce: string | null = null;
  try {
    const proven = await provenSession(request, runtime, token);
    nonce = proven.nonce;
    const shown = presented(token, sourceIp, proven.proof);
    const renewed = await runtime.vault.change<'workload.renew'>({ ...shown, op: 'workload.renew' });
    if (!('refused' in renewed)) return jsonResponse(renewed.answer, 200, { 'dpop-nonce': nonce });
    if (renewed.refused === 'expired') return withNonce(refuse('expired', 'this session ends within seconds, or has: sign in again'), nonce);
    const error = refusal(renewed.refused);
    noteTampered(error, 'POST /api/auth/workload/renew', shown.request);
    throw error;
  } catch (error) {
    if (error instanceof SessionRefused) return error.response;
    const response = errorResponse(sessionStopped(error, sourceIp));
    return nonce === null ? response : withNonce(response, nonce);
  }
}

/** The claims that differ from the binding that comes closest, by name. */
function closest(bindings: readonly IssuerBinding[], claims: Record<string, unknown>): string[] | null {
  let best: string[] | null = null;
  for (const binding of bindings) {
    let expected: BindingClaims;
    try {
      expected = JSON.parse(binding.claims) as BindingClaims;
    } catch {
      continue;
    }
    const differ = differingClaims(binding.profile as WorkloadProfile, expected, claims);
    if (best === null || differ.length < best.length) best = differ;
  }
  return best;
}

/** When each reason and service last logged a refusal, in this isolate: settled values only. */
const refusalsLogged = new Map<string, number>();
const REFUSAL_LOG_MS = 60 * 1000;
const MAX_LOGGED = 1_000;

/** What a refusal's log line says was refused. */
const RUN = "a CI run's exchange";
const SIGNIN = "a workload's sign-in";

/** One line per route, reason and service a minute, in this isolate, as 0.14.7 logged them: enough to see a refusal, not a flood. */
function logRefusal(what: typeof RUN | typeof SIGNIN, reason: string, service: string, sourceIp: string | null, named: { issuer?: string; kid?: string | null }): void {
  const key = `${what} ${reason} ${service}`;
  const now = Date.now();
  if (now - (refusalsLogged.get(key) ?? -Infinity) < REFUSAL_LOG_MS) return;
  refusalsLogged.delete(key);
  refusalsLogged.set(key, now);
  while (refusalsLogged.size > MAX_LOGGED) refusalsLogged.delete(refusalsLogged.keys().next().value!);
  console.error({ event: 'workload_exchange_refused', reason, service, sourceIp, ...named }, `${what} for ${shownMember(service)} was refused: ${reason}`);
}

/** The kid a token names, as an alert shows it: at most 64 characters a kid uses. */
function shownKid(header: Record<string, unknown>): string | null {
  const kid = header.kid;
  return typeof kid === 'string' && /^[A-Za-z0-9._~+/=:-]{1,64}$/.test(kid) ? kid : null;
}
