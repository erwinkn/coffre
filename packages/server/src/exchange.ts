import {
  CARRIED,
  decodeWorkloadToken,
  differingClaims,
  generateToken,
  hashToken,
  MAX_BINDINGS,
  WorkloadTokenRefused,
  type BindingClaims,
  type DecodedToken,
  type VerifiedUnder,
  type WorkloadAlert,
  type WorkloadProfile,
  type WorkloadsConfig,
} from '@coffre/core/identity';
import { isServiceMember, shownMember } from '@coffre/core/schemas';
import { z } from 'zod';

import { ApiError, noteTampered, notFound, refusal, UNAVAILABLE_RETRY_AFTER } from './api/errors.ts';
import { issuerBindings, type IssuerBinding } from './db/queries/bindings.ts';
import { errorResponse, jsonResponse, readLimitedJson } from './http.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';
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
 * alert, once an hour per service in this isolate at most: 0.14.7 kept that
 * count in the database, once per deployment, and the service's gate will
 * keep it in 0.16; until then each new isolate may say it again. Each
 * refusal is one line of the log, once a minute per reason and service.
 *
 * Not yet: 0.14.7's count of what one binding issued a minute (60), which
 * the service's gate keeps in 0.16, with the workload's sessions.
 */
export async function exchangeToken(request: Request, runtime: CoffreRuntime, sourceIp: string | null, track: (work: Promise<unknown>) => void = () => {}): Promise<Response> {
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
    return await exchanged(request, runtime, workloads, sourceIp, track);
  } catch (error) {
    return errorResponse(error);
  } finally {
    inFlight--;
  }
}

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

async function exchanged(request: Request, runtime: CoffreRuntime, workloads: WorkloadsConfig, sourceIp: string | null, track: (work: Promise<unknown>) => void): Promise<Response> {
  const body = exchangeBody.parse(await readLimitedJson(request, EXCHANGE_BODY_BYTES));
  let decoded: DecodedToken;
  try {
    decoded = decodeWorkloadToken(body.token);
  } catch (error) {
    if (error instanceof WorkloadTokenRefused) {
      if (isServiceMember(body.service)) logRefusal(error.reason, body.service, sourceIp, {});
      return refuse(error.reason, error.message);
    }
    throw error;
  }
  const service = body.service;
  const issuer = decoded.claims.iss;
  const unbound = () => {
    logRefusal('no_match', service, sourceIp, {});
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
      // Its keys are not fetched again for a minute (`workloads/keys.ts`): no sooner is any use.
      if (error instanceof IssuerUnavailable) return refuse('issuer_unavailable', error.message, 503, '60');
      if (error instanceof WorkloadTokenRefused) {
        logRefusal(error.reason, service, sourceIp, {});
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
  logRefusal(reason, service, sourceIp, reason === 'unknown_signer' ? { issuer, kid: shownKid(decoded.header) } : {});
  if (reason === 'unknown_signer') await unknownKey(workloads, service, newest, issuer, decoded, sourceIp, track);
  if (reason === 'no_match') {
    // Which claims differ from the closest binding, by name, never the values it expects: told only of a token whose signature the app verified.
    const differ = claims === null ? null : closest(taking.filter((binding) => binding.jwksUri === newest.jwksUri), claims);
    return refuse('no_match', differ === null || differ.length === 0 ? `no binding of ${shownMember(service)} trusts this token` : `no binding of ${shownMember(service)} trusts these claims: ${differ.join(', ')} differ`);
  }
  if (Object.hasOwn(WORDS, reason)) return refuse(SAID[reason] ?? reason, WORDS[reason]!);
  // A fault, `tampered` or `adopting`: answered as the API answers it.
  const error = refusal(reason);
  noteTampered(error, 'POST /api/auth/oidc', requestId);
  return error instanceof ApiError && error.code === 'vault_refused' ? refuse(reason, error.message) : errorResponse(error);
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

/** One line per reason and service a minute, in this isolate, as 0.14.7 logged them: enough to see a refusal, not a flood. */
function logRefusal(reason: string, service: string, sourceIp: string | null, named: { issuer?: string; kid?: string | null }): void {
  const key = `${reason} ${service}`;
  const now = Date.now();
  if (now - (refusalsLogged.get(key) ?? -Infinity) < REFUSAL_LOG_MS) return;
  refusalsLogged.delete(key);
  refusalsLogged.set(key, now);
  while (refusalsLogged.size > MAX_ALERTED) refusalsLogged.delete(refusalsLogged.keys().next().value!);
  console.error({ event: 'workload_exchange_refused', reason, service, sourceIp, ...named }, `a CI run's exchange for ${shownMember(service)} was refused: ${reason}`);
}

/** When each service's unknown key last alerted, in this isolate: settled values only. */
const alerted = new Map<string, number>();
const UNKNOWN_KEY_ALERT_MS = 60 * 60 * 1000;
/** How long the refusal waits on the deployment's alert: past it, it answers, and the alert goes on without it. */
const ALERT_WAIT_MS = 2_000;
const MAX_ALERTED = 1_000;

/** The kid a token names, as an alert shows it: at most 64 characters a kid uses. */
function shownKid(header: Record<string, unknown>): string | null {
  const kid = header.kid;
  return typeof kid === 'string' && /^[A-Za-z0-9._~+/=:-]{1,64}$/.test(kid) ? kid : null;
}

/**
 * A token signed by a key its binding's own keys lack: its issuer most
 * likely rotated them, and none of the service's runs signs in until a
 * manager uploads them again. The deployment's alert, once an hour per
 * service in this isolate at most, waited on for 2 s at most and finished
 * after the response (`track`); never throws.
 */
async function unknownKey(workloads: WorkloadsConfig, service: string, binding: IssuerBinding, issuer: string, decoded: DecodedToken, sourceIp: string | null, track: (work: Promise<unknown>) => void): Promise<void> {
  const now = Date.now();
  if (workloads.alert === null || now - (alerted.get(service) ?? -Infinity) < UNKNOWN_KEY_ALERT_MS) return;
  alerted.delete(service);
  alerted.set(service, now);
  while (alerted.size > MAX_ALERTED) alerted.delete(alerted.keys().next().value!);
  const name = service.slice('token:'.length);
  const kid = shownKid(decoded.header);
  const fetch = binding.profile === 'kubernetes' ? 'kubectl get --raw /openid/v1/jwks > keys.json' : 'save its JWKS as keys.json';
  const alert: WorkloadAlert = {
    kind: 'unknown_key',
    service,
    binding: binding.id,
    session: null,
    ip: sourceIp,
    text: `${name}'s sign-in${sourceIp === null ? '' : ` from ${sourceIp}`} was refused: its token ${kid === null ? 'names no key' : `names key "${kid}"`}, not one uploaded for ${issuer}. `
      + `If that issuer rotated its keys, upload them again: ${fetch}, then coffre trust ${shellWord(shownMember(service))} --issuer ${shellWord(issuer)} --replace-keys --jwks-file keys.json --apply. Said once an hour at most.`,
  };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const sent = (async () => workloads.alert!(alert))().catch((error: unknown) => console.error("the deployment's workload alert failed", logged(error)));
  // Said once an hour: a hook slower than the wait still finishes, the platform keeping the request alive for it.
  track(sent);
  await Promise.race([sent, new Promise<void>((resolve) => (timer = setTimeout(resolve, ALERT_WAIT_MS)))]);
  clearTimeout(timer);
}

/** `word` as one shell word: as it is when it needs no quoting, as an issuer URL does not. */
function shellWord(word: string): string {
  return /^[A-Za-z0-9._~:/@%+=,-]+$/.test(word) ? word : `'${word.replaceAll("'", "'\\''")}'`;
}
