import { verifyProof } from '@coffre/core/identity';
import { z } from 'zod';

import { unknownKeyAlert } from './alerts.ts';
import { ApiError, notFound, UNAVAILABLE_RETRY_AFTER } from './api/errors.ts';
import { ExchangeRefused, UnknownKey, type WorkloadService } from './api/workloads.ts';
import { dpopToken, SessionRefused, signedUrl, standingSession } from './workload-sessions.ts';
import { errorResponse, jsonResponse, readLimitedJson } from './http.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';

// 0.14's workload sessions under `/api/auth`, the source to port from when
// they join the 0.16 skeleton with the gate. Sign-in's paths are in
// signin.ts, a CI run's exchange in exchange.ts.

/** A sign-in's body, in at most this many bytes. */
const EXCHANGE_BODY_BYTES = 16 * 1024;

const REFUSED_CODE = { 401: 'unauthenticated', 429: 'too_many_requests', 503: 'unavailable' } as const;

/** An exchange refused, as its client reads it: 401 with the reason, or 429 and 503 with when to come back (`Retry-After`). */
function refuseExchange(error: ExchangeRefused, headers: Record<string, string> = {}): Response {
  // A 503 is coffre, or what it asked, not answering for a moment (`errorResponse`): a limiter that could not count, STS.
  const later = error.retryAfter ?? (error.status === 503 ? UNAVAILABLE_RETRY_AFTER : error.reason === 'full' ? '30' : '60');
  return jsonResponse(
    { error: REFUSED_CODE[error.status], reason: error.reason, message: error.message },
    error.status,
    error.status === 401 ? headers : { ...headers, 'retry-after': later },
  );
}

/**
 * Both exchanges' admission, before anything else: one limit per source
 * address and one for all. A limiter that fails refuses, and never lets a
 * request through. Null when admitted.
 */
async function admission(workloads: WorkloadService, sourceIp: string | null): Promise<Response | null> {
  try {
    const [source, total] = await Promise.all([
      workloads.limits.perSource.limit({ key: `source:${sourceIp ?? 'unknown'}` }),
      workloads.limits.total.limit({ key: 'total' }),
    ]);
    return source.success && total.success ? null : refuseExchange(new ExchangeRefused('busy', 'too many exchanges: try again in a minute', 429));
  } catch (error) {
    console.error('workload limiter failed', logged(error));
    return refuseExchange(new ExchangeRefused('busy', 'coffre cannot count exchanges right now: try again shortly', 503));
  }
}

/** A workload's sign-in body: the service, and one proof by its kind, in at most this many bytes. */
const sessionBody = z.object({
  service: z.string().max(120),
  proof: z.record(z.string().max(32), z.unknown()).refine((proof) => Object.keys(proof).length === 1, 'a proof names one kind: { "oidc": "<token>" }'),
}).strict();

/** How far a sign-in's proof's `iat` may be from now: it carries no nonce, so its clock bounds it (section 4.1). */
const EXCHANGE_SKEW_SECONDS = 60;

/**
 * POST /api/auth/workload: a workload's proof, an ID token, a signed
 * `GetCallerIdentity` or an enrollment code, for a session bound to the
 * key its DPoP proof names (docs/design/workload-access.md, section 4.1).
 * `{ service, proof: { <kind>: … } }` answers `{ token, tokenType: 'DPoP',
 * expiresAt, notAfter, places }`, or 202 `{ pending, approve }` for a
 * session that waits for a person's approval, with the gate's nonce.
 *
 * Admission first, as for `/api/auth/oidc`; then the body, read only to
 * its limit; its shape; and its `DPoP` header: signed by the key, for this
 * method and URL, within a minute. No nonce, no `ath`: the platform proof
 * is spent or names the key, and the key is the caller's own. Then the
 * proof, by its kind (`WorkloadService.signIn`). A token signed by a key
 * the service's uploaded keys lack alerts, once an hour per service at
 * most (`unknownKeyAlert`), as it does at `/api/auth/oidc`.
 */
export async function exchangeWorkloadSession(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const workloads = runtime.workloads;
  if (workloads === null) return errorResponse(notFound('this instance trusts no workloads'));
  // No gate, no session that could be used: nothing is spent for one.
  if (runtime.gates === undefined) return errorResponse(new ApiError('unavailable', 'this deployment runs no workload gate, so it takes no workload session', 'no_gate'));
  const refused = await admission(workloads, sourceIp);
  if (refused !== null) return refused;
  try {
    const body = sessionBody.parse(await readLimitedJson(request, EXCHANGE_BODY_BYTES));
    const header = request.headers.get('dpop');
    if (header === null) return refuseExchange(new ExchangeRefused('dpop', "a DPoP header, a proof signed by the key the session will be bound to, comes with the sign-in"));
    const proof = await verifyProof(header, { method: request.method, url: signedUrl(request, runtime.publicUrl), skewSeconds: EXCHANGE_SKEW_SECONDS });
    if (!proof.ok) return refuseExchange(new ExchangeRefused('dpop', `the DPoP proof does not hold: ${proof.message}`));
    const made = await workloads.signIn(body, { requestId: crypto.randomUUID(), sourceIp, jkt: proof.jkt });
    const nonce = await gateNonce(runtime, body.service);
    return jsonResponse(made, 'pending' in made ? 202 : 200, nonce === null ? {} : { 'dpop-nonce': nonce });
  } catch (error) {
    if (error instanceof UnknownKey) await unknownKeyAlert(runtime, error, sourceIp);
    if (error instanceof ExchangeRefused) return refuseExchange(error);
    return errorResponse(error);
  }
}

/** The gate's current nonce for a service, for an answer that admits no proof; null when it cannot say, which costs the workload one retry. */
async function gateNonce(runtime: CoffreRuntime, service: string): Promise<string | null> {
  if (runtime.gates === undefined) return null;
  try {
    return await runtime.gates(service.startsWith('token:') ? service : `token:${service}`).nonce();
  } catch (error) {
    console.error('the workload gate failed', logged(error));
    return null;
  }
}

/**
 * POST /api/auth/workload/renew: a session's expiry moved on, by a proof
 * of its key, `{ expiresAt }` (section 5.4). Its session as every request
 * checks it, in one statement and with no vault call; never a `narrow`
 * child's, which ends with its parent or its own expiry.
 */
export async function renewWorkloadSession(request: Request, runtime: CoffreRuntime, sourceIp: string | null) {
  const workloads = runtime.workloads;
  const token = dpopToken(request);
  if (workloads === null || token === null) return errorResponse(new ApiError('unauthenticated', "this takes a workload's session, Authorization: DPoP coffre_wl_…, with its key's proof"));
  try {
    // A frozen session renews: the freeze stops its use, and lifting it restores the session (section 8.2).
    const session = await standingSession(request, runtime, token, sourceIp, { place: null, credential: null, freezes: false });
    return jsonResponse(await workloads.renew(session, { requestId: crypto.randomUUID(), sourceIp }), 200, { 'dpop-nonce': session.nonce });
  } catch (error) {
    if (error instanceof SessionRefused) return error.response;
    if (error instanceof ExchangeRefused) return refuseExchange(error);
    return errorResponse(error);
  }
}
