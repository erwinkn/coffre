// A workload's session, on each of its requests (docs/design/0.16.md, "What
// the app reads of a workload, and decides nothing on"). Its token comes as
// `Authorization: DPoP coffre_wl_…`, with a proof its key signed for this
// request, and the app holds the one to the other before the vault hears of
// it, cheapest first:
//
//   1. the proof's shape, with no I/O (`parseProof`);
//   2. one statement: the session's row by the token's hash, for its
//      service and its key (`routedSession`), unchecked;
//   3. the proof against the request: signed by that key, for this method,
//      URL and token (`verifyProof`);
//   4. the service's gate: the nonce it gave, the proof's `jti` once.
//
// Only then is the key's thumbprint the request's `proof`, and the vault
// decides on its own rows: whether the session stands, its key, its
// binding, what stops it. A token without its key learns nothing and costs
// no vault call; a proof replayed is refused before it can make a change
// twice. A row edited behind the vault can send a proof to the wrong gate,
// which never issued its nonce, or name a key the vault's row does not.
import { hashToken, parseProof, tokenKind, verifyProof, type GateAdmission, type GateCount, type ParsedProof } from '@coffre/core/identity';

import { limitAlert, sendAlert } from './alerts.ts';
import { ApiError } from './api/errors.ts';
import { routedSession, type RoutedSession } from './db/queries/sessions.ts';
import { errorResponse, jsonResponse } from './http.ts';
import { logged } from '@coffre/db/dialect';
import type { CoffreRuntime } from './runtime.ts';

/** `Authorization: DPoP <token>`: a workload's session; null for any other scheme. */
export function dpopToken(request: Request): string | null {
  const match = /^DPoP\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  return match === null ? null : match[1]!;
}

/**
 * The request's URL as `publicUrl` spells it, with its path and query as
 * received: what the proof's `htu` signs. Built from the origin, so a path
 * starting with `//` stays a path.
 */
export function signedUrl(request: Request, publicUrl: string): string {
  const url = new URL(request.url);
  return `${new URL(publicUrl).origin}${url.pathname}${url.search}`;
}

/** A session's request refused before the vault was asked, as the workload's SDK reads it: the status, a reason, and the headers RFC 9449 asks for. */
export class SessionRefused extends Error {
  readonly response: Response;
  constructor(response: Response) {
    super('workload session refused');
    this.name = 'SessionRefused';
    this.response = response;
  }
}

const refused = (error: ApiError, headers: HeadersInit = {}) => new SessionRefused(errorResponse(error, headers));

/** The vault's own answer for a credential that does not stand, so that the app's says no more. */
export const unknown = () => refused(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'));

/** A proof refused (RFC 9449, section 7.1): 401, `invalid_dpop_proof`, and why. */
const proofRefused = (reason: string, message: string) => refused(new ApiError('unauthenticated', message, reason), { 'www-authenticate': 'DPoP error="invalid_dpop_proof"' });

/** A proof without the gate's current nonce: 401, `use_dpop_nonce`, and the nonce to sign with, which the SDK retries with once. */
const useNonce = (nonce: string) =>
  new SessionRefused(jsonResponse(
    { error: 'unauthenticated', reason: 'use_dpop_nonce', message: "sign the proof with coffre's current nonce, in DPoP-Nonce" },
    401,
    { 'www-authenticate': 'DPoP error="use_dpop_nonce"', 'dpop-nonce': nonce },
  ));

/**
 * What stops a session the gate took, as 0.14.7 answered its workload: the
 * vault's word is the same whatever it was asked (`caller`, a use, a
 * change), and the API's own mapping is a person's (`no_reads` there is a
 * binding refused, 400). A workload's session binds nothing, so any
 * `no_reads` it meets is its own binding's.
 */
const STOPS: Record<string, (sourceIp: string | null) => ApiError> = {
  pending: () => new ApiError('unauthenticated', 'this session waits for a manager of its service to approve it', 'pending'),
  narrowed: () => new ApiError('forbidden', 'a narrowed session reaches only /use, narrow and logout', 'narrowed'),
  no_reads: () => new ApiError('forbidden', 'this instance lets no binding list reads (noReads): bind the workload again without them', 'no_reads'),
  source: (ip) => new ApiError('unauthenticated', ip === null ? 'coffre cannot tell where this request comes from, and the binding names its sources' : `${ip} is outside the binding's sources`, 'source'),
  frozen: () => new ApiError('forbidden', 'frozen: a manager stopped this use; nothing passes until they lift it', 'frozen'),
};

/** A workload's request's error, its session's stop worded as 0.14.7 did; any other as it is. */
export function sessionStopped(error: unknown, sourceIp: string | null): unknown {
  if (!(error instanceof ApiError) || error.reason === undefined || !Object.hasOwn(STOPS, error.reason)) return error;
  return STOPS[error.reason]!(sourceIp);
}

/** A session's request the gate took: the thumbprint the vault holds the session to, and the nonce its answer carries (`DPoP-Nonce`). */
export type ProvenSession = { proof: string; nonce: string };

/**
 * The proof of the request `token` came with, held to it and taken by its
 * service's gate, or throws `SessionRefused`. One statement and one call to
 * the gate; nothing of the vault's.
 */
export async function provenSession(request: Request, runtime: Pick<CoffreRuntime, 'db' | 'auth' | 'publicUrl' | 'gates'>, token: string): Promise<ProvenSession> {
  const parsed = sessionProof(request, runtime, token);
  const row = await routedSession(runtime.db, hashToken(token));
  if (row === null) throw unknown();
  return (await gated(request, runtime, token, parsed, row)).proven;
}

/**
 * The checks before any I/O, for a request `token` came with as a
 * workload's session: a deployment that takes sessions, with a gate, and a
 * proof of the right shape. Throws `SessionRefused`.
 */
export function sessionProof(request: Request, runtime: Pick<CoffreRuntime, 'auth' | 'gates'>, token: string): ParsedProof {
  const workloads = runtime.auth.mode === 'signin' ? runtime.auth.signin.workloads : null;
  if (workloads === null || tokenKind(token) !== 'workload') throw unknown();
  // A deployment that runs no gate takes no session: nothing would stop a replay.
  if (runtime.gates === null) throw refused(new ApiError('unavailable', 'this deployment runs no workload gate, so it takes no workload session', 'no_gate'));
  const header = request.headers.get('dpop');
  if (header === null) throw proofRefused('dpop', "a DPoP proof, signed by the session's key, comes with every request");
  const parsed = parseProof(header);
  if (!parsed.ok) throw proofRefused(parsed.reason, parsed.message);
  return parsed;
}

/**
 * The proof `sessionProof` parsed, held to the request and to the session
 * the app routed it by (`row`, read unchecked), then taken by that
 * service's gate, with `counts` in the same call. `content`: the request's
 * headers and its body's line, which a proxied request's proof signs
 * (`hdr`, `req`). Throws `SessionRefused`; a count refused is 429 `limit`,
 * and its window's first refusal the deployment's alert (`limitAlert`),
 * from `sourceIp`, kept alive past the response by `track`.
 */
export async function gated(
  request: Request,
  runtime: Pick<CoffreRuntime, 'publicUrl' | 'gates' | 'auth'>,
  token: string,
  parsed: ParsedProof,
  row: RoutedSession,
  more: { content?: { headers: Headers; body: string }; counts?: readonly GateCount[]; sourceIp?: string | null; track?: (work: Promise<unknown>) => void } = {},
): Promise<{ proven: ProvenSession; hdr: readonly string[] | null }> {
  const verified = await verifyProof(parsed, { method: request.method, url: signedUrl(request, runtime.publicUrl), jkt: row.jkt, token, ...(more.content === undefined ? {} : { content: more.content }) });
  if (!verified.ok) throw proofRefused(verified.reason, verified.message);

  try {
    const gate = runtime.gates!(row.principal);
    if (verified.nonce === null) throw useNonce(await gate.nonce());
    const admitted = await gate.admit({ replay: { session: row.id, jti: verified.jti, nonce: verified.nonce }, ...(more.counts === undefined || more.counts.length === 0 ? {} : { counts: more.counts }) });
    if (admitted.ok) return { proven: { proof: verified.jkt, nonce: admitted.nonce }, hdr: verified.hdr };
    switch (admitted.reason) {
      case 'use_dpop_nonce':
        throw useNonce(admitted.nonce);
      case 'replayed':
        throw proofRefused('replayed', 'this proof was used already: each is taken once');
      case 'overloaded':
        throw await countRefused(runtime, { ok: false, reason: 'overloaded' }, { principal: row.principal, session: row.id, sourceIp: more.sourceIp ?? null }, more);
      case 'limit':
        throw await countRefused(runtime, admitted, { principal: row.principal, session: row.id, sourceIp: more.sourceIp ?? null }, more);
    }
  } catch (error) {
    if (error instanceof SessionRefused) throw error;
    console.error('the workload gate failed', logged(error));
    throw refused(new ApiError('unavailable', 'coffre cannot check this proof right now'));
  }
}

/** A count the gate refused, as the workload's answer: 429, and its window's first refusal the deployment's alert. */
async function countRefused(
  runtime: Pick<CoffreRuntime, 'auth'>,
  admitted: { ok: false; reason: 'overloaded' } | Extract<GateAdmission, { reason: 'limit' }>,
  caller: { principal: string; session: string | null; sourceIp: string | null },
  more: { counts?: readonly GateCount[]; track?: (work: Promise<unknown>) => void },
): Promise<SessionRefused> {
  if (admitted.reason === 'overloaded') return refused(new ApiError('too_many_requests', 'this workload sends more requests than its gate takes: try again shortly', 'overloaded'), { 'retry-after': '1' });
  if (more.counts === undefined || more.counts.length === 0) throw new Error(`the workload gate refused a count it was not asked for: ${admitted.key}`);
  if (admitted.first && runtime.auth.mode === 'signin' && runtime.auth.signin.workloads !== null) {
    await sendAlert(runtime.auth.signin.workloads, limitAlert(caller, admitted), more.track ?? (() => {}));
  }
  return refused(new ApiError('too_many_requests', `past this workload's limit for ${admitted.key}`, 'limit'), { 'retry-after': String(Math.ceil(admitted.retryAfterMs / 1000)) });
}

/**
 * A call over a Cloudflare service binding, as the service its `props`
 * name, counted by that service's gate: no proof, so nothing to replay,
 * and the gate is asked only for the counts the credential's `limit`
 * makes. A deployment that runs no gate takes the call only where the
 * credential has none. Throws `SessionRefused`, as `gated` does; a limit's
 * alert names the service, and no session.
 */
export async function boundGated(
  runtime: Pick<CoffreRuntime, 'gates' | 'auth'>,
  principal: string,
  more: { counts?: readonly GateCount[]; track?: (work: Promise<unknown>) => void },
): Promise<void> {
  if (more.counts === undefined || more.counts.length === 0) return;
  if (runtime.gates === null) throw refused(new ApiError('unavailable', "this deployment runs no workload gate, so it holds no workload to this credential's limit", 'no_gate'));
  try {
    const admitted = await runtime.gates(principal).admit({ counts: more.counts });
    if (admitted.ok) return;
    if (admitted.reason === 'overloaded') throw await countRefused(runtime, { ok: false, reason: 'overloaded' }, { principal, session: null, sourceIp: null }, more);
    if (admitted.reason === 'limit') throw await countRefused(runtime, admitted, { principal, session: null, sourceIp: null }, more);
    throw new Error(`the workload gate asked a call with no proof for one: ${admitted.reason}`);
  } catch (error) {
    if (error instanceof SessionRefused) throw error;
    console.error('the workload gate failed', logged(error));
    throw refused(new ApiError('unavailable', 'coffre cannot count this call right now'));
  }
}

/** An answer to a workload, with the nonce its next proof signs: a response of its own, since another's headers may be immutable. */
export function withNonce(response: Response, nonce: string): Response {
  const headers = new Headers(response.headers);
  headers.set('dpop-nonce', nonce);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
