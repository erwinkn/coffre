// A workload's key-bound session, checked on every request
// (docs/design/workload-access.md, section 5.3): the session token, sent
// as `Authorization: DPoP coffre_wl_…`, with a proof its key signed for
// this request. Never answered from a cache:
//
//   1. the proof's shape, with no I/O (`parseProof`);
//   2. one statement (`workloadSession`): the session's row, its member's
//      generation, its binding, its ancestors and the freezes;
//   3. the row, every clause: kind, MAC, not revoked or expired, not past
//      `not_after`, approved where its binding says `approve`, its member's
//      generation, its binding standing, its ancestors standing;
//   4. the proof against the request: key, signature, method, URL, token,
//      and, for a request coffre forwards, its content (`verifyProof`);
//   5. its client address within the binding's `sources`, and no freeze;
//   6. the gate: the nonce, the proof's `jti` once, and any counts.
//
// The API (`authenticateRequest`), renewal, logout and the credential
// proxy (`PluginContext.workload`) all come through here.
import type { CredentialScope, ScopeGrant } from '@coffre/core/access';
import {
  addressWithin,
  checkConstraints,
  CREDENTIAL_NAME,
  hashToken,
  parseProof,
  verifyProof,
  type BindingPolicy,
  type Constraints,
  type Gate,
  type GateCount,
  type WorkloadCaller,
  type WorkloadProfile,
} from '@coffre/core/identity';

import { checkAuthRow } from './auth-rows.ts';
import { ApiError } from './api/errors.ts';
import { readScope } from './api/services.ts';
import { update, type BindingRow } from './db/queries.ts';
import { workloadSession, type SessionRow } from './db/workloads.ts';
import { credentials } from '@coffre/db/schema';
import { errorResponse, jsonResponse } from './http.ts';
import { logged } from './logged.ts';
import type { CoffreRuntime } from './runtime.ts';

/** A narrowed session's ancestors are at most this many: `narrow` goes four deep (section 8.4). */
export const MAX_ANCESTORS = 4;

/** One write of a session's last use per five minutes, outside the statement, as for every credential. */
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;

/** `Authorization: DPoP <token>`: a workload's session; null for any other scheme. */
export function dpopToken(request: Request): string | null {
  const match = /^DPoP\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  return match === null ? null : match[1]!;
}

/** A session that stands, for one request: its row, its binding and policy, the caller the proxy sees, and the gate's nonce. */
export type StandingSession = {
  row: SessionRow;
  binding: BindingRow;
  policy: BindingPolicy;
  /** The newest policy change as the statement read it, before the vault is asked. */
  policySeq: bigint | null;
  caller: WorkloadCaller;
  /** The gate's current nonce, which every answer to the workload carries (`DPoP-Nonce`). */
  nonce: string;
  /** The database's clock as the statement read it, in milliseconds. */
  now: number;
  /** The environments the session was made for, by ID; and the one this request uses, named or the only one, null when it names none. */
  places: readonly string[];
  place: string | null;
};

/** What a request asks of a session beyond standing: the credential it uses, its content, its counts, and whether a `narrow` child may ask it. */
export type SessionAsk = {
  /** The environment it uses, by ID, and the credential there by name, for the `credential:` freeze; null for neither. */
  place: string | null;
  credential: string | null;
  /** The body line `req` signs, for a request coffre forwards (`bodyDigest`, a declared digest, or `UNSIGNED_BODY`); left out for one that signs no content. */
  body?: string;
  /** Counts the gate takes in the same call (section 8.1). */
  counts?: readonly GateCount[];
  /** Whether a `narrow` child may ask it: only `/use`, narrow and logout. */
  children?: boolean;
};

/** Why a session was refused, as the workload's SDK reads it: the status, a reason, and the headers RFC 9449 asks for. */
export class SessionRefused extends Error {
  readonly response: Response;
  /** A count the gate refused, and whether this was its window's first refusal, which alerts (section 8.1). */
  readonly limit: { key: string; retryAfterMs: number; first: boolean } | null;
  constructor(response: Response, limit: SessionRefused['limit'] = null) {
    super('workload session refused');
    this.name = 'SessionRefused';
    this.response = response;
    this.limit = limit;
  }
}

const unknown = () => refusal(new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'));

function refusal(error: ApiError, headers: HeadersInit = {}): SessionRefused {
  return new SessionRefused(errorResponse(error, headers));
}

/** A proof refused (RFC 9449, section 7.1): 401, `invalid_dpop_proof`, and why. */
export function proofRefused(reason: string, message: string): SessionRefused {
  return refusal(new ApiError('unauthenticated', message, reason), { 'www-authenticate': 'DPoP error="invalid_dpop_proof"' });
}

/** A proof without the gate's current nonce: 401, `use_dpop_nonce`, and the nonce to sign with, retried once (section 5.1). */
function useNonce(nonce: string): SessionRefused {
  return new SessionRefused(jsonResponse(
    { error: 'unauthenticated', reason: 'use_dpop_nonce', message: "sign the proof with coffre's current nonce, in DPoP-Nonce" },
    401,
    { 'www-authenticate': 'DPoP error="use_dpop_nonce"', 'dpop-nonce': nonce },
  ));
}

/**
 * The request's URL as `publicUrl` spells it, with its path and query as
 * received: what the proof's `htu` and `req` sign. Built from the origin,
 * so a path starting with `//` stays a path.
 */
export function signedUrl(request: Request, publicUrl: string): string {
  const url = new URL(request.url);
  return `${new URL(publicUrl).origin}${url.pathname}${url.search}`;
}

/** The workload gate of `principal`, or a refusal: a deployment that runs none accepts no session, since nothing would stop a replay. */
export function gateOf(runtime: Pick<CoffreRuntime, 'gates'>, principal: string): Gate {
  if (runtime.gates === undefined) throw refusal(new ApiError('unavailable', 'this deployment runs no workload gate, so it takes no workload session'));
  return runtime.gates(principal);
}

/** A row's limits, a `narrow` child's; null for a root. One the MAC passed but that does not parse limits it to nothing. */
function constraintsOf(stored: string | null): Constraints | null {
  if (stored === null) return null;
  try {
    return checkConstraints(JSON.parse(stored));
  } catch {
    return { places: [], credentials: [], methods: [], paths: [] };
  }
}

/** A row's ancestors' IDs, root first; null for one that is no list, which stands for nothing. */
function ancestorsOf(stored: string | null): string[] | null {
  if (stored === null) return [];
  try {
    const ids: unknown = JSON.parse(stored);
    return Array.isArray(ids) && ids.length <= MAX_ANCESTORS && ids.every((id) => typeof id === 'string') ? ids : null;
  } catch {
    return null;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The environments a session was made for, by ID, as its row lists them (under its MAC); none for one that lists none. */
export function placesOf(stored: string | null): string[] {
  if (stored === null) return [];
  try {
    const listed: unknown = JSON.parse(stored);
    return Array.isArray(listed) ? listed.flatMap((place) => (typeof place?.environmentId === 'string' ? [place.environmentId as string] : [])) : [];
  } catch {
    return [];
  }
}

/** Whether a workload's row is live on the database's clock: not revoked, not expired, not past its hard end. */
function live(row: SessionRow, now: number): boolean {
  return row.kind === 'workload' && row.revokedAt === null && row.expiresAt.getTime() > now && row.notAfter !== null && row.notAfter.getTime() > now;
}

/**
 * A workload's session for this request, every clause of section 5.3
 * checked, or throws `SessionRefused`. `token` is the one the request's
 * `Authorization: DPoP` carries. Its last use is written at most every five
 * minutes, after, and never costs the request.
 */
export async function standingSession(
  request: Request,
  runtime: Pick<CoffreRuntime, 'db' | 'chainKey' | 'publicUrl' | 'gates' | 'auth' | 'waitUntil'>,
  token: string,
  sourceIp: string | null,
  ask: SessionAsk,
): Promise<StandingSession> {
  const workloads = runtime.auth.mode === 'signin' ? runtime.auth.signin.workloads : null;
  if (workloads === null) throw unknown();
  if (dpopToken(request) !== token) throw refusal(new ApiError('unauthenticated', "a workload's session is sent with its key's proof, Authorization: DPoP, never as a bearer token", 'workload'));
  const header = request.headers.get('dpop');
  if (header === null) throw proofRefused('dpop', 'a DPoP proof, signed by the session\'s key, comes with every request');
  const parsed = parseProof(header);
  if (!parsed.ok) throw proofRefused(parsed.reason, parsed.message);
  if ((ask.place !== null && !UUID.test(ask.place)) || (ask.credential !== null && !CREDENTIAL_NAME.test(ask.credential))) {
    throw refusal(new ApiError('bad_request', 'an environment is named by its ID, and a credential by its name in the configuration'));
  }

  let rows: Awaited<ReturnType<typeof workloadSession>>;
  try {
    rows = await workloadSession(runtime.db, hashToken(token), { place: ask.place, credential: ask.credential });
  } catch (error) {
    console.error('checking a workload session failed', logged(error));
    throw refusal(new ApiError('unavailable', 'coffre cannot check who you are right now'));
  }
  const tokenHash = hashToken(token);
  const own = rows.find((candidate) => candidate.credential.tokenHash.equals(tokenHash));
  if (own === undefined) throw unknown();
  const { credential: row, binding, now } = own;
  // The row, its member and its binding: each a clause of the one statement, each refused as an unknown credential.
  if (!checkAuthRow(runtime.chainKey, 'credentials', row) || !live(row, now)) throw unknown();
  if (own.memberStatus !== 'active' || own.memberGeneration !== row.generation) throw unknown();
  if (
    binding === null || own.bindingTombstoned || binding.revokedAt !== null || binding.policy === null
    || binding.principal !== row.principal || binding.generation !== row.generation || !checkAuthRow(runtime.chainKey, 'service_bindings', binding)
  ) {
    throw unknown();
  }
  const policy = JSON.parse(binding.policy) as BindingPolicy;
  // The environment it uses: the one named, or the one the session was made for (`/use/<credential>`).
  const places = placesOf(row.places);
  const place = ask.place ?? (places.length === 1 ? places[0]! : null);
  if (ask.credential !== null && place === null) {
    throw refusal(new ApiError('bad_request', 'name the environment it uses, /use/<project>/<environment>/<credential>: this session reaches none, or several'));
  }
  if (policy.approve === true && row.approvedAt === null) {
    throw refusal(new ApiError('unauthenticated', 'this session waits for a manager of its service to approve it', 'pending'));
  }
  // Its ancestors, a `narrow` child's, each live, the service's own, its MAC good, and unfrozen.
  const ancestors = ancestorsOf(row.ancestors);
  if (ancestors === null) throw unknown();
  const lineage = ancestors.map((id) => rows.find((candidate) => candidate.credential.id === id));
  for (const ancestor of lineage) {
    if (ancestor === undefined || ancestor.credential.principal !== row.principal || !checkAuthRow(runtime.chainKey, 'credentials', ancestor.credential) || !live(ancestor.credential, now)) {
      throw unknown();
    }
  }
  if (ancestors.length > 0 && ask.children !== true) {
    throw refusal(new ApiError('forbidden', 'a narrowed session reaches only /use, narrow and logout', 'narrowed'));
  }
  if (workloads.noReads && policy.reads !== undefined) {
    throw refusal(new ApiError('forbidden', 'this instance lets no binding list reads (noReads): bind the workload again without them', 'no_reads'));
  }

  // The proof: the key the row is bound to, this request's method and URL, the token, and what is forwarded.
  const verified = await verifyProof(parsed, {
    method: request.method,
    url: signedUrl(request, runtime.publicUrl),
    jkt: row.jkt!,
    token,
    content: ask.body === undefined ? undefined : { headers: request.headers, body: ask.body },
  });
  if (!verified.ok) throw proofRefused(verified.reason, verified.message);

  if (policy.sources !== undefined && (sourceIp === null || !addressWithin(sourceIp, policy.sources))) {
    throw refusal(new ApiError('unauthenticated', sourceIp === null ? 'coffre cannot tell where this request comes from, and the binding names its sources' : `${sourceIp} is outside the binding's sources`, 'source'));
  }
  const frozen = own.frozen;
  if (frozen.instance || frozen.service || frozen.binding || frozen.session || frozen.credential || lineage.some((ancestor) => ancestor!.frozen.session)) {
    throw refusal(new ApiError('forbidden', 'frozen: a manager stopped this use; nothing passes until they lift it', 'frozen'));
  }

  // The gate: the nonce it gave, the `jti` once, and the counts, in one call.
  const gate = gateOf(runtime, row.principal);
  let nonce: string;
  try {
    if (verified.nonce === null) throw useNonce(await gate.nonce());
    const admitted = await gate.admit({ replay: { session: row.id, jti: verified.jti, nonce: verified.nonce }, ...(ask.counts === undefined ? {} : { counts: ask.counts }) });
    if (!admitted.ok) {
      switch (admitted.reason) {
        case 'use_dpop_nonce':
          throw useNonce(admitted.nonce);
        case 'replayed':
          throw proofRefused('replayed', 'this proof was used already: each is accepted once');
        case 'overloaded':
          throw refusal(new ApiError('too_many_requests', 'this workload sends more requests than its gate takes: try again shortly', 'overloaded'), { 'retry-after': '1' });
        case 'limit':
          throw new SessionRefused(
            errorResponse(new ApiError('too_many_requests', `past this workload's limit for ${admitted.key}`, 'limit'), { 'retry-after': String(Math.ceil(admitted.retryAfterMs / 1000)) }),
            { key: admitted.key, retryAfterMs: admitted.retryAfterMs, first: admitted.first },
          );
      }
    }
    nonce = admitted.nonce;
  } catch (error) {
    if (error instanceof SessionRefused) throw error;
    console.error('the workload gate failed', logged(error));
    throw refusal(new ApiError('unavailable', 'coffre cannot check this proof right now'));
  }

  if (now - (row.lastUsedAt?.getTime() ?? 0) > TOUCH_INTERVAL_MS) {
    runtime.waitUntil(update(runtime.db, credentials, { id: row.id }, { lastUsedAt: new Date(now), lastUsedIp: sourceIp }).catch(() => 0));
  }
  return {
    row,
    binding,
    policy,
    policySeq: own.policySeq,
    now,
    nonce,
    places,
    place,
    caller: {
      kind: 'workload',
      principal: row.principal,
      credentialId: row.id,
      bindingId: binding.id,
      profile: binding.profile as WorkloadProfile,
      constraints: constraintsOf(row.constraints),
      hdr: verified.hdr,
      sourceIp,
    },
  };
}

/**
 * What a session reaches, as its caller holds it: its row's scope, an
 * enrollment code's, or else its binding's, never null. Each grant of an
 * environment its binding's `reads` lists carries that list (section 6.1):
 * binding creation gives each such environment a grant of its own, so the
 * list attaches by ID with nothing to look up. A grant without `reads` is
 * use-only, there.
 */
export function sessionScope(row: Pick<SessionRow, 'scope'>, binding: Pick<BindingRow, 'scope'>, policy: BindingPolicy): CredentialScope {
  const scope = readScope(row.scope ?? binding.scope) ?? [];
  const reads = policy.reads ?? {};
  return scope.map((grant): ScopeGrant => {
    const listed = grant.environmentId === null ? undefined : reads[grant.environmentId]?.keys;
    return listed === undefined ? grant : { ...grant, reads: listed };
  });
}
