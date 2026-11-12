import { randomUUID } from 'node:crypto';

import type { Filter, InstanceRole } from '@coffre/core/access';
import { hashToken, tokenKind, type TokenKind } from '@coffre/core/identity';
import type { AdmitReadOutcome } from '@coffre/core/vault';

import { authenticateRequest, endedCredential, refusedByKind, unauthenticated, type AuthenticatedIdentity } from './auth.ts';
import { vaultAdmits } from './api/changes.ts';
import { formatMember, parseMember, type MemberRef } from './api/paths.ts';
import { PARAMS, routeParts } from './api/router.ts';
import { memberBody } from './api/routes.ts';
import type { Touch } from './api/signin.ts';
import { findCredential } from './db/queries.ts';
import { check, parseJsonBody } from './http.ts';
import { namedAhead } from './db/read-ahead.ts';
import { acceptance } from './named-use.ts';
import { RefusalRecord } from './refused.ts';
import type { CoffreRuntime } from './runtime.ts';

/**
 * A member's first add in three round trips (T179 PR 5; docs/design/two-trips.md, "A member add"; formal/Writing.tla,
 * the add), the app's front door. Served before `authenticate` and the router, as a key write is (`writeAhead`): the
 * vault's read reads everything its decision weighs, the caller's rows among them, decides and prepares the add; the
 * app checks the caller's rows' `auth_mac` on what it answered (`authenticateRequest`, reading nothing: AuthChecked),
 * and the route then hands the prepared add back to the vault, whose write holds the read again before it commits
 * (`admitHeld` in api/members.ts). No app statement on the way: the credential's last use, which `verify` would write,
 * is left to its next use, or written on its own should the add go down today's path.
 *
 *   PUT /members/user:ada@acme.example { role: "developer" }, an admin's session   vault 1 + 2   app 0   3 round trips
 *   the same with first grants (`access`), or by someone who runs no instance        today's path (PR 5b)
 *
 * Null wherever this path does not serve the request: another route or shape, a token of another kind or refused for
 * its kind alone, a vault that does not serve it, or the vault's own `served: false`, a refusal among them. The request
 * then goes as ever, and is answered as ever.
 */

/** The kinds of token whose adds this path serves: a person's session and CLI login (a personal token is refused the route, logged, by the router). */
const ADMIT_KINDS: readonly TokenKind[] = ['browser', 'cli'];

/** An add as the front door read it: the member, and the instance role and its scope, projects by slug, as the body names them. */
export type AdmitAsked = { member: MemberRef; principal: string; role?: InstanceRole; scope?: { projects: Filter; environments: Filter } };

/**
 * The request's add, if it is one this path serves: `PUT /members/:member` with no query, its body as the route parses
 * it (`memberBody`), with no first grants, and a scope only with a role that takes one (not `member`, whose scope the
 * route still resolves, and 404s on a project it does not find). Anything else is null, the route's to answer.
 */
export function admitAsked(request: Request, body: Uint8Array): AdmitAsked | null {
  if (request.method !== 'PUT') return null;
  const url = new URL(request.url);
  if (url.search !== '') return null;
  let parts: string[];
  try {
    parts = routeParts(url.pathname);
  } catch {
    return null;
  }
  const [route, raw] = parts;
  if (parts.length !== 2 || route !== 'members' || raw === undefined || !PARAMS.member!.safeParse(raw).success) return null;
  let member: MemberRef;
  try {
    member = parseMember(raw);
  } catch {
    return null;
  }
  let json: unknown;
  try {
    // Decoded and counted as the route reads it (`readJson`).
    json = parseJsonBody(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return null;
  }
  const parsed = check(memberBody, json);
  if (!parsed.success || parsed.data.access !== undefined) return null;
  const { role, scope } = parsed.data;
  if (scope !== undefined && (role === undefined || role === 'member')) return null;
  if (member.type === 'service' && role !== undefined && role !== 'member') return null;
  return {
    member, principal: formatMember(member),
    ...(role === undefined ? {} : { role }),
    ...(scope === undefined ? {} : { scope: { projects: (scope.projects ?? 'all') as Filter, environments: (scope.environments ?? 'all') as Filter } }),
  };
}

/** One try of an add: the vault's answer, the add it prepared among it. */
export type AdmitTry = Extract<AdmitReadOutcome, { served: true }>;

/** A try the vault's decision refused on its read (PR 6): the route answers it, and the vault records it (`RefusalRecord`). */
export type RefusedAdmit = { refused: RefusalRecord };

/** A try as the vault answered it: decided and prepared, or refused. */
export type AdmitTried = AdmitTry | RefusedAdmit;

/** What a try's answer says of its caller, served or refused: the rows, the standing, the vault's clock. */
function answerOf(tried: AdmitTried): { app: string; standing: AdmitTry['standing']; at: number } {
  return 'refused' in tried ? tried.refused.refused : tried;
}

/**
 * An add the vault decided, for the route to commit (`ApiContext.admission`): its tries, each a read of the vault's,
 * three in all (`admitHeld`); the credential's last use, which no statement of this path writes (`Touch`), written
 * should the add go down today's path.
 */
export class Admission {
  readonly asked: AdmitAsked;
  readonly touched: Touch | null;
  #try: AdmitTried | null;
  readonly #ask: () => Promise<AdmitTried | string>;
  readonly #still: (tried: AdmitTried) => Promise<boolean>;

  constructor(asked: AdmitAsked, first: AdmitTried, touched: Touch | null, ask: () => Promise<AdmitTried | string>, still: (tried: AdmitTried) => Promise<boolean>) {
    this.asked = asked;
    this.#try = first;
    this.touched = touched;
    this.#ask = ask;
    this.#still = still;
  }

  /** The try at hand, or null once let go. */
  get current(): AdmitTried | null {
    return this.#try;
  }

  /** The try at hand's refusal, which the vault records in place of the entry its answer would append (`refuse`); else null. */
  get refusal(): RefusalRecord | null {
    return this.#try !== null && 'refused' in this.#try ? this.#try.refused : null;
  }

  /**
   * The add read again, once the vault's write found its read moved; or why the vault no longer serves it, the request
   * then going down today's path, but for its credential, no longer the caller's (`credential`: ended, or its rows not
   * the same caller's, checked as the first's were), which answers 401, as a key write's retry does (`Written.again`).
   */
  async again(): Promise<AdmitTried | string> {
    this.#try = null;
    const next = await this.#ask();
    if (next === 'forged' || next === 'ended') return 'credential';
    if (typeof next === 'string') return next;
    if (!(await this.#still(next))) return 'credential';
    this.#try = next;
    return next;
  }
}

/**
 * The add's first try, and its caller checked on the rows it answered: null where this path does not serve it (the
 * request goes as ever), or the credential's own answer where the rows do not bear out the caller (401, as ever).
 */
export async function admitAhead(
  runtime: CoffreRuntime,
  request: Request,
  sourceIp: string | null,
  token: string,
  asked: AdmitAsked,
): Promise<{ identity: AuthenticatedIdentity | Response; admission: Admission | null } | null> {
  const kind = tokenKind(token);
  if (kind === null || !ADMIT_KINDS.includes(kind) || runtime.vault.admitRead === undefined || !(await vaultAdmits(runtime.vault))) return null;
  if (refusedByKind(runtime, token) !== null) return null;
  const requestId = randomUUID();
  const tokenHash = hashToken(token);
  const ask = async (): Promise<AdmitTried | string> => {
    const answer = await runtime.vault.admitRead!({
      tokenHash: tokenHash.toString('base64'), accepts: acceptance(runtime), principal: asked.principal,
      ...(asked.role === undefined ? {} : { role: asked.role }), ...(asked.scope === undefined ? {} : { scope: asked.scope }),
      operationId: randomUUID(), requestId,
    });
    if (answer.served) return answer;
    return 'ticket' in answer ? { refused: new RefusalRecord(runtime.vault, answer, 'member.add') } : answer.why;
  };
  const first = await ask();
  // The caller's credential not as its log has it, or ended: 401, never down today's path (as a key write's, `writeAhead`).
  if (first === 'forged') return { identity: unauthenticated(runtime.auth), admission: null };
  if (first === 'ended') return { identity: endedCredential(), admission: null };
  if (typeof first === 'string') return null;
  const rows = (tried: AdmitTried) => namedAhead(answerOf(tried).app);
  const ahead = rows(first);
  let touched: Touch | null = null;
  // The credential checked on the rows the vault answered, its MAC and token's hash among them (AuthChecked: before
  // anything is written), its expiry at the vault's `at`, its standing as the vault decided it, and the passkey rows the
  // read answered with it (T216, as a key write's: `writeAhead`).
  const identity = await authenticateRequest(request, runtime, requestId, token, sourceIp, {
    standing: answerOf(first).standing, at: answerOf(first).at, ...(ahead?.credential === undefined ? {} : { ahead: ahead.credential }),
    touch: (touch) => {
      touched = touch;
    },
  });
  if (identity instanceof Response || !identity.registered) return { identity, admission: null };
  const credentialId = identity.credentialId;
  const still = async (tried: AdmitTried): Promise<boolean> => {
    const credential = rows(tried)?.credential;
    if (credential == null) return false;
    try {
      const row = await findCredential(runtime.db, runtime.chainKey, { tokenHash }, credential, false);
      return row !== null && row.id === credentialId;
    } catch {
      return false;
    }
  };
  return { identity, admission: new Admission(asked, first, touched, ask, still) };
}
