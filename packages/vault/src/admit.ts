import { createHmac, timingSafeEqual } from 'node:crypto';

import { EVERYWHERE, isInstanceRole, isScope, normalScope, ownsInstance, runsInstance, type Filter, type InstanceRole, type Scope } from '@coffre/core/access';
import { PRINCIPAL } from '@coffre/core/vault';
import type { Access, AdmitReadInput, CredentialAcceptance } from '@coffre/core/vault';

import { readerOf, type Reader } from './decide.ts';
import { noEdits, type CredentialInput, type PrincipalInput, type SealKeys } from './inputs.ts';
import type { ChangeRow, LogMacKey } from './log-entry.ts';
import { bytes, callerFirst, callerInputs, changeOf, holds, oldOf, stands, writeStanding, type CallerInputs, type RawCaller, type ReadObject, type Unserved } from './write.ts';

/**
 * A member add in three round trips (T179 PR 5; docs/design/two-trips.md, "A member add", "As built: PR 5";
 * formal/Writing.tla, the add): the vault's side. Its read (`admit_read`, migration 0062) reads everything the decision
 * weighs, in one snapshot, with no lock; the Worker decides on that read and nothing else (DecideOnRead) and prepares
 * the add; the app checks the caller's rows' `auth_mac` on what the read answered and hands the prepared add back,
 * under the vault's MAC (`AdmitTicket`); the vault's write locks the members' rows and 0.14's head, then holds the same
 * read again under the fence (`admit_hold`, ReadHeld) before it writes. The read is one text, whose SHA-256 (the
 * digest) the add's change carries.
 *
 * Served only for what this path holds whole: the first add of a principal no row names, by a caller who runs the
 * instance (an admin or an Owner of all of it, with no credential scope), as a person with an instance role and its
 * scope, or a service account with neither. Anything else, a refusal included, is `unserved`, and the request goes down
 * today's path (`admit`), which answers it, logged, as ever: a re-admit, a role change, first grants, a set-up by
 * someone who does not run the instance (PR 5b: the read holds the places and the services setting).
 *
 *   Bob's PUT /members/user:ada { role: "developer" }   admit_read    the read                              one round trip
 *                                                        the Worker    decides, prepares                     none
 *                                                        admit_write   rows + head | hold, writes, COMMIT    two
 */

export { callAdmit, holdAdmit, type AdmitCall, type AdmitRead } from './admit.postgres.ts';

/** The kinds of credential whose adds this path serves: a person's sessions. A personal token is refused this route by the app's router, logged; a service's token runs no instance. */
export const ADMIT_KINDS: readonly string[] = ['browser', 'cli'];

/** The member asked for, as the read has it: its row (a first add: none), its grants, 0.14's newest access entry about it, its object's newest change. */
export type AdmitSubject = { principal: string; row: Record<string, unknown> | null; grants: number; access: bigint | null; seal: Buffer | null; newest: ChangeRow | null };

/** The read (`admit_inputs`), parsed: the only data the decision takes, made here and nowhere else. */
export type AdmitInputs = CallerInputs & {
  subject: AdmitSubject;
  /** Each project the scope names, by its slug, in the order asked: its id, or none for no such project. */
  projects: { slug: string; id: string | null }[];
};

type RawAdmit = RawCaller & {
  subject: { row: Record<string, unknown> | null; grants: unknown[]; access: number | string | null; newest: Parameters<typeof changeOf>[0] };
  projects: { slug: string; row: Record<string, unknown> | null }[];
};

/** The read's text as the decision takes it. */
export function parseAdmitInputs(text: string, principal: string): AdmitInputs {
  const raw = JSON.parse(text) as RawAdmit;
  const s = raw.subject;
  return {
    ...callerInputs(raw),
    subject: {
      principal, row: s.row, grants: s.grants.length, access: s.access == null ? null : BigInt(s.access),
      seal: s.row === null ? null : bytes(s.row.seal as string | null), newest: changeOf(s.newest),
    },
    projects: raw.projects.map(({ slug, row }) => ({ slug, id: row === null ? null : String(row.id) })),
  };
}

/** An add as the app asks it: the member, its instance role and the role's scope, projects by slug (`PUT /members/:member`'s body). */
export type AdmitAsked = { principal: string; role?: InstanceRole; scope?: { projects: Filter; environments: Filter } };

/** The projects a scope names, by slug, each once: what the read resolves. */
export function scopeSlugs(asked: AdmitAsked): string[] {
  const projects = asked.scope?.projects;
  if (projects === undefined || projects === 'all') return [];
  return [...new Set('only' in projects ? projects.only : projects.except)];
}

/** What the add is decided as: who asks, and the member's instance role and scope (projects by id), as `admit` would make them. */
export type AdmitDecided = {
  credential: CredentialInput;
  principal: PrincipalInput;
  reader: Reader;
  role: InstanceRole;
  scope: Scope;
};

/**
 * The decision, on the read alone (DecideOnRead), in the order the write's takes (`decideWrite`): the caller's
 * credential first (`callerFirst`); then, a member that has a row already (a re-admit, a role change) or a scope this
 * path does not resolve, today's (`shape`); then every newest change held to its MAC (T190) and each row to its newest
 * change's seal (StaleFirst), the member asked for among them, whose object has no change while it has no row; then
 * `admit`'s rules for a first add by someone who runs the instance. Anything `admit` would refuse is `refused` or
 * `shape`: today's path refuses it, logged.
 */
export function decideAdmit(
  keys: { seals: SealKeys; macs: readonly LogMacKey[] },
  read: AdmitInputs,
  request: { at: number; accepts: CredentialAcceptance; kinds: readonly string[]; asked: AdmitAsked; listed: boolean },
): AdmitDecided | Unserved {
  const caller = callerFirst(keys, read, request);
  if (typeof caller === 'string') return caller;
  const { asked } = request;
  const { principal, roles, policy, subject } = read;
  // A member already, or one the deployment's config names (its Owners'): today's path, which decides on its row.
  if (subject.row !== null || request.listed) return 'shape';
  if (!PRINCIPAL.test(asked.principal) || asked.principal !== subject.principal) return 'shape';
  const objects: ReadObject[] = [
    caller.own,
    { held: principal, ref: { kind: 'principal', id: caller.row.principal } },
    { held: read.roles, ref: { kind: 'roles', id: 'instance' } },
    { held: read.policy, ref: { kind: 'policy', id: 'instance' } },
    // The member asked for, no row: its object none, which its newest change must leave (none, or an end).
    { held: { row: null, seal: null, newest: subject.newest } as ReadObject['held'], ref: { kind: 'principal', id: subject.principal } },
  ];
  if (!objects.every((object) => holds(keys, object))) return 'tampered';
  if (!objects.every((object) => stands(keys, object))) return 'stale';
  // 0.14's newest access entry about the caller, which its newest change must account for (UsesSeeOldWrites); and none
  // about a principal with no row, nor a grant: 0.14's rows of a member its log never made.
  const old = oldOf(principal.newest);
  if (principal.access !== null && (old === null || principal.access > old)) return 'stale';
  if (subject.access !== null || subject.grants > 0) return 'stale';
  if (principal.row === null || policy.row === null) return 'credential';
  const reader = readerOf(principal.row, caller.row, roles.row ?? noEdits(), [], request.at);
  if (reader.status !== 'active') return 'refused';
  // Who runs the instance adds anyone (`admit`); anyone else only sets a service account up, with what the setting
  // lets them give (`#setsUp`), which this read does not hold.
  if (!runsInstance(reader.live)) return 'refused';
  // `admit`'s and the route's checks of what is asked, each today's path's to refuse.
  if (asked.role !== undefined && !isInstanceRole(asked.role)) return 'shape';
  if (asked.scope !== undefined && asked.role === undefined) return 'shape';
  if (asked.role !== undefined && asked.role !== 'member' && !asked.principal.startsWith('user:')) return 'shape';
  let scope: Scope = EVERYWHERE;
  if (asked.role !== undefined && asked.role !== 'member') {
    const ids = new Map(read.projects.map(({ slug, id }) => [slug, id]));
    const projects = asked.scope?.projects ?? 'all';
    const named = (slugs: readonly string[]): string[] | null => {
      const found = slugs.map((slug) => ids.get(slug) ?? null);
      return found.every((id) => id !== null) ? (found as string[]) : null;
    };
    let filter: Filter = 'all';
    if (projects !== 'all') {
      const list = named('only' in projects ? projects.only : projects.except);
      // A project no slug names: today's path answers 404.
      if (list === null) return 'shape';
      filter = 'only' in projects ? { only: list } : { except: list };
    }
    scope = normalScope({ projects: filter, environments: asked.scope?.environments ?? 'all' });
    if (!isScope(scope)) return 'shape';
  }
  const role = asked.role ?? 'member';
  if (role === 'owner' && !ownsInstance(reader.live)) return 'refused';
  return { credential: caller.row, principal: principal.row, reader, role, scope };
}

/** An add as the app asks it, checked: what no caller of the vault's sends is a bug of the app's, which fails the call. */
export function validateAdmitRead(input: AdmitReadInput): void {
  if (typeof input?.tokenHash !== 'string' || Buffer.from(input.tokenHash, 'base64').length !== 32) throw new Error('an add names its token by its hash, 32 bytes, base64');
  if (typeof input.accepts?.signin !== 'boolean' || !Array.isArray(input.accepts.issuers) || input.accepts.issuers.some((issuer) => typeof issuer !== 'string')) {
    throw new Error("an add says what credentials the app accepts: whether it signs in, and its providers' issuers");
  }
  if (typeof input.principal !== 'string' || input.principal.length === 0 || input.principal.length > 400) throw new Error('an add names the member it adds');
  if (input.role !== undefined && typeof input.role !== 'string') throw new Error("an add's role is an instance role's name");
  if (input.scope !== undefined && !isScope(input.scope)) throw new Error("an add's scope is a role's: { projects, environments }, each all, only or except");
}

/** What the add decided the caller holds, as `access` answers it: the app's caller for the rest of the request. */
export function admitStanding(decided: AdmitDecided, at: number): Access {
  return writeStanding(decided, at);
}

/**
 * The add as the vault prepared it, which the app carries from the read to the write and can neither change nor make
 * (two-trips.md, "A member add", step 2): what the write writes, the read it holds, and who it is by, by ids
 * (ActorFromRead: the write resolves no token).
 */
export type AdmitTicket = {
  v: 1;
  /** Until when the write takes it (the vault's clock): a read is held for one request's tries, not kept. */
  until: number;
  at: number;
  digest: string;
  tokenHash: string;
  principal: string;
  scopeSlugs: string[];
  actor: string;
  credential: string;
  identity: string | null;
  personal: boolean;
  role: InstanceRole;
  scope: Scope;
  requestId: string | null;
  operationId: string | null;
};

/** How long a prepared add is taken: the write follows its read by the app's check, in memory. */
export const TICKET_MS = 30_000;

const TICKET_DOMAIN = 'coffre.admit.v1\0';

/** A prepared add, sealed under the vault's change MAC key (`log015.mac`), domain-separated from every log MAC. */
export function sealTicket(key: LogMacKey, ticket: AdmitTicket): string {
  const text = JSON.stringify(ticket);
  const mac = createHmac('sha256', key.key).update(TICKET_DOMAIN).update(text, 'utf8').digest();
  return `${Buffer.from(text, 'utf8').toString('base64url')}.${Buffer.concat([key.tag, mac]).toString('base64url')}`;
}

/** The prepared add a ticket carries, if one of these keys sealed it: `expired` once its time is past at `now`; else null, no ticket of the vault's. */
export function openTicket(keys: readonly LogMacKey[], sealed: unknown, now: number): AdmitTicket | 'expired' | null {
  if (typeof sealed !== 'string') return null;
  const [body, tag, ...rest] = sealed.split('.');
  if (body === undefined || tag === undefined || rest.length > 0) return null;
  const text = Buffer.from(body, 'base64url').toString('utf8');
  const given = Buffer.from(tag, 'base64url');
  const holds = keys.some((key) => {
    if (given.length !== key.tag.length + 32 || !given.subarray(0, key.tag.length).equals(key.tag)) return false;
    const mac = createHmac('sha256', key.key).update(TICKET_DOMAIN).update(text, 'utf8').digest();
    return timingSafeEqual(mac, given.subarray(key.tag.length));
  });
  if (!holds) return null;
  const ticket = JSON.parse(text) as AdmitTicket;
  if (ticket.v !== 1 || typeof ticket.until !== 'number') return null;
  return now > ticket.until ? 'expired' : ticket;
}

