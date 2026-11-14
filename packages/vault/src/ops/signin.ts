import { randomUUID } from 'node:crypto';

import {
  allows,
  assignableToEnvironment,
  definitionOf,
  delegable,
  DEVICE_TTL_SECONDS,
  heldColumns,
  holds as holdsAt,
  isScope,
  issuedGrant,
  issuesCredential,
  managesService,
  MAX_PERSONAL_TOKEN_MINUTES,
  MAX_SCOPE_PLACES,
  ownsProject,
  PERMISSIONS,
  protectedWithin,
  ROLE_ID,
  ROLES,
  runsInstance,
  scopeDefinition,
  USER_CODE,
  type Holdings,
  type Permission,
  type Place,
  type Policy,
  type RoleDefinition,
  type Scope,
  type ScopeGrant,
  type ServiceAccount,
} from '@coffre/core/access';
import type { Account, AccountLink, AccountUnlink, Answers, Asked, CredentialEnd, DeviceDecide, Presented, SigninChanges, TokenCreate } from '@coffre/core/vault';
import { credentials, deviceLogins, environments, grants, identities, policy, principals, projects, roles } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { callerFrom, callerParts, refusedTo, type Asking } from '../caller.ts';
import { amended, part, put, WRITE_MS, type Operation, type Parts, type Refusal, type Seen, type Unsealed, type Write } from '../change.ts';
import type { Fresh, Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { HASH, presented, text, traced } from './input.ts';
import { definitionsOf, manages, onSession, projectsOf, runs, serviceOf, serviceParts, settingOf } from './services.ts';

/** A provider's id, as the table's own check has it (`identities_provider_check`). */
const PROVIDER = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** An email as a member's id holds one (`principals_id_check`, `principals_user_lowercase`). */
const EMAIL = /^[^\s:@][^\s@]*@[^\s@]+$/;
const MOST_EMAILS = 20;
/** The longest a browser's session lasts, whatever the app asks: the most a deployment's `browserSessionHours` says. */
const BROWSER_MINUTES = 7 * 24 * 60;
/** Who made what the vault makes of itself: an Owner its configuration names. */
const VAULT = 'system:vault';

const email = (value: unknown): value is string => text(value) && EMAIL.test(value) && value === value.toLowerCase();

/** An account's emails, if it is one as the contract has it: its provider, issuer and subject, and 20 verified emails at most, lowercase, each once. */
function verified(account: Account | undefined): string[] | undefined {
  const emails = Array.isArray(account?.emails) ? [...account.emails] : undefined;
  if (emails === undefined || emails.length > MOST_EMAILS || !emails.every(email) || new Set(emails).size !== emails.length
    || !text(account!.provider) || !PROVIDER.test(account!.provider) || !text(account!.issuer) || account!.issuer === '' || !text(account!.subject) || account!.subject === '') return undefined;
  return emails;
}

/**
 * A person signs in to a browser (docs/design/0.16.md, "Signing in"), with
 * an account the app verified: nobody asks it, and the vault takes the
 * account on the app's word, which the entry says. One statement writes
 * the session, the identity bound or signed in again, an Owner the
 * configuration names and the rows do not, and the end of the session the
 * browser showed.
 */
function signin(input: Asked<'signin'>, vault: Deciding): Operation<Parts, Answers['signin']> {
  const from = traced(input);
  const { account, session, replaces } = input;
  const emails = verified(account);
  if (emails === undefined
    || !text(session?.token) || !HASH.test(session.token) || !Number.isInteger(session.minutes) || session.minutes < 1 || session.minutes > BROWSER_MINUTES || !(session.label === null || text(session.label))
    || !(replaces === null || (text(replaces) && HASH.test(replaces) && replaces !== session.token))) {
    throw new TypeError("a sign-in names an account by its provider, issuer and subject, with 20 verified emails at most, lowercase; a session by its token's SHA-256, for a week at most; and the session it replaces, if any, by its token's");
  }
  const { provider, issuer, subject } = account;
  const named = emails.map((address) => `user:${address}`);
  // Drawn here: a decision draws nothing.
  const ids = { identity: randomUUID(), credential: randomUUID() };
  // Where it is bound: one row at most, found by the unique index that holds an account to one member (`identities_active_subject`).
  const bound = sql`i.provider = ${provider} AND i.issuer_hash = ${issuer} AND i.active_subject = ${subject}`;
  const read = {
    account: part(identities, sql`${identities.id} IN (SELECT i.id FROM identities i WHERE ${bound})`),
    // Whoever it is bound to, and whoever its emails name: each by its key.
    holder: part(principals, sql`${principals.id} IN (SELECT i.principal FROM identities i WHERE ${bound})`),
    named: part(principals, sql`${principals.id} = ANY(${sql.param(named)}::text[])`),
    // The accounts of those the emails name, revoked ones too: one revoked behind the vault is still found, and is not the vault's.
    theirs: part(identities, sql`${identities.principal} = ANY(${sql.param(named)}::text[])`),
    replaced: part(credentials, replaces === null ? sql`false` : sql`${credentials.tokenHash} = decode(${replaces}, 'hex')`),
    // The instance's one row, which the vault's adoption of the database writes: nobody signs in to one it has not adopted.
    instance: part(policy, sql`${policy.onlyRow}`),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      // Every other change is asked by a caller, whose rows the adoption sealed. This one is asked by nobody, and makes an
      // Owner from nothing: on a database not adopted yet it would begin the log, and the adoption would never run.
      // Before its adoption a database has no such row; one that is there and not the vault's was written behind it.
      if (seen.instance.length === 0) return { refused: unsealed.instance > 0 ? 'tampered' : 'adopting' };
      // A row written behind the vault is not a row that is absent: an account that is not the vault's is not a new
      // one, nor its member nobody.
      if (unsealed.account + unsealed.holder > 0) return { refused: 'tampered' };
      const now = new Date(at);
      const writes: Write[] = [];
      const detail: Record<string, unknown> = { kind: 'browser', verified: 'app', provider, issuer, subject, emails };
      const members = [...seen.holder, ...seen.named];
      /**
       * A member as this change leaves them: their row; or, for one the
       * configuration names an Owner, an active Owner of the whole
       * instance, made or made one again here. Undefined for no member.
       */
      const memberOf = (id: string): Fresh<typeof principals> | undefined => {
        const row = members.find((other) => other.id === id);
        if (!vault.owners.includes(id.slice('user:'.length))) return row;
        if (row !== undefined && row.status === 'active' && row.role === 'owner' && row.scope === null) return row;
        // Let back in, their status says when and by whom; given the role alone, it says what it said.
        const owner = { status: 'active', role: 'owner', scope: null, ...(row?.status === 'active' ? {} : { statusChangedAt: now, statusChangedBy: VAULT }) };
        const made: Fresh<typeof principals> = row === undefined ? { id, generation: 0, createdAt: now, createdBy: VAULT, frozenAt: null, statusChangedAt: now, statusChangedBy: VAULT, ...owner } : { ...row, ...owner };
        writes.push(row === undefined ? put(principals, made) : amended(principals, row, owner));
        detail.owner = row === undefined ? 'made' : 'restored';
        return made;
      };

      const [identity] = seen.account;
      let who: Fresh<typeof principals> | undefined;
      let identityId: string;
      if (identity !== undefined) {
        who = memberOf(identity.principal);
        // An account bound before its member was last removed is dead with everything else they held.
        if (who === undefined || who.status !== 'active' || who.generation !== identity.generation) return { refused: 'deactivated' };
        writes.push(amended(identities, identity, { lastSignInAt: now, email: emails[0] ?? identity.email }));
        identityId = identity.id;
      } else {
        // Nor is a member passed over for the next email, or without an account, for a row of theirs that is not the vault's.
        if (unsealed.named + unsealed.theirs > 0) return { refused: 'tampered' };
        const id = named.find((other) => members.some((row) => row.id === other) || vault.owners.includes(other.slice('user:'.length)));
        if (id === undefined) return { refused: 'not_registered' };
        who = memberOf(id)!;
        if (who.status !== 'active') return { refused: 'deactivated' };
        // One who signs in with another account already links this one from a session of theirs. An account of a generation before their last removal is dead, and no account of theirs.
        if (seen.theirs.some((other) => other.principal === who!.id && other.generation === who!.generation && other.revokedAt === null)) return { refused: 'account_mismatch' };
        writes.push(put(identities, { id: ids.identity, provider, subject, issuerHash: issuer, generation: who.generation, principal: who.id, email: emails[0] ?? null, createdAt: now, createdBy: who.id, lastSignInAt: now, revokedAt: null, revokedBy: null }));
        identityId = ids.identity;
        detail.bound = id.slice('user:'.length);
      }

      const expiresAt = new Date(at + session.minutes * 60_000);
      writes.push(put(credentials, {
        id: ids.credential, kind: 'browser', tokenHash: Buffer.from(session.token, 'hex'), tokenHint: null, previousTokenHash: null, generation: who.generation, principal: who.id, identityId,
        scope: null, places: null, label: session.label, createdAt: now, createdBy: who.id, expiresAt, lastUsedAt: null, lastUsedIp: null, frozenAt: null, revokedAt: null, revokedBy: null,
        jkt: null, notAfter: null, ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null, run: null, client: null, challenge: null,
      }));
      // The session the browser showed ends with this one's start: a browser holds one.
      const [old] = seen.replaced;
      const ended = old !== undefined && old.kind === 'browser' && old.revokedAt === null ? old : undefined;
      if (ended !== undefined) {
        writes.push(amended(credentials, ended, { revokedAt: now, revokedBy: who.id }));
        detail.replaced = ended.id;
      }
      return {
        writes,
        entry: {
          // A session's coming ages out with the uses; an account bound, or an Owner made, is kept.
          kept: detail.bound !== undefined || detail.owner !== undefined,
          action: 'sign_in', actor: who.id, credential: ids.credential, request: from.request, ip: from.ip,
          objects: [`principal:${who.id}`, `credential:${ids.credential}`, `identity:${identityId}`, ...(ended === undefined ? [] : [`credential:${ended.id}`])],
          detail: { ...detail, identity: identityId },
        },
        answer: { principal: who.id, credential: ids.credential, expiresAt: expiresAt.toISOString() },
      };
    },
  };
}

/** A credential's or an identity's id, as the vault draws one. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** A member, as the table's own check has it (`principals_id_check`). */
const MEMBER = /^(user|token):[^\s:]\S*$/;
/** No project: a change about none, where only the caller's instance role weighs. */
const NO_PROJECT = sql`(SELECT NULL::uuid WHERE false)`;
/** What a member's tokens are, as their list shows them: a service account's and a person's, and a workload's sessions, which its managers end as they end its tokens. */
const TOKENS = ['service', 'personal', 'handle', 'workload'];

type Shown = ReturnType<typeof presented>;

/**
 * Who asks, as the changes a caller asks take them: one whose credential
 * stands. A workload's session that stands and is stopped is told why; a
 * narrowed one uses values and changes nothing.
 */
function asking(seen: Seen<ReturnType<typeof callerParts>>, shown: Shown, vault: Deciding, at: number): Asking | Refusal {
  const caller = callerFrom(seen, shown, vault.workloads, at);
  if (caller === null) return { refused: 'unauthenticated' };
  if (caller.workload?.stop != null) return { refused: caller.workload.stop };
  if (caller.workload?.narrowed === true) return { refused: 'narrowed' };
  return caller;
}

/** The entry's fields a change a caller asks gives the same way. */
export const by = (caller: Asking, shown: Shown) => ({ actor: caller.principal, credential: caller.credential.id, request: shown.request, ip: shown.ip });

/**
 * End a credential (`CredentialEnd`): one row written, revoked. What it
 * ends is the credential the request came in on (`sign_out`), or one named
 * by its id (`token.revoke`), which the caller may end by the rules 0.14.7
 * kept (`revokeCredential`): their own, a member's token for whoever
 * manages that service account, anyone's for whoever runs the instance.
 *
 * Rows hidden from the read: the caller's, or the credential's, make it a
 * refusal. The instance's policy row, the service account's row, or a
 * place one of its grants is on, make the caller manage it less, or not
 * at all. A grant of the service account's, or an environment of its
 * projects that is protected, would make them manage it more easily: one
 * written behind the vault refuses, `tampered` (`manages`). One deleted
 * for the decision and put back after is not found, and the caller ends a
 * token they would not have: what a database writer gets that way is a
 * credential ended, which the credential's own row, edited or deleted,
 * ends as well.
 */
function credentialEnd(input: Presented & CredentialEnd, vault: Deciding): Operation<Parts, Answers['credential.end']> {
  const shown = presented(input);
  const { credential: id, of } = input;
  const member = typeof of === 'object' && of !== null ? (of as { member: unknown }).member : null;
  if (id === null ? of !== null : !text(id) || !UUID.test(id) || !(of === null || of === 'handle' || (typeof member === 'string' && text(member) && MEMBER.test(member)))) {
    throw new TypeError("a credential is ended by its id, with what it is named as (none, a handle of the caller's, or a member's token), or by none for the one the request came in on");
  }
  const read = {
    ...callerParts(shown.token, projectsOf(member as string | null)),
    target: part(credentials, id === null ? sql`false` : sql`${credentials.id} = ${id}::uuid`),
    ...serviceParts(member as string | null),
  };
  const action = id === null ? 'sign_out' : 'token.revoke';
  return {
    read,
    // Who stands and is refused is logged, with the credential they named if it is there.
    denied: refusedTo(action, shown, vault.workloads, { objects: (seen: Seen<typeof read>) => seen.target.map((row) => `credential:${row.id}`) }),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      let caller: Asking | Refusal;
      let row: Row<typeof credentials> | undefined;
      if (id === null) {
        // Signing out: any credential that stands ends itself, a workload's session that is stopped or narrowed too. Only a handle may not: it is the proxy's.
        caller = callerFrom(seen, shown, vault.workloads, at) ?? { refused: 'unauthenticated' };
        if ('refused' in caller) return caller;
        row = caller.credential;
      } else {
        caller = asking(seen, shown, vault, at);
        if ('refused' in caller) return caller;
        row = seen.target.find((other) => other.revokedAt === null && other.expiresAt.getTime() > at);
        const own = row?.principal === caller.principal;
        // One answer for a credential that is not there, is ended already, or is not the caller's to end.
        // Who reaches each route, as 0.14.7: a handle's, any credential of its person; the others, any but a personal token, and the sessions route no workload's session either.
        const reaches = of === 'handle' || (caller.credential.kind !== 'personal' && (of !== null || caller.credential.kind !== 'workload'));
        const theirs = row !== undefined && reaches && (of === 'handle'
          ? own && row.kind === 'handle'
          : of === null
            ? own || runs(caller)
            : row.principal === member && TOKENS.includes(row.kind) && (own || manages(caller, seen, unsealed, row.principal, at)));
        if (theirs === 'tampered') return { refused: 'tampered' };
        if (!theirs) return { refused: 'unknown_credential' };
      }
      const ended = row!;
      const own = ended.principal === caller.principal;
      return {
        writes: [amended(credentials, ended, { revokedAt: new Date(at), revokedBy: caller.principal })],
        entry: {
          ...by(caller, shown),
          // A session's or a run's coming and going ages out with the uses: signing out, or ending a session or a handle of one's own. A token ended, or someone else's credential, is kept.
          kept: action === 'token.revoke' && !(own && ['browser', 'cli', 'handle'].includes(ended.kind)),
          action,
          objects: [...new Set([`principal:${caller.principal}`, `credential:${caller.credential.id}`, `credential:${ended.id}`, `principal:${ended.principal}`])],
          detail: { credential: ended.id, kind: ended.kind, principal: ended.principal },
        },
        answer: { credential: ended.id },
      };
    },
  };
}

/**
 * A person, on their browser session, binds a second account the app
 * verified (`AccountLink`). The account bound to anyone already, them
 * included, is refused. So is one whose row the read found written behind
 * the vault, `tampered`: it is bound to someone, the row cannot say whom.
 *
 * A row the index does not find: one deleted, or edited to say it is
 * revoked, which takes it out of `identities_active_subject`, and no other
 * index reads an account by its subject. The account is then bound to the
 * caller, who holds it at its provider, and so could sign in as the member
 * it was bound to anyway; that member's row, edited, serves nobody.
 */
function accountLink(input: Presented & AccountLink, vault: Deciding): Operation<Parts, Answers['account.link']> {
  const shown = presented(input);
  const emails = verified(input.account);
  if (emails === undefined) throw new TypeError('an account is linked by its provider, issuer and subject, with 20 verified emails at most, lowercase');
  const { provider, issuer, subject } = input.account;
  // Drawn here: a decision draws nothing.
  const id = randomUUID();
  const read = {
    ...callerParts(shown.token, NO_PROJECT),
    // Where it is bound: one row at most, found by the unique index that holds an account to one member (`identities_active_subject`).
    bound: part(identities, sql`${identities.id} IN (SELECT i.id FROM identities i WHERE i.provider = ${provider} AND i.issuer_hash = ${issuer} AND i.active_subject = ${subject})`),
  };
  return {
    read,
    denied: refusedTo('account.link', shown, vault.workloads, { objects: (seen: Seen<typeof read>) => seen.bound.map((row) => `identity:${row.id}`) }),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      // A browser's session, a person's, which an account opened: an account linked through a token would sign in with all its person holds, for good.
      if (caller.credential.kind !== 'browser') return { refused: 'no_access' };
      if (seen.bound.some((row) => row.revokedAt === null)) return { refused: 'already_linked' };
      // A row written behind the vault is not a row that is absent: the account may be bound to anyone.
      if (unsealed.bound > 0) return { refused: 'tampered' };
      const now = new Date(at);
      return {
        writes: [put(identities, { id, provider, subject, issuerHash: issuer, generation: caller.credential.generation, principal: caller.principal, email: emails[0] ?? null, createdAt: now, createdBy: caller.principal, lastSignInAt: now, revokedAt: null, revokedBy: null })],
        entry: {
          ...by(caller, shown),
          kept: true,
          action: 'account.link',
          objects: [`principal:${caller.principal}`, `credential:${caller.credential.id}`, `identity:${id}`],
          detail: { verified: 'app', provider, subject, emails, identity: id },
        },
        answer: { identity: id },
      };
    },
  };
}

/**
 * The caller revokes one of their accounts (`AccountUnlink`): one row
 * written. The sessions it opened end with it, by the rule that reads them
 * (`callerOf`), with no write. A row hidden from the read is no account of
 * theirs: refused.
 */
function accountUnlink(input: Presented & AccountUnlink, vault: Deciding): Operation<Parts, Answers['account.unlink']> {
  const shown = presented(input);
  const { identity: id } = input;
  if (!text(id) || !UUID.test(id)) throw new TypeError("an account is unlinked by its identity's id");
  const read = {
    ...callerParts(shown.token, NO_PROJECT),
    target: part(identities, sql`${identities.id} = ${id}::uuid`),
  };
  return {
    read,
    denied: refusedTo('account.unlink', shown, vault.workloads, { objects: (seen: Seen<typeof read>) => seen.target.map((row) => `identity:${row.id}`) }),
    decide(seen: Seen<typeof read>, at: number) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      // On a session, which only a person has.
      if (!onSession(caller)) return { refused: 'no_access' };
      const row = seen.target.find((other) => other.principal === caller.principal && other.revokedAt === null);
      if (row === undefined) return { refused: 'unknown_identity' };
      return {
        writes: [amended(identities, row, { revokedAt: new Date(at), revokedBy: caller.principal })],
        entry: {
          ...by(caller, shown),
          kept: true,
          action: 'account.unlink',
          objects: [`principal:${caller.principal}`, `credential:${caller.credential.id}`, `identity:${id}`],
          detail: { identity: id, provider: row.provider, subject: row.subject },
        },
        answer: { identity: id },
      };
    },
  };
}

/** A service's token lasts 366 days at most, as 0.14.7's (`MAX_SERVICE_TOKEN_DAYS`). */
const SERVICE_MINUTES = 366 * 24 * 60;
/** Where a fork inherits from, three deep, as a use reads it (use.ts). */
const MAX_PARENTS = 3;
/** A place's slug as one is made (`SLUG` in places.ts): a tombstone's `~` names none. */
export const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
/** An environment a handle stands in for, by path: `market/dev`, or `market/dev@me` for its person's personal config of it. */
const HANDLE_PATH = /^([a-z0-9][a-z0-9-]{0,62})\/([a-z0-9][a-z0-9-]{0,62})(@me)?$/;
/** Each kind's prefix, which its hint starts with (`tokenHint` in @coffre/core/identity). */
const PREFIX = { personal: 'coffre_pat_', handle: 'coffre_use_', service: 'coffre_svc_' } as const;

/** A label as 0.14.7 took one, printed in lists and terminals: trimmed, 1 to 120 characters, no control character. */
export const labelled = (value: unknown): value is string => text(value) && value.length <= 120 && value !== '' && value === value.trim() && !/\p{Cc}/u.test(value);

/** What a handle reads and uses, and no more: it writes nothing (0.14.7's `HANDLE_HOLDS`). */
const HANDLE_HOLDS: RoleDefinition = { name: 'Handle', description: 'Read and use, as its person does.', permissions: ['secret.read', 'secret.use'], protected: ['secret.read', 'secret.use'] };
/**
 * The roles a handle's scope is made under: `viewer` where its person
 * reads, `contributor` where they only use, each keeping what they hold
 * there of reading and using, in each column (`heldColumns`), whatever an
 * Owner made of the roles.
 */
const HANDLE_ROLES: Policy['roles'] = { viewer: HANDLE_HOLDS, contributor: HANDLE_HOLDS };

/** A place asked, by slug, with the role asked there. */
export type Wanted = { project: string; environment: string | null; role: string };

/** A scope as the app names it, `{ "market/dev": "viewer" }`, copied: 1 to 1,000 places, each a project or one of its environments by slug, and a role's id. */
export function scopeAsked(value: unknown): Wanted[] | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0 || entries.length > MAX_SCOPE_PLACES) return undefined;
  const wanted: Wanted[] = [];
  for (const [path, role] of entries) {
    const [project, environment, ...more] = path.split('/');
    if (more.length > 0 || !SLUG.test(project!) || !(environment === undefined || SLUG.test(environment)) || typeof role !== 'string' || !ROLE_ID.test(role)) return undefined;
    wanted.push({ project: project!, environment: environment ?? null, role });
  }
  return wanted;
}

/** A handle's environments as the app names them, copied: 1 to 1,000 paths. */
function pathsAsked(value: unknown): { project: string; environment: string; personal: boolean }[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_SCOPE_PLACES) return undefined;
  const paths = [...value].map((path: unknown) => (typeof path === 'string' ? HANDLE_PATH.exec(path) : null));
  if (!paths.every((match) => match !== null)) return undefined;
  return paths.map((match) => ({ project: match![1]!, environment: match![2]!, personal: match![3] !== undefined }));
}

/** A grant of a scope, and the place it is on as the caller names it. */
export type Issued = { grant: ScopeGrant; path: string };

/**
 * A scope as the credential's row seals it, which a use reads
 * (`isCredentialScope`): each place by id, in order, both columns of what
 * it holds, and, a service's, whether it reads the sensitive values there.
 * 0.14.7's `storedScope`.
 */
export function sealedScope(issued: readonly Issued[]): ScopeGrant[] {
  const key = (grant: ScopeGrant) => `${grant.projectId}/${grant.environmentId ?? ''}`;
  return issued
    .map(({ grant }) => grant)
    .sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0))
    .map((grant) => {
      const { permissions, protected: guarded } = scopeDefinition(grant);
      return { projectId: grant.projectId, environmentId: grant.environmentId, role: grant.role, permissions: { normal: [...permissions], protected: [...guarded] }, ...(grant.sensitive === undefined ? {} : { sensitive: grant.sensitive }) };
    });
}

/**
 * Make a token (`TokenCreate`): one row written, the credential, its scope
 * sealed on it, by place id, from paths resolved through the rows read.
 * 0.14.7's `issuePersonalToken`, `issueHandle` and `issueServiceToken`.
 *
 * - A personal token: a person on a session, each role one that manages no
 *   access and that they hold all of at its place, and in a project's
 *   protected environments (`personalScope`); each grant keeps what the
 *   role holds and they hold there, column by column (`issuedGrant`).
 * - A handle: a person on a session or a personal token; each environment
 *   named and each parent it inherits from that they read or use, `viewer`
 *   where they read and `contributor` where they only use; never past the
 *   personal token it is made on, in what it reaches or when it ends.
 * - A service's token: whoever manages the service (`managesService`), each
 *   grant one the service holds and the caller could give it
 *   (`issuesCredential`); every grant it holds when none is asked; and the
 *   sensitive values of a project only from an Owner of it (`ownsProject`).
 *   Its scope is always written, never null: what was asked, or what the
 *   read found it holds.
 *
 * Rows hidden from the read: one with a MAC that is not the vault's
 * refuses, `tampered`, wherever it is. One taken away for the decision,
 * and put back after: the caller's grant, a role, a place or a parent,
 * and the token reaches less, or is refused. A protected environment's
 * row: a service's token on its project takes holding the role in each
 * environment the read finds protected, as 0.14.7 did (`givesService`), so
 * one made without the row is made as if it were not protected, which
 * 0.16 accepts (D241, docs/design/0.16.md); a personal token made without
 * it, which would have been refused, keeps what its person holds in that column on
 * the whole project (`heldColumns`), and so uses, and never reads, where
 * they only use. A service's grant is
 * the one that would let a caller manage the service when they would not
 * (the "Not caught within the minute" item of docs/design/0.16.md): the
 * service holds dev and prod, the caller is a Developer of dev, and the
 * prod grant is taken away while they mint. The token they make holds its
 * sealed scope and no more, each grant of it one they hold every
 * permission of (`issuesCredential`): dev, and never prod, once the grant
 * is back. What is left is a token under a service's name that its maker
 * did not manage, reaching nothing they did not, named in a kept
 * `token.create` entry with them as its actor.
 */
function tokenCreate(input: Presented & TokenCreate, vault: Deciding): Operation<Parts, Answers['token.create']> {
  const shown = presented(input);
  const { kind, credential: token, hint } = input;
  const service = kind === 'service' ? (input as { member: unknown }).member : null;
  // Whose personal token the route names: the caller's own, or none.
  const forWhom = kind === 'personal' ? (input as { member: unknown }).member : null;
  const most = kind === 'service' ? SERVICE_MINUTES : MAX_PERSONAL_TOKEN_MINUTES;
  const wanted = kind === 'handle' || (kind === 'service' && (input as { scope: unknown }).scope === null) ? null : scopeAsked((input as { scope: unknown }).scope);
  const paths = kind === 'handle' ? pathsAsked((input as { paths: unknown }).paths) : null;
  if (!(kind === 'personal' || kind === 'handle' || kind === 'service')
    || !text(token?.token) || !HASH.test(token.token) || !Number.isInteger(token.minutes) || token.minutes < 1 || token.minutes > most
    || !(labelled(token.label) || (kind === 'service' && token.label === null))
    || !text(hint) || !new RegExp(`^${PREFIX[kind]}…[A-Za-z0-9_-]{4}$`).test(hint)
    || (kind === 'service' ? !(typeof service === 'string' && text(service) && MEMBER.test(service) && service.startsWith('token:')) || (wanted === undefined) : kind === 'handle' ? paths === undefined : wanted == null || !(typeof forWhom === 'string' && text(forWhom) && MEMBER.test(forWhom) && forWhom.startsWith('user:')))) {
    throw new TypeError("a token is made of a kind, personal, handle or service, from its token's SHA-256 and its hint; for a week at most, a service's 366 days; with a label, a service's or none; and a person and a scope of 1 to 1,000 places by path, a handle's environments, or a service account and its scope or none");
  }
  // Drawn here: a decision draws nothing.
  const id = randomUUID();
  const member = service as string | null;
  // What is asked about, by slug: each project, and each environment with its project.
  const asked: { project: string; environment: string | null }[] = paths ?? wanted ?? [];
  const slugs = [...new Set(asked.map((place) => place.project))];
  const pairs = asked.filter((place): place is { project: string; environment: string } => place.environment !== null);
  const named = sql`(SELECT p.id FROM projects p WHERE p.slug = ANY(${sql.param(slugs)}::text[]))`;
  // Each project and environment pair through the two unique keys, so each is an index lookup; a handle's with the parents each inherits from.
  const onEnvironments = sql`(SELECT e.id FROM unnest(${sql.param(pairs.map((place) => place.project))}::text[], ${sql.param(pairs.map((place) => place.environment))}::text[]) AS a(project, environment) JOIN projects p ON p.slug = a.project JOIN environments e ON e.project_id = p.id AND e.slug = a.environment)`;
  const chain = sql`(WITH RECURSIVE chain (id, parent_id, depth) AS (
    SELECT e.id, e.parent_id, 0 FROM environments e WHERE e.id IN ${onEnvironments}
    UNION SELECT e.id, e.parent_id, chain.depth + 1 FROM environments e JOIN chain ON e.id = chain.parent_id WHERE chain.depth < ${MAX_PARENTS}
  ) SELECT id FROM chain)`;
  const read = {
    // The caller's grants and roles in every project the token would reach, and the environments protected there.
    ...callerParts(shown.token, member === null ? named : sql`(${named} UNION ${projectsOf(member)})`),
    project: part(projects, sql`${projects.slug} = ANY(${sql.param(slugs)}::text[])`),
    environment: part(environments, sql`${environments.id} IN ${kind === 'handle' ? chain : onEnvironments}`),
    // The roles asked: what each holds is its row.
    asked: part(roles, sql`NOT ${roles.instance} AND ${roles.id} = ANY(${sql.param([...new Set((wanted ?? []).map((place) => place.role))])}::text[])`),
    ...serviceParts(member),
    // The projects of the service's grants, by which the token's answer names the places it holds. Each place a service's
    // token reaches is in one of them, so `beside` reads every environment the decision weighs, whatever its row says.
    holding: part(projects, member === null ? sql`false` : sql`${projects.id} IN ${projectsOf(member)}`),
  };
  type Read = Seen<typeof read>;
  /** A place asked, as far as the rows read have it. */
  const placeOf = (seen: Read, project: string, environment: string | null) => {
    const there = seen.project.find((row) => row.slug === project);
    if (there === undefined) return undefined;
    if (environment === null) return { place: { projectId: there.id } as Place, path: there.slug, object: `project:${there.id}` };
    const at = seen.environment.find((row) => row.projectId === there.id && row.slug === environment);
    return at && { place: { projectId: there.id, environmentId: at.id, environmentSlug: at.slug } as Place, path: `${there.slug}/${at.slug}`, object: `environment:${at.id}`, row: at };
  };
  const NO_ACCESS: Refusal = { refused: 'no_access' };
  return {
    read,
    denied: refusedTo('token.create', shown, vault.workloads, {
      objects: (seen: Read) => [
        ...seen.account.map((row) => `principal:${row.id}`),
        ...asked.flatMap(({ project, environment }) => {
          const found = placeOf(seen, project, environment);
          return found === undefined ? [] : [found.object];
        }),
      ],
    }),
    decide(seen: Read, at: number, unsealed: Unsealed<typeof read>) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (caller.workload !== null) return { refused: 'workload_cannot_issue' };
      // A row written behind the vault is not a row that is absent, wherever it is: one grant less, one role less, an environment unprotected.
      if (Object.values(unsealed).some((count) => count > 0)) return { refused: 'tampered' };
      const holder = caller.holds;
      let principal = caller.principal;
      let generation = caller.credential.generation;
      let ends = at + token.minutes * 60_000;
      let issued: Issued[];
      let places: { environmentId: string; personal: boolean }[] | null = null;

      if (kind === 'personal' || kind === 'handle') {
        if (!caller.principal.startsWith('user:')) return { refused: 'not_a_person' };
        // A personal token is made on a session: a token never makes another. A handle on a personal token too, within it.
        if (!(onSession(caller) || (kind === 'handle' && caller.credential.kind === 'personal'))) return NO_ACCESS;
      }
      if (kind === 'personal') {
        // For themselves alone: a person names no one else's.
        if (forWhom !== caller.principal) return NO_ACCESS;
        const policy: Policy = { ...holder.policy, roles: { ...definitionsOf(seen.asked), ...holder.policy.roles } };
        const person: Holdings & { policy: Policy } = { ...holder, policy };
        // As 0.14.7 told them: a role there is not, one its place does not take, or one that manages access; then a place that is not there; then one beyond them.
        if (!wanted!.every(({ role, environment }) => delegable(role, policy) && (environment === null || assignableToEnvironment(role, policy)))) return { refused: 'invalid' };
        const found = wanted!.map(({ project, environment, role }) => ({ role, at: placeOf(seen, project, environment) }));
        if (found.some(({ at: there }) => there === undefined)) return NO_ACCESS;
        issued = [];
        for (const { role, at: there } of found) {
          const { place, path } = there!;
          const definition = definitionOf(policy, role)!;
          // All the role gives them there, its protected column in a protected environment, and in each protected environment of a project.
          const beyond = [place, ...protectedWithin(policy, place)].some((spot) => PERMISSIONS.some((permission) => holdsAt(definition, permission, spot, person) && !allows(person, permission, spot)));
          if (beyond) return NO_ACCESS;
          issued.push({ grant: issuedGrant({ projectId: place.projectId, environmentId: place.environmentId ?? null, role }, policy, heldColumns(person, place)), path });
        }
      } else if (kind === 'handle') {
        // Each environment it reaches, by id, and whether its person reads there: each named, and each parent that they read or use.
        const reached = new Map<string, { place: Place; path: string; reads: boolean }>();
        places = [];
        for (const { project, environment, personal } of paths!) {
          const there = placeOf(seen, project, environment);
          if (there === undefined) return NO_ACCESS;
          reached.set(there.row!.id, { place: there.place, path: there.path, reads: allows(holder, 'secret.read', there.place) });
          if (!places.some((made) => made.environmentId === there.row!.id && made.personal === personal)) places.push({ environmentId: there.row!.id, personal });
          let child = there.row!;
          for (let depth = 0; child.parentId !== null && depth < MAX_PARENTS; depth += 1) {
            // In the same project, as its key holds it (`environments_parent_in_project`); a deleted one's tombstone is no parent.
            const parent = seen.environment.find((row) => row.id === child.parentId && !row.slug.includes('~'));
            if (parent === undefined) break;
            const place: Place = { projectId: parent.projectId, environmentId: parent.id, environmentSlug: parent.slug };
            const reads = allows(holder, 'secret.read', place);
            if (reads || allows(holder, 'secret.use', place)) reached.set(parent.id, { place, path: `${project}/${parent.slug}`, reads });
            child = parent;
          }
        }
        const policy: Policy = { ...holder.policy, roles: HANDLE_ROLES };
        issued = [];
        for (const { place, path, reads } of reached.values()) {
          // Use is what a handle exercises: where its person only uses, that is all it needs of them.
          const needs = reads ? PERMISSIONS.filter((permission) => holdsAt(ROLES.viewer, permission, place, holder)) : ['secret.use' as const];
          if (!needs.every((permission) => allows(holder, permission, place))) return NO_ACCESS;
          issued.push({ grant: issuedGrant({ projectId: place.projectId, environmentId: place.environmentId ?? null, role: reads ? 'viewer' : 'contributor' }, policy, heldColumns(holder, place)), path });
        }
        // Never past the personal token it is made on.
        if (caller.credential.kind === 'personal') ends = Math.min(ends, caller.credential.expiresAt.getTime());
      } else {
        if (vault.workloads?.useOnly === true) return { refused: 'use_only' };
        const manager = manages(caller, seen, unsealed, member!, at);
        if (manager !== true) return manager === 'tampered' ? { refused: 'tampered' } : NO_ACCESS;
        const account = serviceOf(seen, member!, at);
        if (account === null) return { refused: 'unknown_principal' };
        const row = seen.account.find((other) => other.id === member)!;
        [principal, generation] = [row.id, row.generation];
        const policy: Policy = { ...holder.policy, roles: { ...definitionsOf(seen.heldAs), ...definitionsOf(seen.asked), ...holder.policy.roles } };
        const issuer: Holdings & { policy: Policy } = { ...holder, policy };
        // A place it holds, by path: its project's slug, and its environment's.
        const pathOf = (place: Place) => {
          const project = seen.holding.find((other) => other.id === place.projectId)?.slug ?? place.projectId;
          return place.environmentId == null ? project : `${project}/${place.environmentSlug}`;
        };
        let scope: { role: string; place: Place; path: string }[];
        if (wanted === null) {
          scope = account.grants.map(({ role, place }) => ({ role, place, path: pathOf(place) }));
        } else {
          if (!wanted!.every(({ role, environment }) => definitionOf(policy, role) !== undefined && (environment === null || assignableToEnvironment(role, policy)))) return { refused: 'invalid' };
          const found = wanted!.map(({ project, environment, role }) => ({ role, at: placeOf(seen, project, environment) }));
          if (found.some(({ at: there }) => there === undefined)) return NO_ACCESS;
          scope = found.map(({ role, at: there }) => ({ role, place: there!.place, path: there!.path }));
        }
        // Nothing it is given later reaches a token made before: it needs a grant first.
        if (scope.length === 0) return { refused: 'no_grants' };
        // The role as it is now, all each grant keeps: the caller gives it, and the service holds, every permission of it.
        if (!issuesCredential(issuer, settingOf(seen), caller.principal, account, scope)) return NO_ACCESS;
        issued = scope.map(({ role, place, path }) => ({
          grant: { ...issuedGrant({ projectId: place.projectId, environmentId: place.environmentId ?? null, role }, policy), sensitive: ownsProject(issuer, place.projectId) },
          path,
        }));
      }

      const now = new Date(at);
      const expiresAt = new Date(ends);
      const scope = sealedScope(issued);
      return {
        writes: [put(credentials, {
          id, kind, tokenHash: Buffer.from(token.token, 'hex'), tokenHint: hint, previousTokenHash: null, generation, principal, identityId: null,
          scope: JSON.stringify(scope), places: places === null ? null : JSON.stringify(places), label: token.label, createdAt: now, createdBy: caller.principal, expiresAt,
          lastUsedAt: null, lastUsedIp: null, frozenAt: null, revokedAt: null, revokedBy: null,
          jkt: null, notAfter: null, ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null, run: null, client: null, challenge: null,
        })],
        entry: {
          ...by(caller, shown),
          // A run's handle comes and goes with it, and ages out with the uses; a token is kept.
          kept: kind !== 'handle',
          action: 'token.create',
          objects: [...new Set([`principal:${caller.principal}`, `credential:${caller.credential.id}`, `credential:${id}`, `principal:${principal}`, ...scope.map((grant) => (grant.environmentId === null ? `project:${grant.projectId}` : `environment:${grant.environmentId}`))])],
          detail: { credential: id, kind, principal, expiresAt: expiresAt.toISOString(), scope, ...(places === null ? {} : { places }) },
        },
        answer: { principal, credential: id, expiresAt: expiresAt.toISOString(), scope: Object.fromEntries(issued.map(({ grant, path }) => [path, grant.role]).sort(([a], [b]) => (a! < b! ? -1 : 1))) },
      };
    },
  };
}

/** The longest a CLI's session lasts, whatever the app asks: the most a deployment's `cliSessionDays` says. */
const CLI_MINUTES = 365 * 24 * 60;

/**
 * The instance's one row, which the vault's adoption of the database
 * writes. A change nobody asks reads it, as a sign-in does: on a database
 * not adopted yet it would begin the log, and the adoption would never run.
 */
const instancePart = () => part(policy, sql`${policy.onlyRow}`);

/** `adopting` before the adoption, `tampered` for an instance's row that is not the vault's; else nothing. */
const adopted = (rows: readonly unknown[], unsealed: number): Refusal | undefined => (rows.length === 0 ? { refused: unsealed > 0 ? 'tampered' : 'adopting' } : undefined);

/**
 * A CLI asks to be signed in from a browser (`DeviceStart`): one row
 * written, the device login, with both codes the app drew. Nobody asks it,
 * and nothing it reads decides access: a row that holds either code, there
 * or written behind the vault, is refused alike, since the table's unique
 * keys would refuse the write too; a row deleted for the decision lets the
 * one write through. How many wait at once is the app's to count, before
 * it asks (docs/design/0.16.md, "A cap on strangers is the app's").
 */
function deviceStart(input: Asked<'device.start'>): Operation<Parts, Answers['device.start']> {
  const from = traced(input);
  const { code, userCode, label } = input;
  if (!text(code) || !HASH.test(code) || !text(userCode) || !USER_CODE.test(userCode) || !(label === null || labelled(label))) {
    throw new TypeError("a device login starts with its device code's SHA-256, a user code of eight letters, BCDF-GHJK, and the CLI's label or none");
  }
  // Drawn here: a decision draws nothing.
  const id = randomUUID();
  const read = {
    // Either code held: one row at most by each unique key.
    taken: part(deviceLogins, sql`${deviceLogins.deviceCodeHash} = decode(${code}, 'hex') OR ${deviceLogins.userCode} = ${userCode}`),
    instance: instancePart(),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const before = adopted(seen.instance, unsealed.instance);
      if (before !== undefined) return before;
      if (seen.taken.length > 0 || unsealed.taken > 0) return { refused: 'taken' };
      const now = new Date(at);
      const expiresAt = new Date(at + DEVICE_TTL_SECONDS * 1000);
      return {
        writes: [put(deviceLogins, {
          id, deviceCodeHash: Buffer.from(code, 'hex'), userCode, clientLabel: label, clientIp: from.ip, createdAt: now, expiresAt,
          decidedAt: null, decision: null, generation: 0, principal: null, consumedAt: null,
        })],
        entry: {
          // Asked by nobody yet: whoever approves it is named by the next.
          kept: false,
          action: 'device.start', actor: null, credential: null, request: from.request, ip: from.ip,
          objects: [`device_login:${id}`],
          detail: { deviceLogin: id, userCode, label, expiresAt: expiresAt.toISOString() },
        },
        answer: { deviceLogin: id, expiresAt: expiresAt.toISOString() },
      };
    },
  };
}

/**
 * A person, on a session of theirs, approves or denies a device login by
 * its user code (`DeviceDecide`): its row written, decided. Only one that
 * waits for a decision, before its 10 minutes are up: of two people
 * deciding at once, the second finds it decided. A row written behind the
 * vault is refused, `tampered`: what the person approves is what its row
 * says, and its device code is whoever wrote it.
 */
function deviceDecide(input: Presented & DeviceDecide, vault: Deciding): Operation<Parts, Answers['device.decide']> {
  const shown = presented(input);
  const { userCode, approve } = input;
  if (!text(userCode) || !USER_CODE.test(userCode) || typeof approve !== 'boolean') throw new TypeError('a device login is approved or denied by its user code, BCDF-GHJK');
  const action = approve ? 'device.approve' : 'device.deny';
  const read = {
    ...callerParts(shown.token, NO_PROJECT),
    login: part(deviceLogins, sql`${deviceLogins.userCode} = ${userCode}`),
  };
  return {
    read,
    denied: refusedTo(action, shown, vault.workloads, { objects: (seen: Seen<typeof read>) => seen.login.map((row) => `device_login:${row.id}`) }),
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      // A person, as themselves, on a session: a token approving one would make a session with all its person holds (0.14.7).
      if (!onSession(caller)) return { refused: 'no_access' };
      if (unsealed.login > 0) return { refused: 'tampered' };
      // Decided only with a write's time left before it expires (`WRITE_MS`): a write that starts by `until` may wait on a lock that long.
      const row = seen.login.find((other) => other.decidedAt === null && heldUntil(other) > at);
      if (row === undefined) return { refused: 'unknown_code' };
      const now = new Date(at);
      return {
        writes: [amended(deviceLogins, row, approve
          ? { decidedAt: now, decision: 'approved', principal: caller.principal, generation: caller.credential.generation }
          : { decidedAt: now, decision: 'denied' })],
        // Decided while it waits: a write that would start too late to land within its 10 minutes is decided again, and refused.
        until: heldUntil(row),
        entry: {
          ...by(caller, shown),
          // Part of a session's coming, which ages out (D231).
          kept: false,
          action,
          objects: [`principal:${caller.principal}`, `credential:${caller.credential.id}`, `device_login:${row.id}`],
          detail: { deviceLogin: row.id, label: row.clientLabel, clientIp: row.clientIp },
        },
        answer: { deviceLogin: row.id },
      };
    },
  };
}

/**
 * The last instant a change of a device login may start its write and still
 * land before the login expires: its expiry, less the time a write is given
 * (`WRITE_MS`, change.ts), which a row lock may take whole.
 */
function heldUntil(login: { expiresAt: Date }): number {
  return login.expiresAt.getTime() - WRITE_MS;
}

/**
 * The CLI collects its session (`DeviceRedeem`): the device login written
 * consumed, and a CLI session of its approver's, in one statement. Nobody
 * asks it but whoever holds the device code. Of two collecting at once,
 * the second finds it consumed.
 *
 * Its decision rests on two rows, the device login and its approver's:
 * either written behind the vault refuses it, `tampered`, since a row that
 * says someone approved it would become their session. One deleted for
 * the decision is not there, and only refuses.
 */
function deviceRedeem(input: Asked<'device.redeem'>): Operation<Parts, Answers['device.redeem']> {
  const from = traced(input);
  const { code, session } = input;
  if (!text(code) || !HASH.test(code) || !text(session?.token) || !HASH.test(session.token) || !Number.isInteger(session.minutes) || session.minutes < 1 || session.minutes > CLI_MINUTES) {
    throw new TypeError("a device login is collected by its device code's SHA-256, for a session by its token's SHA-256, of 365 days at most");
  }
  // Drawn here: a decision draws nothing.
  const id = randomUUID();
  const of = sql`d.device_code_hash = decode(${code}, 'hex')`;
  const read = {
    login: part(deviceLogins, sql`${deviceLogins.deviceCodeHash} = decode(${code}, 'hex')`),
    approver: part(principals, sql`${principals.id} IN (SELECT d.principal FROM device_logins d WHERE ${of})`),
    instance: instancePart(),
  };
  return {
    read,
    decide(seen: Seen<typeof read>, at: number, unsealed: Unsealed<typeof read>) {
      const before = adopted(seen.instance, unsealed.instance);
      if (before !== undefined) return before;
      if (unsealed.login + unsealed.approver > 0) return { refused: 'tampered' };
      const [row] = seen.login;
      // Approved or not, one past its 10 minutes is good for nothing: one the CLI never collected stays no key to a session.
      // As for a decision, a write's time before it expires is already past it.
      if (row === undefined || row.consumedAt !== null || heldUntil(row) <= at) return { refused: 'expired' };
      if (row.decision === null) return { refused: 'pending' };
      // Approved before its approver was last removed: they were let back in with nothing from before.
      const who = seen.approver.find((other) => other.id === row.principal);
      if (row.decision !== 'approved' || who === undefined || who.status !== 'active' || who.generation !== row.generation) return { refused: 'denied' };
      const now = new Date(at);
      const expiresAt = new Date(at + session.minutes * 60_000);
      return {
        writes: [
          amended(deviceLogins, row, { consumedAt: now }),
          put(credentials, {
            id, kind: 'cli', tokenHash: Buffer.from(session.token, 'hex'), tokenHint: null, previousTokenHash: null, generation: who.generation, principal: who.id, identityId: null,
            scope: null, places: null, label: row.clientLabel, createdAt: now, createdBy: who.id, expiresAt, lastUsedAt: null, lastUsedIp: null, frozenAt: null, revokedAt: null, revokedBy: null,
            jkt: null, notAfter: null, ancestors: null, constraints: null, enrollmentId: null, approvedAt: null, approvedBy: null, run: null, client: null, challenge: null,
          }),
        ],
        // Collected while its code is good, the write's own time included.
        until: heldUntil(row),
        entry: {
          // A session's coming ages out with the uses (D231).
          kept: false,
          action: 'sign_in', actor: who.id, credential: id, request: from.request, ip: from.ip,
          objects: [`principal:${who.id}`, `credential:${id}`, `device_login:${row.id}`],
          detail: { kind: 'cli', deviceLogin: row.id, label: row.clientLabel, clientIp: row.clientIp },
        },
        answer: { principal: who.id, credential: id, expiresAt: expiresAt.toISOString() },
      };
    },
  };
}

/** The changes of sign-in and of credentials (docs/design/0.16.md, "Signing in"). */
export const signinOperations: Operations<SigninChanges> = {
  signin,
  'credential.end': credentialEnd,
  'account.link': accountLink,
  'account.unlink': accountUnlink,
  'token.create': tokenCreate,
  'device.start': deviceStart,
  'device.decide': deviceDecide,
  'device.redeem': deviceRedeem,
};
