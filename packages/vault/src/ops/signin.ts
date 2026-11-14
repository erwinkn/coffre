import { randomUUID } from 'node:crypto';

import type { Answers, Asked, SigninChanges } from '@coffre/core/vault';
import { credentials, identities, policy, principals } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { amended, part, put, type Operation, type Parts, type Seen, type Unsealed, type Write } from '../change.ts';
import type { Fresh } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import type { Operations } from './index.ts';
import { HASH, text, traced } from './input.ts';

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
  const emails = Array.isArray(account?.emails) ? [...account.emails] : undefined;
  if (emails === undefined || emails.length > MOST_EMAILS || !emails.every(email) || new Set(emails).size !== emails.length
    || !text(account.provider) || !PROVIDER.test(account.provider) || !text(account.issuer) || account.issuer === '' || !text(account.subject) || account.subject === ''
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
      if (seen.instance.length === 0) return { refused: 'adopting' };
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

/** The changes of sign-in and of credentials (docs/design/0.16.md, "Signing in"). */
export const signinOperations: Operations<SigninChanges> = { signin };
