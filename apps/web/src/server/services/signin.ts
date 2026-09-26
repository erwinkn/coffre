import { randomBytes } from 'node:crypto';

import type { Database, DatabaseClient } from '../database.ts';
import { toIsoTimestamp, toNullableIsoTimestamp } from '../database.ts';

import type { AuditEntry } from '../../../../../packages/db/src/audit.ts';
import type { Principal } from '../../../../../packages/core/src/identity/types.ts';
import type { SigninConfig } from '../../../../../packages/core/src/identity/signin/config.ts';
import type { SigninProfile } from '../../../../../packages/core/src/identity/signin/types.ts';
import {
  generateToken,
  hashToken,
  isCoffreToken,
  tokenHint,
  type CredentialKind,
} from '../../../../../packages/core/src/identity/tokens.ts';
import { advisoryLock, runAudited } from './audited.ts';
import { isInstanceOwner, isRootAdmin, type PrincipalRef } from './permissions.ts';
import { AccessDenied, AuditedFailure, NotFound, type RequestContext } from './secrets.ts';

export type SigninServiceDeps = {
  pool: Database;
  auditChainKey: Buffer;
  rootAdmins: readonly string[];
  signin: SigninConfig;
};

/** Why a provider-verified person was still not let in. */
export type SigninRefusal =
  /** No invitation matches any of the account's verified emails. */
  | 'not_registered'
  /** The matching person was removed from this instance. */
  | 'deactivated'
  /**
   * The email matches someone who already signs in with another account. A
   * second account is linked from the account page, while signed in, never
   * by email alone.
   */
  | 'account_mismatch'
  /** Linking: the account already belongs to someone else. */
  | 'already_linked';

class SigninRefused extends Error {
  readonly statusCode = 403;
  readonly reason: SigninRefusal;
  constructor(reason: SigninRefusal) {
    super(reason);
    this.reason = reason;
  }
}

export type IssuedCredential = { id: string; token: string; expiresAt: string };

export type SigninResult =
  | { ok: true; principal: PrincipalRef; credential: IssuedCredential }
  | { ok: false; reason: SigninRefusal };

/** A caller authenticated by a coffre-issued credential. */
export type CredentialPrincipal = Principal & { credentialId: string };

export type ClientMeta = {
  requestId: string;
  sourceIp: string | null;
  /** Shown in the session list, e.g. "Firefox on macOS". */
  label: string | null;
};

export type SessionRow = {
  id: string;
  kind: 'browser' | 'cli';
  label: string | null;
  hint: string;
  provider: string | null;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
  current: boolean;
};

export type IdentityRow = {
  id: string;
  provider: string;
  email: string | null;
  createdAt: string;
  lastSignInAt: string | null;
};

export type ServiceTokenRow = {
  id: string;
  label: string | null;
  hint: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  lastUsedAt: string | null;
  lastUsedIp: string | null;
};

export type DeviceStart = {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
};

export type DeviceRequest = {
  userCode: string;
  clientLabel: string | null;
  clientIp: string | null;
  createdAt: string;
  expiresAt: string;
};

export type DevicePoll =
  | { status: 'pending' }
  | { status: 'denied' }
  | { status: 'expired' }
  | { status: 'approved'; principal: PrincipalRef; credential: IssuedCredential };

const DEVICE_TTL_SECONDS = 10 * 60;
const DEVICE_POLL_SECONDS = 5;
const DEVICE_PENDING_PER_IP = 5;
const DEVICE_PENDING_TOTAL = 200;
/** No vowels, so a code never spells a word; no 0/O or 1/I lookalikes. */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;
const MAX_SERVICE_TOKEN_DAYS = 366;

function userCode(): string {
  const chars: string[] = [];
  while (chars.length < 8) {
    for (const byte of randomBytes(16)) {
      // 240 is the largest multiple of 20 below 256: no modulo bias.
      if (byte < 240 && chars.length < 8) chars.push(USER_CODE_ALPHABET[byte % 20]);
    }
  }
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
}

/** Accept what a person types: any case, with or without the dash. */
export function normalizeUserCode(input: string): string | null {
  const letters = input.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length !== 8 || [...letters].some((c) => !USER_CODE_ALPHABET.includes(c))) {
    return null;
  }
  return `${letters.slice(0, 4)}-${letters.slice(4)}`;
}

function tooMany(message: string): Error {
  return Object.assign(new Error(message), { statusCode: 429 });
}

/**
 * coffre's own sign-in: who may come in, and the credentials they hold.
 *
 * Providers only prove control of an account. What that account may do here
 * is decided in this file, in three steps:
 *
 * 1. An account already bound to a person (an `identities` row) signs in as
 *    that person, whatever its email says today.
 * 2. Otherwise a verified email that matches an invited person binds the
 *    account to them, but only if they have no account bound yet. Taking over
 *    an existing person by email would let whoever controls a stale address
 *    at some provider walk in.
 * 3. Otherwise the answer is no, and the refusal is audited.
 *
 * Every credential is a random bearer token stored only as its SHA-256.
 */
export class SigninService {
  readonly #deps: SigninServiceDeps;

  constructor(deps: SigninServiceDeps) {
    this.#deps = deps;
  }

  get config(): SigninConfig {
    return this.#deps.signin;
  }

  #run<T>(fn: (tx: DatabaseClient) => Promise<{ result: T; entries: AuditEntry[] }>): Promise<T> {
    return runAudited(this.#deps.pool, this.#deps.auditChainKey, fn);
  }

  #isRoot(principalId: string): boolean {
    return isRootAdmin({ type: 'user', id: principalId }, this.#deps.rootAdmins);
  }

  // --- signing in ---------------------------------------------------------

  async completeSignin(profile: SigninProfile, meta: ClientMeta): Promise<SigninResult> {
    const claimed = profile.emails[0] ?? `${profile.provider}:${profile.subject}`;
    const base = {
      actorType: 'user' as const,
      actorId: claimed,
      action: 'auth.signin',
      requestId: meta.requestId,
      sourceIp: meta.sourceIp,
    };
    const account = { provider: profile.provider, subject: profile.subject, emails: profile.emails };
    const refuse = (reason: SigninRefusal, actorId = claimed) =>
      new AuditedFailure(new SigninRefused(reason), {
        ...base,
        actorId,
        decision: 'deny',
        metadata: { ...account, reason },
      });

    try {
      return await this.#run(async (tx) => {
        await advisoryLock(tx, `coffre:identity:${profile.provider}:${profile.subject}`);
        const entries: AuditEntry[] = [];

        const bound = await tx.query<{ id: string; principal_id: string; active: boolean }>(
          `SELECT i.id, i.principal_id, p.active
             FROM identities i
             JOIN principals p
               ON p.principal_type = i.principal_type AND p.principal_id = i.principal_id
            WHERE i.provider = $1 AND i.subject = $2 AND i.revoked_at IS NULL`,
          [profile.provider, profile.subject],
        );

        let principalId: string;
        let identityId: string;
        if (bound.rows[0] !== undefined) {
          const identity = bound.rows[0];
          principalId = identity.principal_id;
          identityId = identity.id;
          if (!identity.active && !this.#isRoot(principalId)) throw refuse('deactivated', principalId);
          await this.#ensureRootRow(tx, principalId);
          await tx.query(
            `UPDATE identities
                SET last_sign_in_at = now(), email = COALESCE($2, email)
              WHERE id = $1`,
            [identityId, profile.emails[0] ?? null],
          );
        } else {
          const match = await this.#principalForEmails(tx, profile.emails);
          if (match === null) throw refuse('not_registered');
          principalId = match.id;
          if (!match.active && !this.#isRoot(principalId)) throw refuse('deactivated', principalId);

          await advisoryLock(tx, `coffre:principal:user:${principalId}`);
          const existing = await tx.query(
            `SELECT 1 FROM identities
              WHERE principal_type = 'user' AND principal_id = $1 AND revoked_at IS NULL`,
            [principalId],
          );
          if (existing.rowCount !== 0) throw refuse('account_mismatch', principalId);

          await this.#ensureRootRow(tx, principalId);
          identityId = await this.#bind(tx, principalId, profile, principalId);
          entries.push({
            ...base,
            actorId: principalId,
            action: 'identity.bind',
            decision: 'allow',
            metadata: { ...account, identityId, matchedEmail: match.email },
          });
        }

        const principal: PrincipalRef = { type: 'user', id: principalId };
        const credential = await this.#issue(tx, 'browser', principal, {
          identityId,
          label: meta.label,
          createdBy: principalId,
          expiresAt: new Date(Date.now() + this.#deps.signin.browserSessionHours * 3_600_000),
        });
        entries.push({
          ...base,
          actorId: principalId,
          decision: 'allow',
          metadata: { ...account, identityId, credentialId: credential.id },
        });

        return { result: { ok: true as const, principal, credential }, entries };
      });
    } catch (error) {
      if (error instanceof SigninRefused) return { ok: false, reason: error.reason };
      throw error;
    }
  }

  /** Bind another provider account to the signed-in person. */
  async linkIdentity(
    ctx: RequestContext,
    profile: SigninProfile,
  ): Promise<{ ok: true } | { ok: false; reason: SigninRefusal }> {
    const base = {
      actorType: ctx.principal.type,
      actorId: ctx.principal.id,
      action: 'identity.bind',
      requestId: ctx.requestId,
      sourceIp: ctx.sourceIp,
    };
    const account = { provider: profile.provider, subject: profile.subject, emails: profile.emails };

    try {
      return await this.#run(async (tx) => {
        if (ctx.principal.type !== 'user') throw new AccessDenied('only people link sign-in accounts');
        await advisoryLock(tx, `coffre:identity:${profile.provider}:${profile.subject}`);

        const bound = await tx.query<{ principal_id: string }>(
          `SELECT principal_id FROM identities
            WHERE provider = $1 AND subject = $2 AND revoked_at IS NULL`,
          [profile.provider, profile.subject],
        );
        if (bound.rows[0] !== undefined) {
          if (bound.rows[0].principal_id === ctx.principal.id) {
            return { result: { ok: true as const }, entries: [] };
          }
          throw new AuditedFailure(new SigninRefused('already_linked'), {
            ...base,
            decision: 'deny',
            metadata: { ...account, reason: 'already_linked' },
          });
        }

        const identityId = await this.#bind(tx, ctx.principal.id, profile, ctx.principal.id);
        return {
          result: { ok: true as const },
          entries: [{ ...base, decision: 'allow', metadata: { ...account, identityId } }],
        };
      });
    } catch (error) {
      if (error instanceof SigninRefused) return { ok: false, reason: error.reason };
      throw error;
    }
  }

  /**
   * Configured root admins need no invitation, but identities and
   * credentials need a principals row to point at, and verify() requires it
   * to be active.
   */
  async #ensureRootRow(tx: DatabaseClient, principalId: string): Promise<void> {
    if (!this.#isRoot(principalId)) return;
    await tx.query(
      `INSERT INTO principals (principal_type, principal_id, instance_role, created_by, active)
       VALUES ('user', $1, 'user', 'system:signin', true)
       ON CONFLICT (principal_type, principal_id) DO UPDATE SET active = true
       WHERE NOT principals.active`,
      [principalId],
    );
  }

  async #bind(
    tx: DatabaseClient,
    principalId: string,
    profile: SigninProfile,
    createdBy: string,
  ): Promise<string> {
    const inserted = await tx.query<{ id: string }>(
      `INSERT INTO identities (provider, subject, principal_type, principal_id, email, created_by, last_sign_in_at)
       VALUES ($1, $2, 'user', $3, $4, $5, now())
       RETURNING id`,
      [profile.provider, profile.subject, principalId, profile.emails[0] ?? null, createdBy],
    );
    return inserted.rows[0].id;
  }

  /**
   * The invited person, or root admin, that one of these verified emails
   * names. The provider's primary address is tried first.
   */
  async #principalForEmails(
    tx: DatabaseClient,
    emails: readonly string[],
  ): Promise<{ id: string; active: boolean; email: string } | null> {
    if (emails.length === 0) return null;
    const rows = await tx.query<{ principal_id: string; active: boolean }>(
      `SELECT principal_id, active FROM principals
        WHERE principal_type = 'user' AND lower(principal_id) = ANY($1::text[])`,
      [emails],
    );
    for (const email of emails) {
      if (this.#isRoot(email)) {
        return { id: email, active: true, email };
      }
      const row = rows.rows.find((candidate) => candidate.principal_id.toLowerCase() === email);
      if (row !== undefined) return { id: row.principal_id, active: row.active, email };
    }
    return null;
  }

  async #issue(
    tx: DatabaseClient,
    kind: CredentialKind,
    principal: PrincipalRef,
    options: { identityId: string | null; label: string | null; createdBy: string; expiresAt: Date },
  ): Promise<IssuedCredential> {
    const token = generateToken(kind);
    const inserted = await tx.query<{ id: string; expires_at: Date | string }>(
      `INSERT INTO credentials (
         kind, token_hash, token_hint, principal_type, principal_id, identity_id,
         label, created_by, expires_at
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, expires_at`,
      [
        kind,
        hashToken(token),
        tokenHint(token),
        principal.type,
        principal.id,
        options.identityId,
        options.label?.slice(0, 120) ?? null,
        options.createdBy,
        options.expiresAt,
      ],
    );
    const row = inserted.rows[0];
    return { id: row.id, token, expiresAt: toIsoTimestamp(row.expires_at) };
  }

  // --- verifying ------------------------------------------------------------

  /**
   * Resolve a bearer token to its caller, or throw.
   *
   * A token dies with its person: removing someone deactivates their
   * principal, and the join on `principals.active` stops every credential
   * they hold on the next request, before any revocation sweep.
   */
  async verify(token: string, request: { sourceIp: string | null } = { sourceIp: null }): Promise<CredentialPrincipal> {
    if (!isCoffreToken(token)) throw new Error('not a coffre credential');

    const result = await this.#deps.pool.query<{
      id: string;
      principal_type: 'user' | 'service';
      principal_id: string;
      last_used_at: Date | string | null;
      subject: string | null;
    }>(
      `SELECT c.id, c.principal_type, c.principal_id, c.last_used_at, i.subject
         FROM credentials c
         JOIN principals p
           ON p.principal_type = c.principal_type AND p.principal_id = c.principal_id
         LEFT JOIN identities i ON i.id = c.identity_id
        WHERE c.token_hash = $1
          AND c.revoked_at IS NULL
          AND c.expires_at > now()
          AND p.active
          AND (c.identity_id IS NULL OR i.revoked_at IS NULL)`,
      [hashToken(token)],
    );
    const row = result.rows[0];
    if (row === undefined) throw new Error('unknown, expired or revoked credential');

    const lastUsed = row.last_used_at === null ? 0 : new Date(row.last_used_at).getTime();
    if (Date.now() - lastUsed > TOUCH_INTERVAL_MS) {
      // Coarse on purpose: one write per credential per five minutes, not
      // one per request. Losing it must never cost the request.
      await this.#deps.pool
        .query(
          `UPDATE credentials SET last_used_at = now(), last_used_ip = $2 WHERE id = $1`,
          [row.id, request.sourceIp],
        )
        .catch(() => {});
    }

    return row.principal_type === 'service'
      ? { type: 'service', id: row.principal_id, commonName: row.principal_id, credentialId: row.id }
      : {
          type: 'user',
          id: row.principal_id,
          email: row.principal_id,
          subject: row.subject ?? row.principal_id,
          credentialId: row.id,
        };
  }

  // --- signing out and revoking ---------------------------------------------

  /** Revoke the credential this token is. Unknown tokens are a quiet no-op. */
  async signOut(token: string, meta: Omit<ClientMeta, 'label'>): Promise<void> {
    if (!isCoffreToken(token)) return;
    await this.#run(async (tx) => {
      const revoked = await tx.query<{
        id: string;
        kind: CredentialKind;
        principal_type: 'user' | 'service';
        principal_id: string;
      }>(
        `UPDATE credentials
            SET revoked_at = now(), revoked_by = principal_id
          WHERE token_hash = $1 AND revoked_at IS NULL
          RETURNING id, kind, principal_type, principal_id`,
        [hashToken(token)],
      );
      const row = revoked.rows[0];
      if (row === undefined) return { result: undefined, entries: [] };
      return {
        result: undefined,
        entries: [
          {
            actorType: row.principal_type,
            actorId: row.principal_id,
            action: 'auth.signout',
            decision: 'allow',
            requestId: meta.requestId,
            sourceIp: meta.sourceIp,
            metadata: { credentialId: row.id, kind: row.kind },
          },
        ],
      };
    });
  }

  /**
   * Revoke one credential: your own, or anyone's if you own the instance.
   */
  async revokeCredential(ctx: RequestContext, credentialId: string): Promise<{ revoked: true }> {
    return this.#run(async (tx) => {
      const base = {
        actorType: ctx.principal.type,
        actorId: ctx.principal.id,
        action: 'credential.revoke',
        requestId: ctx.requestId,
        sourceIp: ctx.sourceIp,
      };
      const found = await tx.query<{
        kind: CredentialKind;
        principal_type: 'user' | 'service';
        principal_id: string;
      }>(
        `SELECT kind, principal_type, principal_id FROM credentials
          WHERE id = $1 AND revoked_at IS NULL
          FOR UPDATE`,
        [credentialId],
      );
      const row = found.rows[0];
      if (row === undefined) {
        throw new AuditedFailure(new NotFound('unknown credential'), {
          ...base,
          decision: 'deny',
          metadata: { credentialId, reason: 'unknown_credential' },
        });
      }
      const own = row.principal_type === ctx.principal.type && row.principal_id === ctx.principal.id;
      if (!own && !(await isInstanceOwner(tx, ctx.principal, this.#deps.rootAdmins))) {
        throw new AuditedFailure(new AccessDenied('only owners may revoke other people\'s credentials'), {
          ...base,
          decision: 'deny',
          metadata: { credentialId, reason: 'requires_instance_owner' },
        });
      }

      await tx.query(
        `UPDATE credentials SET revoked_at = now(), revoked_by = $2 WHERE id = $1`,
        [credentialId, ctx.principal.id],
      );
      return {
        result: { revoked: true as const },
        entries: [
          {
            ...base,
            decision: 'allow',
            metadata: {
              credentialId,
              kind: row.kind,
              principalType: row.principal_type,
              principalId: row.principal_id,
            },
          },
        ],
      };
    });
  }

  /** Unbind one of your sign-in accounts, ending the sessions it opened. */
  async unlinkIdentity(ctx: RequestContext, identityId: string): Promise<{ unlinked: true }> {
    return this.#run(async (tx) => {
      const base = {
        actorType: ctx.principal.type,
        actorId: ctx.principal.id,
        action: 'identity.unbind',
        requestId: ctx.requestId,
        sourceIp: ctx.sourceIp,
      };
      const revoked = await tx.query<{ provider: string; subject: string }>(
        `UPDATE identities
            SET revoked_at = now(), revoked_by = $3
          WHERE id = $1
            AND principal_type = $2 AND principal_id = $3
            AND revoked_at IS NULL
          RETURNING provider, subject`,
        [identityId, ctx.principal.type, ctx.principal.id],
      );
      const row = revoked.rows[0];
      if (row === undefined) {
        throw new AuditedFailure(new NotFound('unknown sign-in account'), {
          ...base,
          decision: 'deny',
          metadata: { identityId, reason: 'unknown_identity' },
        });
      }
      const ended = await tx.query(
        `UPDATE credentials SET revoked_at = now(), revoked_by = $2
          WHERE identity_id = $1 AND revoked_at IS NULL`,
        [identityId, ctx.principal.id],
      );
      return {
        result: { unlinked: true as const },
        entries: [
          {
            ...base,
            decision: 'allow',
            metadata: { identityId, ...row, sessionsEnded: ended.rowCount ?? 0 },
          },
        ],
      };
    });
  }

  // --- listing --------------------------------------------------------------

  async listSessions(ctx: RequestContext, currentCredentialId: string | null): Promise<SessionRow[]> {
    const result = await this.#deps.pool.query<{
      id: string;
      kind: 'browser' | 'cli';
      label: string | null;
      token_hint: string;
      provider: string | null;
      created_at: Date | string;
      expires_at: Date | string;
      last_used_at: Date | string | null;
      last_used_ip: string | null;
    }>(
      `SELECT c.id, c.kind, c.label, c.token_hint, i.provider,
              c.created_at, c.expires_at, c.last_used_at, c.last_used_ip
         FROM credentials c
         LEFT JOIN identities i ON i.id = c.identity_id
        WHERE c.principal_type = $1 AND c.principal_id = $2
          AND c.kind IN ('browser', 'cli')
          AND c.revoked_at IS NULL AND c.expires_at > now()
        ORDER BY COALESCE(c.last_used_at, c.created_at) DESC`,
      [ctx.principal.type, ctx.principal.id],
    );
    return result.rows.map((row) => ({
      id: row.id,
      kind: row.kind,
      label: row.label,
      hint: row.token_hint,
      provider: row.provider,
      createdAt: toIsoTimestamp(row.created_at),
      expiresAt: toIsoTimestamp(row.expires_at),
      lastUsedAt: toNullableIsoTimestamp(row.last_used_at),
      lastUsedIp: row.last_used_ip,
      current: row.id === currentCredentialId,
    }));
  }

  async listIdentities(ctx: RequestContext): Promise<IdentityRow[]> {
    const result = await this.#deps.pool.query<{
      id: string;
      provider: string;
      email: string | null;
      created_at: Date | string;
      last_sign_in_at: Date | string | null;
    }>(
      `SELECT id, provider, email, created_at, last_sign_in_at
         FROM identities
        WHERE principal_type = $1 AND principal_id = $2 AND revoked_at IS NULL
        ORDER BY created_at`,
      [ctx.principal.type, ctx.principal.id],
    );
    return result.rows.map((row) => ({
      id: row.id,
      provider: row.provider,
      email: row.email,
      createdAt: toIsoTimestamp(row.created_at),
      lastSignInAt: toNullableIsoTimestamp(row.last_sign_in_at),
    }));
  }

  // --- service tokens -------------------------------------------------------

  async listServiceTokens(ctx: RequestContext, serviceId: string): Promise<ServiceTokenRow[]> {
    const client = await this.#deps.pool.connect();
    try {
      const self = ctx.principal.type === 'service' && ctx.principal.id === serviceId;
      if (!self && !(await isInstanceOwner(client, ctx.principal, this.#deps.rootAdmins))) {
        throw new AccessDenied('only owners may see service tokens');
      }
      const result = await client.query<{
        id: string;
        label: string | null;
        token_hint: string;
        created_at: Date | string;
        created_by: string;
        expires_at: Date | string;
        last_used_at: Date | string | null;
        last_used_ip: string | null;
      }>(
        `SELECT id, label, token_hint, created_at, created_by, expires_at, last_used_at, last_used_ip
           FROM credentials
          WHERE principal_type = 'service' AND principal_id = $1
            AND revoked_at IS NULL AND expires_at > now()
          ORDER BY created_at DESC`,
        [serviceId],
      );
      return result.rows.map((row) => ({
        id: row.id,
        label: row.label,
        hint: row.token_hint,
        createdAt: toIsoTimestamp(row.created_at),
        createdBy: row.created_by,
        expiresAt: toIsoTimestamp(row.expires_at),
        lastUsedAt: toNullableIsoTimestamp(row.last_used_at),
        lastUsedIp: row.last_used_ip,
      }));
    } finally {
      await client.release();
    }
  }

  /**
   * Mint a token for a service principal. The value is returned once and
   * exists nowhere afterwards; losing it means minting another.
   */
  async issueServiceToken(
    ctx: RequestContext,
    serviceId: string,
    input: { label: string | null; expiresInDays: number },
  ): Promise<IssuedCredential> {
    return this.#run(async (tx) => {
      const base = {
        actorType: ctx.principal.type,
        actorId: ctx.principal.id,
        action: 'credential.issue',
        requestId: ctx.requestId,
        sourceIp: ctx.sourceIp,
      };
      const details = { kind: 'service', principalType: 'service', principalId: serviceId, label: input.label };
      await advisoryLock(tx, `coffre:principal:service:${serviceId}`);

      if (!(await isInstanceOwner(tx, ctx.principal, this.#deps.rootAdmins))) {
        throw new AuditedFailure(new AccessDenied('only owners may issue service tokens'), {
          ...base,
          decision: 'deny',
          metadata: { ...details, reason: 'requires_instance_owner' },
        });
      }
      if (
        !Number.isInteger(input.expiresInDays) ||
        input.expiresInDays < 1 ||
        input.expiresInDays > MAX_SERVICE_TOKEN_DAYS
      ) {
        throw Object.assign(new Error(`tokens last between 1 and ${MAX_SERVICE_TOKEN_DAYS} days`), {
          statusCode: 400,
        });
      }
      const service = await tx.query(
        `SELECT 1 FROM principals WHERE principal_type = 'service' AND principal_id = $1 AND active`,
        [serviceId],
      );
      if (service.rowCount === 0) {
        throw new AuditedFailure(new NotFound('unknown service'), {
          ...base,
          decision: 'deny',
          metadata: { ...details, reason: 'unknown_principal' },
        });
      }

      const credential = await this.#issue(tx, 'service', { type: 'service', id: serviceId }, {
        identityId: null,
        label: input.label,
        createdBy: ctx.principal.id,
        expiresAt: new Date(Date.now() + input.expiresInDays * 86_400_000),
      });
      return {
        result: credential,
        entries: [
          {
            ...base,
            decision: 'allow',
            metadata: { ...details, credentialId: credential.id, expiresAt: credential.expiresAt },
          },
        ],
      };
    });
  }

  // --- device flow (RFC 8628), for `coffre login` ---------------------------

  /**
   * Open a device authorization. Unauthenticated by nature, so it writes no
   * audit row, and the number of open requests is capped per address and
   * overall; a flood can only make `coffre login` wait, never grow a table
   * without bound.
   */
  async startDevice(input: { clientLabel: string | null; sourceIp: string | null }): Promise<DeviceStart> {
    const client = await this.#deps.pool.connect();
    try {
      await client.query('BEGIN');
      await advisoryLock(client, 'coffre:device-authorizations');
      const open = await client.query<{ total: number; from_ip: number }>(
        `SELECT count(*)::int AS total,
                count(*) FILTER (WHERE client_ip IS NOT DISTINCT FROM $1)::int AS from_ip
           FROM device_authorizations
          WHERE decided_at IS NULL AND expires_at > now()`,
        [input.sourceIp],
      );
      const { total, from_ip } = open.rows[0];
      if (from_ip >= DEVICE_PENDING_PER_IP || total >= DEVICE_PENDING_TOTAL) {
        throw tooMany('too many sign-in requests are waiting; try again in a few minutes');
      }

      const deviceCode = randomBytes(32).toString('base64url');
      let code = userCode();
      // A collision among live codes is astronomically unlikely, but the
      // unique index would turn it into a 500; draw again instead.
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const taken = await client.query('SELECT 1 FROM device_authorizations WHERE user_code = $1', [code]);
        if (taken.rowCount === 0) break;
        code = userCode();
      }
      await client.query(
        `INSERT INTO device_authorizations (device_code_hash, user_code, client_label, client_ip, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`,
        [hashToken(deviceCode), code, input.clientLabel?.slice(0, 120) ?? null, input.sourceIp, DEVICE_TTL_SECONDS],
      );
      await client.query('COMMIT');

      const verificationUri = `${this.#deps.signin.publicUrl}/auth/device`;
      return {
        deviceCode,
        userCode: code,
        verificationUri,
        verificationUriComplete: `${verificationUri}?code=${code}`,
        expiresIn: DEVICE_TTL_SECONDS,
        interval: DEVICE_POLL_SECONDS,
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      await client.release();
    }
  }

  /** What the person approving a code is about to let in. */
  async describeDevice(userCodeInput: string): Promise<DeviceRequest | null> {
    const code = normalizeUserCode(userCodeInput);
    if (code === null) return null;
    const result = await this.#deps.pool.query<{
      user_code: string;
      client_label: string | null;
      client_ip: string | null;
      created_at: Date | string;
      expires_at: Date | string;
    }>(
      `SELECT user_code, client_label, client_ip, created_at, expires_at
         FROM device_authorizations
        WHERE user_code = $1 AND decided_at IS NULL AND expires_at > now()`,
      [code],
    );
    const row = result.rows[0];
    if (row === undefined) return null;
    return {
      userCode: row.user_code,
      clientLabel: row.client_label,
      clientIp: row.client_ip,
      createdAt: toIsoTimestamp(row.created_at),
      expiresAt: toIsoTimestamp(row.expires_at),
    };
  }

  async decideDevice(
    ctx: RequestContext,
    userCodeInput: string,
    approve: boolean,
  ): Promise<{ decided: true }> {
    return this.#run(async (tx) => {
      const base = {
        actorType: ctx.principal.type,
        actorId: ctx.principal.id,
        action: approve ? 'device.approve' : 'device.deny',
        requestId: ctx.requestId,
        sourceIp: ctx.sourceIp,
      };
      const code = normalizeUserCode(userCodeInput);
      if (ctx.principal.type !== 'user') {
        throw new AccessDenied('only people approve sign-ins');
      }
      const decided = code === null
        ? null
        : await tx.query<{ id: string; client_label: string | null; client_ip: string | null }>(
            `UPDATE device_authorizations
                SET decided_at = now(),
                    decision = $2,
                    principal_type = CASE WHEN $2 = 'approved' THEN 'user' END,
                    principal_id = CASE WHEN $2 = 'approved' THEN $3 END
              WHERE user_code = $1 AND decided_at IS NULL AND expires_at > now()
              RETURNING id, client_label, client_ip`,
            [code, approve ? 'approved' : 'denied', ctx.principal.id],
          );
      const row = decided?.rows[0];
      if (row === undefined) {
        throw new AuditedFailure(new NotFound('that code is unknown or has expired'), {
          ...base,
          decision: 'deny',
          metadata: { userCode: code ?? userCodeInput.slice(0, 16), reason: 'unknown_code' },
        });
      }
      return {
        result: { decided: true as const },
        entries: [
          {
            ...base,
            decision: 'allow',
            metadata: {
              deviceAuthorizationId: row.id,
              clientLabel: row.client_label,
              clientIp: row.client_ip,
            },
          },
        ],
      };
    });
  }

  /** The CLI's poll. An approved code is exchanged for a CLI session exactly once. */
  async pollDevice(deviceCode: string, meta: Omit<ClientMeta, 'label'>): Promise<DevicePoll> {
    return this.#run(async (tx) => {
      const found = await tx.query<{
        id: string;
        decision: 'approved' | 'denied' | null;
        principal_id: string | null;
        client_label: string | null;
        client_ip: string | null;
        expired: boolean;
        consumed: boolean;
      }>(
        `SELECT id, decision, principal_id, client_label, client_ip,
                expires_at <= now() AS expired,
                consumed_at IS NOT NULL AS consumed
           FROM device_authorizations
          WHERE device_code_hash = $1
          FOR UPDATE`,
        [hashToken(deviceCode)],
      );
      const row = found.rows[0];
      const none = (result: DevicePoll) => ({ result, entries: [] });
      if (row === undefined || row.consumed) return none({ status: 'expired' });
      if (row.decision === 'denied') return none({ status: 'denied' });
      if (row.decision === null) return none(row.expired ? { status: 'expired' } : { status: 'pending' });

      const principalId = row.principal_id as string;
      await tx.query(`UPDATE device_authorizations SET consumed_at = now() WHERE id = $1`, [row.id]);
      const active = await tx.query(
        `SELECT 1 FROM principals WHERE principal_type = 'user' AND principal_id = $1 AND active`,
        [principalId],
      );
      if (active.rowCount === 0) return none({ status: 'denied' });

      const principal: PrincipalRef = { type: 'user', id: principalId };
      const credential = await this.#issue(tx, 'cli', principal, {
        identityId: null,
        label: row.client_label,
        createdBy: principalId,
        expiresAt: new Date(Date.now() + this.#deps.signin.cliSessionDays * 86_400_000),
      });
      return {
        result: { status: 'approved' as const, principal, credential },
        entries: [
          {
            actorType: 'user',
            actorId: principalId,
            action: 'credential.issue',
            decision: 'allow',
            requestId: meta.requestId,
            sourceIp: meta.sourceIp,
            metadata: {
              kind: 'cli',
              credentialId: credential.id,
              deviceAuthorizationId: row.id,
              clientLabel: row.client_label,
              clientIp: row.client_ip,
            },
          },
        ],
      };
    });
  }
}
