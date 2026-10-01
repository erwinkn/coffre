import type { Permission } from '@coffre/core/access';
import type { Refusal as VaultRefusal, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';

import { appendAudit, type AuditEntry } from '../db/audit.ts';
import { auditHead } from '../db/queries.ts';
import { can, type Caller, type Place } from './caller.ts';
import { forbidden, vaultRefused, type ApiError } from './errors.ts';
import type { Asking } from './keys.ts';
import { formatMember } from './paths.ts';
import type { SigninService } from './signin.ts';
import type { SyncRunner } from './syncs.ts';

/** What every handler works with: the stores, and who is asking. */
export type ApiContext = {
  db: Database;
  chainKey: Buffer;
  /** Keys, grants, who is a member, root admins: every decision the app cannot make alone. */
  vault: Vault;
  /** Background work that must outlive the response, such as syncs. */
  waitUntil: (promise: Promise<unknown>) => void;
  /** Runs syncs: after a commit that changed an environment's secrets, and on request. */
  syncs: SyncRunner;
  /** coffre's own sign-in and the tokens it issues; null behind Cloudflare Access. */
  signin: SigninService | null;
  caller: Caller;
  requestId: string;
  sourceIp: string | null;
  /** The coffre credential that authenticated this request, in signin mode. */
  credentialId: string | null;
};

/** The fields of an audit entry that are the same for everything one request does. */
export function actor(
  ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>,
): Pick<AuditEntry, 'actorType' | 'actorId' | 'requestId' | 'sourceIp'> {
  return {
    actorType: ctx.caller.principal.type,
    actorId: ctx.caller.principal.id,
    requestId: ctx.requestId,
    sourceIp: ctx.sourceIp,
  };
}

type EntryFields = Omit<AuditEntry, 'actorType' | 'actorId' | 'requestId' | 'sourceIp' | 'action' | 'decision'>;

export function allowed(
  ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>,
  action: string,
  fields: EntryFields = {},
): AuditEntry {
  return { ...actor(ctx), action, decision: 'allow', ...fields };
}

export function denied(
  ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>,
  action: string,
  reason: string,
  fields: EntryFields = {},
): AuditEntry {
  return {
    ...actor(ctx),
    action,
    decision: 'deny',
    ...fields,
    metadata: { ...fields.metadata, reason },
  };
}

/**
 * A refusal worth logging. `audited` rolls back whatever the attempt did,
 * commits the entry on its own, and throws the error to the caller.
 */
export class Refusal extends Error {
  readonly error: ApiError | Error;
  readonly entry: AuditEntry;

  constructor(error: ApiError | Error, entry: AuditEntry) {
    super(error.message);
    this.name = 'Refusal';
    this.error = error;
    this.entry = entry;
  }
}

/**
 * The one transaction shape for anything the log should know about: do the
 * work and append its entries in the same transaction, so neither commits
 * without the other. Push entries onto `log` as the work goes.
 * Vault calls belong before or after this transaction.
 *
 * A thrown Refusal rolls the work back and then commits its own entry: who
 * was turned away is half of what an audit log is for.
 */
export async function audited<T>(
  ctx: Pick<ApiContext, 'db' | 'chainKey'>,
  work: (tx: Transaction, log: AuditEntry[]) => Promise<T>,
): Promise<T> {
  try {
    return await ctx.db.transaction(async (tx) => {
      const log: AuditEntry[] = [];
      // Take the head before any application rows.
      if (await auditHead(tx, { lock: true }) === null) throw new Error('audit_chain_head is missing');
      const result = await work(tx, log);
      if (log.length > 0) await appendAudit(tx, ctx.chainKey, log);
      return result;
    });
  } catch (error) {
    if (!(error instanceof Refusal)) throw error;
    return refuse(ctx, error);
  }
}

/** Collect read and vault events without a transaction; commit before returning anything. */
export async function recorded<T>(
  ctx: Pick<ApiContext, 'db' | 'chainKey'>,
  work: (log: AuditEntry[]) => Promise<T>,
): Promise<T> {
  return withRefusals(ctx, async () => {
    const log: AuditEntry[] = [];
    const result = await work(log);
    if (log.length > 0) await audited(ctx, async (_tx, entries) => { entries.push(...log); });
    return result;
  });
}

/** Checks made before the write transaction still need their refusal recorded. */
export async function withRefusals<T>(
  ctx: Pick<ApiContext, 'db' | 'chainKey'>,
  work: () => Promise<T>,
): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (!(error instanceof Refusal)) throw error;
    return refuse(ctx, error);
  }
}

/** `missing_secret_read`, the reason logged when `secret.read` was needed. */
export function missing(permission: Permission): string {
  return `missing_${permission.replace('.', '_')}`;
}

/**
 * Refuse, and log the refusal, unless the caller holds `permission` at
 * `place`. `fields` add to the deny entry, which already names the place.
 */
export function need(
  ctx: ApiContext,
  permission: Permission,
  place: Place,
  action: string,
  fields: EntryFields = {},
): void {
  if (can(ctx.caller, permission, place)) return;
  throw new Refusal(
    forbidden(),
    denied(ctx, action, missing(permission), {
      projectId: place.projectId,
      environmentId: place.environmentId ?? null,
      ...fields,
    }),
  );
}

/** The caller, as the vault knows them, for this request. */
export function asking(ctx: Pick<ApiContext, 'caller' | 'requestId'>): Asking {
  return { principal: formatMember(ctx.caller.principal), requestId: ctx.requestId };
}

/**
 * The vault said no. The app logs it too, as `vault_<code>`: the app's log
 * then tells the whole story, and the vault's own log is the one the app
 * cannot rewrite.
 */
export function vaultRefusal(
  ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>,
  refusal: VaultRefusal,
  action: string,
  fields: EntryFields = {},
): Refusal {
  return new Refusal(vaultRefused(refusal), denied(ctx, action, `vault_${refusal.code}`, fields));
}

/** Refuse, and log the refusal, unless the caller is an instance owner or a root admin. */
export function requireOwner(ctx: ApiContext, action: string, fields: EntryFields = {}): void {
  if (ctx.caller.isOwner) return;
  throw new Refusal(
    forbidden('only instance owners may do that'),
    denied(ctx, action, 'requires_instance_owner', fields),
  );
}

/** Log a refusal on its own and throw its error, for checks made outside any transaction. */
export async function refuse(ctx: Pick<ApiContext, 'db' | 'chainKey'>, refusal: Refusal): Promise<never> {
  await ctx.db.transaction((tx) => appendAudit(tx, ctx.chainKey, [refusal.entry]));
  throw refusal.error;
}
