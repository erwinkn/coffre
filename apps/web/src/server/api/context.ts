import type { KekRegistry } from '../../../../../packages/core/src/kek/registry.ts';
import type { Permission } from '../../../../../packages/core/src/access.ts';
import { appendAudit, type AuditEntry } from '../../../../../packages/db/src/audit.ts';
import type { Database, Transaction } from '../../../../../packages/db/src/database.ts';
import { can, type Caller, type Place } from './caller.ts';
import { forbidden, type ApiError } from './errors.ts';

/** What every handler works with: the stores, and who is asking. */
export type ApiContext = {
  db: Database;
  chainKey: Buffer;
  keks: KekRegistry;
  rootAdmins: readonly string[];
  /** Background work that must outlive the response, such as syncs. */
  waitUntil: (promise: Promise<unknown>) => void;
  /** Called after a commit that changed an environment's secrets, so its syncs can push. */
  onChange: (environmentId: string) => void;
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
      const result = await work(tx, log);
      if (log.length > 0) await appendAudit(tx, ctx.chainKey, log);
      return result;
    });
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
