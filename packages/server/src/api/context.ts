import type { Permission } from '@coffre/core/access';
import type { McpScope } from '@coffre/core/mcp';
import type { Refusal as VaultRefusal, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';
import { lockLogHead } from '@coffre/db/log';

import { appendAudit, type AuditEntry } from '../db/audit.ts';
import { can, type Caller, type Place } from './caller.ts';
import { forbidden, vaultRefused, type ApiError } from './errors.ts';
import type { Asking } from './keys.ts';
import { formatMember } from './paths.ts';
import type { SigninService } from './signin.ts';
import type { WorkloadService } from './workloads.ts';
import type { McpService } from '../mcp/service.ts';

/** A request made through MCP: the connection it came in on, its client, and the scopes its token holds. */
export type McpVia = { connectionId: string; clientId: string; clientName: string; scopes: readonly McpScope[] };

/** What every handler works with: the stores, and who is asking. */
export type ApiContext = {
  db: Database;
  chainKey: Buffer;
  /** Keys, grants, who is a member, root admins: every decision the app cannot make alone. */
  vault: Vault;
  /** Background work that must outlive the response, that is explicitly scheduled. */
  waitUntil: (promise: Promise<unknown>) => void;
  /** coffre's own sign-in and the tokens it issues; null behind Cloudflare Access. */
  signin: SigninService | null;
  /** Trust bindings for CI runs, when sign-in turns them on (`signin({ workloads })`); null otherwise. */
  workloads: WorkloadService | null;
  /** MCP clients' consent and connections, when sign-in turns them on (`signin({ mcp })`); null otherwise. */
  mcp: McpService | null;
  caller: Caller;
  requestId: string;
  sourceIp: string | null;
  /** The coffre credential that authenticated this request, in signin mode. */
  credentialId: string | null;
  /**
   * That credential, when a trust binding issued it for a CI run: every
   * entry the request writes names it, the vault's through its calls'
   * correlation, so that each leads back to the run (`token.exchange`).
   */
  provenance: string | null;
  /**
   * The MCP connection the request came through, for a tool's call: its
   * entries name it, and the routes it may reach are its scopes' (`ROUTE_SCOPES`).
   * Its `provenance` is the connection, which the vault's entries carry.
   */
  via: McpVia | null;
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

type Writer = Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'> & { provenance?: string | null; via?: McpVia | null };

/**
 * What an entry's metadata adds for a request that came in on a credential
 * a trust binding issued: `credentialId`, the caller's, written last so that
 * nothing the operation says can stand in for it. A credential the operation
 * acts on is its `targetCredentialId`. Through MCP, the credential is the
 * connection, and `via` names it and its client, for "ada via Claude".
 */
function traced(ctx: Writer, metadata: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (ctx.provenance == null) return metadata;
  const via = ctx.via == null ? {} : { via: { connectionId: ctx.via.connectionId, clientId: ctx.via.clientId, clientName: ctx.via.clientName } };
  return { ...metadata, ...via, credentialId: ctx.provenance };
}

export function allowed(
  ctx: Writer,
  action: string,
  fields: EntryFields = {},
): AuditEntry {
  const metadata = traced(ctx, fields.metadata);
  return { ...actor(ctx), action, decision: 'allow', ...fields, ...(metadata === undefined ? {} : { metadata }) };
}

export function denied(
  ctx: Writer,
  action: string,
  reason: string,
  fields: EntryFields = {},
): AuditEntry {
  return {
    ...actor(ctx),
    action,
    decision: 'deny',
    ...fields,
    metadata: { ...traced(ctx, fields.metadata), reason },
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
      await lockLogHead(tx);
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
export function asking(ctx: Pick<ApiContext, 'caller' | 'requestId'> & { provenance?: string | null }, operationId: string | null = null): Asking {
  return { principal: formatMember(ctx.caller.principal), requestId: ctx.requestId, operationId, credentialId: ctx.provenance ?? null };
}

/**
 * The vault said no to part of something larger the app was doing, such as
 * a requested grant: the app logs what the person tried, refused
 * as `vault_<code>`, beside the vault's own entry for the part it refused.
 * Where the vault's refusal is the whole of the action, a read, a write, an
 * access change, its entry is the record: throw `vaultRefused` instead.
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
