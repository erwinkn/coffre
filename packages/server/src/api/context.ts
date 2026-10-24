import { makesProjects, runsInstance, type Permission } from '@coffre/core/access';
import type { McpScope } from '@coffre/core/mcp';
import type { Refusal as VaultRefusal, Through, Vault } from '@coffre/core/vault';
import type { Database, Queryable, Transaction } from '@coffre/db';
import { lockLogHead } from '@coffre/db/log';

import { appendAudit, type AuditEntry } from '../db/audit.ts';
import type { WatchContext, Watcher } from '../watch.ts';
import { liveEnvironmentSlugs, wayInStands } from '../db/queries.ts';
import { can, newestPolicySeq, type Caller, type Place } from './caller.ts';
import { ApiError, forbidden, vaultRefused } from './errors.ts';
import type { Asking } from './keys.ts';
import { formatMember } from './paths.ts';
import type { PersonalToken, SigninService } from './signin.ts';
import type { WorkloadService } from './workloads.ts';
import type { McpService } from '../mcp/service.ts';

/**
 * A request made through MCP: the connection it came in on, its client, and
 * the scopes its token holds; for a change its person approved on coffre's
 * page, the approval.
 */
export type McpVia = { connectionId: string; clientId: string; clientName: string; scopes: readonly McpScope[]; approvalId?: string };

/** What every handler works with: the stores, and who is asking. */
export type ApiContext = {
  db: Database;
  chainKey: Buffer;
  /** The app keys `chainKey` replaced, which only verify (`previousAuditChainKeys`). */
  previousChainKeys: readonly Buffer[];
  /** Keys, grants, who is a member and their role: every decision the app cannot make alone. */
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
  /** The Cloudflare service binding a call came through, which stands in for a credential (`AuthenticatedIdentity.bindingId`). */
  bindingId?: string | null;
  /**
   * That credential, when a trust binding issued it for a CI run, or it is
   * a personal token: every entry the request writes names it, the vault's
   * through its calls' correlation, so that each leads back to the run
   * (`token.exchange`) or the token (`token.create`).
   */
  provenance: string | null;
  /**
   * The MCP connection the request came through, for a tool's call: its
   * entries name it, and the routes it may reach are its scopes' (`ROUTE_SCOPES`).
   * Its `provenance` is the connection, which the vault's entries carry.
   */
  via: McpVia | null;
  /**
   * The personal token the request came in on: it acts as its person,
   * within its scope, and only on the routes a token may reach
   * (`PERSONAL_TOKEN_ROUTES`). Its `provenance` is the token, which every
   * entry the request writes names, for "ada via token 'cursor-agent'".
   */
  personalToken: PersonalToken | null;
  /** When the credential the request came in on ends, ISO 8601: `GET /api/me` says it. Null without one, behind Cloudflare Access or through MCP. */
  credentialExpiresAt: string | null;
  /** Days a value may go unchanged before it is flagged for rotation (`rotateAfterDays`), or null for no flag. */
  rotateAfterDays: number | null;
  /**
   * The deployment's audit watch, if it added one (plugins/audit-watch.ts):
   * its hooks, and a context for them, in the name of the request's caller
   * when `asCaller`.
   */
  watch?: { hooks: Watcher; context: (asCaller?: boolean) => WatchContext } | null;
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
  const via =
    ctx.via == null
      ? {}
      : {
          via: {
            connectionId: ctx.via.connectionId,
            clientId: ctx.via.clientId,
            clientName: ctx.via.clientName,
            ...(ctx.via.approvalId === undefined ? {} : { approvalId: ctx.via.approvalId }),
          },
        };
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
 * Given a request's `caller`, it commits only while the policy is the one
 * the caller was loaded with (`policyStill`): whatever the request decided
 * from its roles and protected environments, it decided as they are when it
 * commits. Only what follows through on the vault's own decision, which
 * the vault made under its head, is written without one (`{ db, chainKey }`).
 *
 * A thrown Refusal rolls the work back and then commits its own entry: who
 * was turned away is half of what an audit log is for.
 */
export async function audited<T>(
  ctx: Pick<ApiContext, 'db' | 'chainKey'> & { caller?: Pick<Caller, 'policySeq' | 'policy'> },
  work: (tx: Transaction, log: AuditEntry[]) => Promise<T>,
): Promise<T> {
  try {
    return await ctx.db.transaction(async (tx) => {
      const log: AuditEntry[] = [];
      // Take the head before any application rows.
      await lockLogHead(tx);
      if (ctx.caller !== undefined) await policyStill({ caller: ctx.caller }, tx);
      const result = await work(tx, log);
      if (log.length > 0) await appendAudit(tx, ctx.chainKey, log);
      return result;
    });
  } catch (error) {
    if (!(error instanceof Refusal)) throw error;
    return refuse(ctx, error);
  }
}

/**
 * Refuse, 409 `policy_changed`, if the instance's roles or protected
 * environments changed since the caller was loaded. In an audited
 * transaction, it fences every decision made from `caller.policy` that the
 * transaction commits (`audited` runs it for a request), a fork left
 * unprotected or a credential's scope: a change appends its
 * `policy.change` under the same head the transaction holds, so one that
 * passes here was not overtaken by any. After a read, with no lock, it
 * fences what the read hands back (`fenced`).
 *
 *   caller loaded, prod not protected (newest change 41)
 *   a Maintainer protects prod                           change 57
 *   the fork's transaction, under the head: 57, not 41   409; asked again, the fork is protected
 *
 * The policy names its protected environments by id, and reads each one's
 * slug, which a scoped instance role's filters match, from its row
 * (`livePolicy`). So the rows are read again here, by id: a protected
 * environment renamed, deleted, or written since (a fork's, protected
 * before its row) is a policy changed, with no entry of its own to say so,
 * and nothing that renames or deletes one has to remember to write one
 * (docs/design/roles.md, "What changes the policy").
 *
 *   Ada, a Developer of market and Owner of every prod, gives a token on market
 *   meanwhile prod is renamed staging, which her Owner role does not reach
 *   her transaction, under the head: staging, not prod   409; asked again, she is refused
 */
export async function policyStill(ctx: { caller: Pick<Caller, 'policySeq' | 'policy'> }, db: Queryable): Promise<void> {
  const { policy, policySeq } = ctx.caller;
  const read = Object.values(policy.protectedIn).flat();
  const slugs = await liveEnvironmentSlugs(db, read.map((place) => place.environmentId));
  const moved = read.some(({ environmentId, slug }) => (slugs.get(environmentId) ?? null) !== slug);
  if (!moved && (await newestPolicySeq(db)) === policySeq) return;
  throw new ApiError('conflict', "the instance's roles or protected environments changed while this ran: try again", POLICY_CHANGED);
}

/** The reason a request overtaken by a change to the policy answers with: asked again, it is weighed as the policy is now. */
export const POLICY_CHANGED = 'policy_changed';

/**
 * Collect read and vault events without a transaction; commit before
 * returning anything, through the fence (`audited`). A read that hands
 * back a value the app opened itself says so (`fence`), and goes through
 * it even with nothing to log (`fenced`). Either way, the way the request
 * came in must still stand (`credentialStill`).
 */
export async function recorded<T>(
  ctx: Pick<ApiContext, 'db' | 'chainKey' | 'caller' | 'requestId' | 'sourceIp' | 'credentialId' | 'bindingId' | 'via'>,
  work: (log: AuditEntry[], fence: () => void, at: (where: EntryFields) => void) => Promise<T>,
): Promise<T> {
  return withRefusals(ctx, async () => {
    const log: AuditEntry[] = [];
    let fencing = false;
    // Where the read was, and its operation, for the refusal of a credential that ended meanwhile.
    let where: EntryFields = {};
    const result = await work(log, () => (fencing = true), (fields) => (where = fields));
    if (log.length > 0) {
      await audited(ctx, async (tx, entries) => {
        await credentialStill(ctx, tx, 'secret.read', where);
        entries.push(...log);
      });
    } else {
      if (fencing) await fenced(ctx);
      await credentialStill(ctx, ctx.db, 'secret.read', where);
    }
    return result;
  });
}

/**
 * Refuse, 401, if the way the request came in has ended since it was
 * checked: its credential revoked, the MCP connection or the Cloudflare
 * binding it came through revoked or unbound, or its member removed, even if admitted again since, at a new
 * generation. The vault releases values on the member's standing and
 * grants, under their row and its head, and is told the credential only to
 * name it in its entries; the app checked the credential before asking it,
 * unlocked. So a read checks it again after the vault has released: under
 * the head when it commits entries of its own, otherwise with no lock. A
 * revocation committed before this read is seen; one after came after the
 * release (formal/Credentials.tla, `CredentialFenceUnderHead` and
 * `CredentialFenceUnlocked`). Issuing a service account a credential checks
 * it too, under the head (`issuerNow`). A refusal is logged, `action`
 * refused as `credential_ended`, `where` the read was, after the vault's
 * release if there was one: the same operation.
 *
 *   Ada's token checked, her export asks the vault
 *   Ada revokes the token                            token.revoke
 *   the vault releases the values                    secret.read
 *   checked again: revoked                           401, not the values
 */
export async function credentialStill(
  ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp' | 'credentialId' | 'bindingId' | 'via'>,
  db: Queryable,
  action = 'secret.read',
  where: EntryFields = {},
): Promise<void> {
  const stands = await wayInStands(db, {
    principal: formatMember(ctx.caller.principal),
    generation: ctx.caller.generation,
    credentialId: ctx.credentialId,
    bindingId: ctx.bindingId ?? null,
    connectionId: ctx.via?.connectionId ?? null,
  });
  // Logged, so that a release the vault logged before this read shows withheld, not handed to an ended credential.
  if (!stands) {
    throw new Refusal(
      new ApiError('unauthenticated', 'that credential is unknown, expired or revoked'),
      denied(ctx, action, 'credential_ended', { ...where, metadata: { credentialId: ctx.credentialId } }),
    );
  }
}

/**
 * Hand back a value the app opened itself, a plain one, only as the policy
 * is now: once a read after the value's finds the caller's policy still
 * the newest (`policyStill`). It takes no lock: a change committed before
 * this read is seen, and one after it came after the value was read, so
 * the read stands before it. No vault call decided it, as one decides each
 * value it releases, under its own head.
 *
 *   caller loaded, Ada reads prod                    a plain value of prod read
 *   prod protected; she only uses it now             the read answers 409, not the value
 */
export async function fenced(ctx: Pick<ApiContext, 'db' | 'caller'>): Promise<void> {
  await policyStill(ctx, ctx.db);
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
  // One who uses values and reads none, a Contributor, is told how they use them.
  const uses = permission === 'secret.read' && can(ctx.caller, 'secret.use', place);
  throw new Refusal(
    uses ? forbidden('you use these values without reading them (secret.use): `coffre run` gives your app placeholders, which the credential proxy fills in') : forbidden(),
    denied(ctx, action, missing(permission), {
      projectId: place.projectId,
      environmentId: place.environmentId ?? null,
      ...fields,
    }),
  );
}

/**
 * What the vault's entries name a request by: the credential or connection
 * it came in on, an ID. A call through a Cloudflare binding came in on
 * neither: its app entries name the binding, `binding:<id>`, and lead to
 * the vault's through the request's ID.
 */
export function vaultCredential(ctx: { provenance?: string | null; bindingId?: string | null }): string | null {
  return ctx.bindingId == null ? (ctx.provenance ?? null) : null;
}

/** The caller, as the vault knows them, for this request. */
export function asking(ctx: Pick<ApiContext, 'caller' | 'requestId'> & { provenance?: string | null; bindingId?: string | null }, operationId: string | null = null): Asking {
  return {
    principal: formatMember(ctx.caller.principal),
    requestId: ctx.requestId,
    operationId,
    credentialId: vaultCredential(ctx),
    ...through(ctx.caller),
  };
}

/** The credential the caller came in on, as the vault decides on it: its scope and its kind. */
export function through(caller: Pick<Caller, 'credentialScope' | 'kind'>): Through {
  return { credentialScope: caller.credentialScope, caller: caller.kind };
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

/**
 * Refuse, and log the refusal, unless the caller runs the instance: an
 * Admin or Owner whose scope narrows nothing (`runsInstance`).
 */
export function requireInstance(ctx: Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>, action: string, fields: EntryFields = {}, what = 'do that'): void {
  if (runsInstance(ctx.caller)) return;
  throw new Refusal(
    forbidden(`only admins and owners of the whole instance may ${what}`),
    denied(ctx, action, 'requires_instance_admin', fields),
  );
}

/** Refuse, and log the refusal, unless the caller may make a project their scope takes in (`makesProjects`). */
export function requireProjectMaker(ctx: ApiContext, action: string, fields: EntryFields = {}): void {
  if (makesProjects(ctx.caller)) return;
  throw new Refusal(
    forbidden('only admins and owners whose scope takes in new projects may make one'),
    denied(ctx, action, 'requires_instance_admin', fields),
  );
}

/** Log a refusal on its own and throw its error, for checks made outside any transaction. */
export async function refuse(ctx: Pick<ApiContext, 'db' | 'chainKey'>, refusal: Refusal): Promise<never> {
  await ctx.db.transaction((tx) => appendAudit(tx, ctx.chainKey, [refusal.entry]));
  throw answered(refusal);
}

/**
 * The error a refusal answers with, carrying the reason its entry logs
 * (`principal_not_registered`, `referenced`, …): what a client branches on,
 * never the message's words.
 */
function answered({ error, entry }: Refusal): ApiError | Error {
  const reason = entry.metadata?.reason;
  if (!(error instanceof ApiError) || error.reason !== undefined || typeof reason !== 'string') return error;
  return new ApiError(error.code, error.message, reason);
}
