import { randomUUID } from 'node:crypto';

import { BindingInvalid, canonicalClaims, checkBinding, MAX_BINDINGS, type BindingClaims, type WorkloadProfile, type WorkloadsConfig } from '@coffre/core/identity';
import type { Access, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';
import { knownMigrations } from '@coffre/db/schema-version';
import { serviceBindings } from '@coffre/db/schema';

import { appliedMigrations, findBinding, insertBinding, liveBindings, memberStanding, updateAuth, type BindingRow } from '../db/queries.ts';
import { discoverKeys, DiscoveryFailed } from '../workloads/discovery.ts';
import type { WorkloadTransport } from '../workloads/transport.ts';
import type { Asker } from './signin.ts';
import { allowed, audited, denied, Refusal, withRefusals } from './context.ts';
import { ApiError, badRequest, conflict, forbidden, notFound } from './errors.ts';

export type WorkloadServiceDeps = {
  db: Database;
  chainKey: Buffer;
  vault: Vault;
  config: WorkloadsConfig;
  transport: WorkloadTransport;
};

/** A binding as an owner sees it. */
export type BindingView = {
  id: string;
  profile: WorkloadProfile;
  issuer: string;
  jwksUri: string;
  claims: BindingClaims;
  label: string | null;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
};

/** What saving a binding would do: the binding as checked, the keys its issuer names, and the bindings it replaces. */
export type BindingPlan = {
  profile: WorkloadProfile;
  issuer: string;
  jwksUri: string;
  claims: BindingClaims;
  /** `asked`: named in `replaces`. `keys_moved`: the service's bindings on the issuer, under its old keys' URL. */
  replaces: { id: string; why: 'asked' | 'keys_moved' }[];
};

export type BindingInput = {
  profile: string;
  issuer: string | null;
  claims: Record<string, string>;
  label: string | null;
  /** Bindings this one takes the place of, as a change to them: they are removed in the same step. */
  replaces: string[];
};

/** The migration that adds bindings: until it runs, this release works without them. */
const BINDINGS_MIGRATION = '0002_service_bindings';

/**
 * Trust bindings: which CI runs may sign in as a service by the ID token
 * their platform signs (docs/design/oidc.md). Owners make and remove them;
 * each is checked against its profile, its issuer asked where its keys are,
 * and nothing about it changes afterwards but its label and last use. A
 * change is a new binding, and the old one's `token.unbind` its tombstone.
 *
 * Making one takes the log's head first, as every audited change does, so
 * two at once cannot both find room under `MAX_BINDINGS`.
 */
export class WorkloadService {
  readonly #deps: WorkloadServiceDeps;

  constructor(deps: WorkloadServiceDeps) {
    this.#deps = deps;
  }

  async listBindings(ctx: Asker, serviceId: string): Promise<BindingView[]> {
    const { principal } = ctx.caller;
    const self = principal.type === 'service' && principal.id === serviceId;
    if (!self && !ctx.caller.isOwner) throw forbidden('only owners may see trust bindings');
    await this.#migrated();
    const member = `token:${serviceId}`;
    const standing = await memberStanding(this.#deps.db, member);
    if (standing === null) throw notFound('unknown service');
    return (await liveBindings(this.#deps.db, this.#deps.chainKey, member, standing.generation)).map(view);
  }

  /** Check a binding and ask its issuer where its keys are; with `dryRun`, write nothing and log nothing. */
  async bind(ctx: Asker, serviceId: string, input: BindingInput, options: { dryRun: boolean }): Promise<BindingPlan | { binding: BindingView; replaced: string[] }> {
    const member = `token:${serviceId}`;
    const details = { principalType: 'service', principalId: serviceId, profile: input.profile, issuer: input.issuer };
    let policy: ReturnType<typeof checkBinding>;
    try {
      policy = checkBinding(input, { allowLoopback: this.#deps.config.allowLoopback });
    } catch (error) {
      if (error instanceof BindingInvalid) throw badRequest(error.message);
      throw error;
    }
    return withRefusals(this.#deps, async () => {
      if (!ctx.caller.isOwner) {
        throw new Refusal(forbidden('only owners may trust workloads'), denied(ctx, 'token.bind', 'requires_instance_owner', { metadata: details }));
      }
      await this.#migrated();
      const standing = await this.#deps.vault.access(member);
      const unknown = () => new Refusal(notFound('unknown service'), denied(ctx, 'token.bind', 'unknown_principal', { metadata: details }));
      if (standing.status !== 'active') throw unknown();
      let jwksUri: string;
      try {
        jwksUri = await discoverKeys(this.#deps.transport, policy.issuer, { allowLoopback: this.#deps.config.allowLoopback });
      } catch (error) {
        if (error instanceof DiscoveryFailed) throw badRequest(`coffre could not use ${policy.issuer}: ${error.message}`);
        throw error;
      }
      const plan = (live: BindingRow[]): BindingPlan => {
        const asked = new Set(input.replaces);
        const unknownReplaced = input.replaces.filter((id) => !live.some((row) => row.id === id));
        if (unknownReplaced.length > 0) throw conflict(`no live binding of ${member}'s is ${unknownReplaced.join(', ')}`);
        const replaces = live.flatMap((row): BindingPlan['replaces'] => {
          if (asked.has(row.id)) return [{ id: row.id, why: 'asked' }];
          return row.issuer === policy.issuer && row.jwksUri !== jwksUri ? [{ id: row.id, why: 'keys_moved' }] : [];
        });
        if (live.length - replaces.length + 1 > MAX_BINDINGS) throw conflict(`a service holds at most ${MAX_BINDINGS} bindings`);
        return { ...policy, jwksUri, replaces };
      };
      if (options.dryRun) return plan(await liveBindings(this.#deps.db, this.#deps.chainKey, member, standing.generation));

      return audited(this.#deps, async (tx, log) => {
        if (!(await stillMember(tx, member, standing))) throw unknown();
        const planned = plan(await liveBindings(tx, this.#deps.chainKey, member, standing.generation));
        const id = randomUUID();
        const now = new Date();
        const row = {
          id,
          principal: member,
          generation: standing.generation,
          profile: planned.profile,
          issuer: planned.issuer,
          jwksUri: planned.jwksUri,
          claims: canonicalClaims(planned.claims),
          label: input.label?.slice(0, 120) ?? null,
          createdAt: now,
          createdBy: ctx.caller.principal.id,
        };
        await insertBinding(tx, this.#deps.chainKey, row);
        for (const replaced of planned.replaces) {
          await this.#revoke(tx, replaced.id, ctx.caller.principal.id, now);
          log.push(allowed(ctx, 'token.unbind', {
            metadata: { bindingId: replaced.id, principalType: 'service', principalId: serviceId, reason: replaced.why === 'asked' ? 'replaced' : 'keys_moved', by: id },
          }));
        }
        log.push(allowed(ctx, 'token.bind', {
          metadata: {
            bindingId: id,
            principalType: 'service',
            principalId: serviceId,
            profile: planned.profile,
            issuer: planned.issuer,
            jwksUri: planned.jwksUri,
            claims: planned.claims,
            replaces: planned.replaces.map((replaced) => replaced.id),
          },
        }));
        return {
          binding: view({ ...row, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null }),
          replaced: planned.replaces.map((replaced) => replaced.id),
        };
      });
    });
  }

  /** Remove a binding. Its successful `token.unbind` is its tombstone: no row put back brings it back. */
  async unbind(ctx: Asker, serviceId: string, bindingId: string): Promise<{ unbound: true }> {
    const member = `token:${serviceId}`;
    const metadata = { bindingId, principalType: 'service', principalId: serviceId };
    return withRefusals(this.#deps, async () => {
      if (!ctx.caller.isOwner) {
        // Logged as a denial, which no tombstone check counts.
        throw new Refusal(forbidden('only owners may remove trust bindings'), denied(ctx, 'token.unbind', 'requires_instance_owner', { metadata }));
      }
      await this.#migrated();
      return audited(this.#deps, async (tx, log) => {
        const row = await findBinding(tx, this.#deps.chainKey, member, bindingId);
        const live = row !== null && row.revokedAt === null
          && (await liveBindings(tx, this.#deps.chainKey, member, row.generation)).some((candidate) => candidate.id === bindingId);
        if (!live || (await this.#revoke(tx, bindingId, ctx.caller.principal.id, new Date())) === 0) {
          throw new Refusal(notFound('unknown trust binding'), denied(ctx, 'token.unbind', 'unknown_binding', { metadata }));
        }
        log.push(allowed(ctx, 'token.unbind', { metadata: { ...metadata, reason: 'removed' } }));
        return { unbound: true as const };
      });
    });
  }

  #revoke(tx: Transaction, id: string, by: string, at: Date): Promise<number> {
    return updateAuth(tx, this.#deps.chainKey, serviceBindings, { id, revokedAt: null }, { revokedAt: at, revokedBy: by });
  }

  /** Bindings live in a table this release's migration adds; until it runs, coffre works without them. */
  async #migrated(): Promise<void> {
    const needed = knownMigrations(this.#deps.db).indexOf(BINDINGS_MIGRATION) + 1;
    if ((await appliedMigrations(this.#deps.db)) < needed) {
      throw new ApiError('unavailable', 'trust bindings need this release\'s database migration: an owner runs `coffre migrate`');
    }
  }
}

/** The member still stands where `standing` said, read under the log's head (`#stillMember` in signin.ts). */
async function stillMember(tx: Transaction, member: string, standing: Access): Promise<boolean> {
  const row = await memberStanding(tx, member);
  return row !== null && row.generation === standing.generation && row.status === 'active';
}

function view(row: BindingRow): BindingView {
  return {
    id: row.id,
    profile: row.profile as WorkloadProfile,
    issuer: row.issuer,
    jwksUri: row.jwksUri,
    claims: JSON.parse(row.claims) as BindingClaims,
    label: row.label,
    createdAt: row.createdAt.toISOString(),
    createdBy: row.createdBy,
    lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
  };
}
