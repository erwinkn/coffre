import { randomUUID } from 'node:crypto';

import {
  BindingInvalid,
  canonicalClaims,
  checkBinding,
  checkFetchUrl,
  CLOCK_TOLERANCE_SECONDS,
  decodeWorkloadToken,
  GITLAB_ISSUER,
  MAX_BINDINGS,
  MAX_TOKEN_AGE_SECONDS,
  WorkloadTokenRefused,
  type BindingClaims,
  type DecodedToken,
  type WorkloadProfile,
  type WorkloadsConfig,
} from '@coffre/core/identity';
import type { Access, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';
import { knownMigrations } from '@coffre/db/schema-version';
import { serviceBindings } from '@coffre/db/schema';

import { issuedBy } from '../auth-rows.ts';
import {
  appliedMigrations,
  bindingStands,
  consumeToken,
  exchangeCandidates,
  exchangesSince,
  findBinding,
  insertBinding,
  liveBindings,
  memberStanding,
  revokeLiveCredentials,
  tokenConsumed,
  update,
  updateAuth,
  type BindingRow,
} from '../db/queries.ts';
import { discoverKeys, DiscoveryFailed } from '../workloads/discovery.ts';
import { IssuerUnavailable, verifyWithKeys } from '../workloads/keys.ts';
import { FetchRefused, type WorkloadTransport } from '../workloads/transport.ts';
import type { Asker, SigninService } from './signin.ts';
import { allowed, audited, denied, Refusal, withRefusals, type ApiContext } from './context.ts';
import { ApiError, badRequest, conflict, forbidden, notFound } from './errors.ts';

export type WorkloadServiceDeps = {
  db: Database;
  chainKey: Buffer;
  vault: Vault;
  config: WorkloadsConfig;
  transport: WorkloadTransport;
  /** What issues the credential an exchange returns. */
  signin: SigninService;
  /** The audience every token must name, alone. */
  publicUrl: string;
};

/** What a CI run sends: the service it signs in as, `token:<id>`, and its platform's ID token. */
export type ExchangeRequest = { service: string; token: string };

/** A credential of the service, for one run, and when it dies. */
export type Exchanged = { token: string; expiresAt: string };

/** Why an exchange was refused, as a CI user can act on it; never the values a binding expects. */
export type ExchangeReason =
  | 'malformed'
  | 'no_match'
  | 'signature'
  | 'unknown_key'
  | 'expired'
  | 'too_old'
  | 'not_yet_valid'
  | 'audience'
  | 'replayed'
  | 'busy'
  | 'issuer_unavailable'
  | 'migration_pending';

/**
 * A refused exchange: 401 with its reason, 429 when too many come at once,
 * 503 when the issuer cannot be asked. Nobody was authenticated, so none of
 * it goes in the audit log (anyone can mint a genuine token from their own
 * repository); the process log has a line, sampled.
 */
export class ExchangeRefused extends Error {
  readonly reason: ExchangeReason;
  readonly status: 401 | 429 | 503;
  constructor(reason: ExchangeReason, message: string, status: 401 | 429 | 503 = 401) {
    super(message);
    this.name = 'ExchangeRefused';
    this.reason = reason;
    this.status = status;
  }
}

/** How long a credential an exchange issues lives: one `coffre run` needs it for seconds. */
export const EXCHANGED_CREDENTIAL_MS = 5 * 60 * 1000;
/** How many credentials one binding issues a minute, counted under the log's head. */
export const EXCHANGES_PER_BINDING_MINUTE = 60;
/** Exchanges under way at once in this isolate or process. */
const MAX_IN_FLIGHT = 32;
let inFlight = 0;

/**
 * The claims of the run a credential was issued for, as the issuer
 * asserted them: in the exchange's entry, so that a read leads back to
 * its run. What the issuer says, not proof of which run sent the request.
 */
const RUN_CLAIMS = [
  'sub', 'jti', 'actor', 'event_name', 'ref', 'sha', 'repository', 'repository_id', 'run_id', 'run_attempt',
  'workflow_ref', 'job_workflow_ref', 'job_workflow_sha', 'environment',
  'project_path', 'project_id', 'namespace_id', 'pipeline_id', 'pipeline_source', 'job_id',
] as const;
const MAX_RUN_CLAIM = 256;

/** Refusals logged, by reason and service, once a minute each. */
const refusalsLogged = new Map<string, number>();
const REFUSAL_LOG_MS = 60 * 1000;

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

/** The IDs a binding names, as an owner would otherwise look them up. */
export type WorkloadIds =
  | { github: string; repositoryId: string; ownerId: string }
  | { gitlab: string; projectId: string; namespaceId: string };

const GITHUB_REPOSITORY = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const GITLAB_PROJECT = /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+){1,20}$/;

/** The migrations that add bindings, and spent tokens: until they run, this release works without them. */
const BINDINGS_MIGRATION = '0002_service_bindings';
const EXCHANGE_MIGRATION = '0003_exchanges';

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

  /** The two limits every exchange passes first (`exchangeWorkloadToken` in auth-routes.ts). */
  get limits(): WorkloadsConfig['limits'] {
    return this.#deps.config.limits;
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
          await this.#revoke(tx, replaced.id, `token:${serviceId}`, ctx.caller.principal.id, now);
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
        if (!live || (await this.#revoke(tx, bindingId, member, ctx.caller.principal.id, new Date())) === 0) {
          throw new Refusal(notFound('unknown trust binding'), denied(ctx, 'token.unbind', 'unknown_binding', { metadata }));
        }
        log.push(allowed(ctx, 'token.unbind', { metadata: { ...metadata, reason: 'removed' } }));
        return { unbound: true as const };
      });
    });
  }

  /**
   * A public repository's or project's IDs, which bindings name rather than
   * names: GitHub's API, or a GitLab's. The pages cannot ask those hosts
   * themselves, since they may connect only to coffre; the CLI asks itself.
   * A private one is not found, and its IDs are typed in.
   */
  async lookup(ctx: Asker, input: { github?: string; gitlab?: string; gitlabUrl?: string }): Promise<WorkloadIds> {
    if (!ctx.caller.isOwner) throw forbidden('only owners may trust workloads');
    const ask = async (url: URL): Promise<Record<string, unknown>> => {
      try {
        const answer = await this.#deps.transport.json(url);
        return typeof answer === 'object' && answer !== null ? (answer as Record<string, unknown>) : {};
      } catch (error) {
        if (error instanceof FetchRefused) throw notFound(`${url.hostname} did not find it: a private one's IDs are typed in`);
        throw error;
      }
    };
    const id = (value: unknown) => (typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : null);
    if (input.github !== undefined) {
      if (!GITHUB_REPOSITORY.test(input.github)) throw badRequest('a GitHub repository is <owner>/<name>');
      const repository = await ask(new URL(`https://api.github.com/repos/${input.github}`));
      const [repositoryId, ownerId] = [id(repository.id), id((repository.owner as Record<string, unknown> | undefined)?.id)];
      if (repositoryId === null || ownerId === null) throw notFound(`GitHub does not know ${input.github}`);
      return { github: input.github, repositoryId, ownerId };
    }
    if (input.gitlab !== undefined) {
      if (!GITLAB_PROJECT.test(input.gitlab)) throw badRequest('a GitLab project is <group>/<name>');
      const base = input.gitlabUrl ?? GITLAB_ISSUER;
      try {
        checkFetchUrl(base, 'the GitLab URL', { allowLoopback: this.#deps.config.allowLoopback, path: true, query: false });
      } catch (error) {
        if (error instanceof BindingInvalid) throw badRequest(error.message);
        throw error;
      }
      const project = await ask(new URL(`${base.replace(/\/$/, '')}/api/v4/projects/${encodeURIComponent(input.gitlab)}`));
      const [projectId, namespaceId] = [id(project.id), id((project.namespace as Record<string, unknown> | undefined)?.id)];
      if (projectId === null || namespaceId === null) throw notFound(`GitLab does not know ${input.gitlab}`);
      return { gitlab: input.gitlab, projectId, namespaceId };
    }
    throw badRequest('look up a GitHub repository or a GitLab project');
  }

  /** Revoke a binding, and every credential it issued that still lives: they die with it. */
  /**
   * Revoke a binding, and the credentials it issued that are still live: at
   * most a few minutes' worth, however long its history. Every use of a
   * credential checks its binding too, so these rows are belt and braces;
   * the expired ones are dead already and are left as they are.
   */
  async #revoke(tx: Transaction, id: string, member: string, by: string, at: Date): Promise<number> {
    const revoked = await updateAuth(tx, this.#deps.chainKey, serviceBindings, { id, revokedAt: null }, { revokedAt: at, revokedBy: by });
    await revokeLiveCredentials(tx, this.#deps.chainKey, { principal: member, createdBy: issuedBy(id), at }, { revokedAt: at, revokedBy: by });
    return revoked;
  }

  /**
   * A CI run's ID token, for a credential of the service it names
   * (docs/design/oidc.md, section 2). Admission comes first, in the route;
   * then, in order, so that a stranger costs one bounded read at most:
   *
   * 1. the token's shape;
   * 2. the service's live bindings on its issuer, one read;
   * 3. its signature under that issuer's keys, then its audience, times and
   *    claims against those bindings;
   * 4. that it is not spent yet, a read;
   * 5. the member, from the vault, outside any transaction;
   * 6. in one transaction that holds the log's head: the member and the
   *    binding again, the times again, the binding's rate, the token spent,
   *    the credential issued and `token.exchange` logged, or none of it.
   */
  async exchange(request: ExchangeRequest, meta: { requestId: string; sourceIp: string | null }): Promise<Exchanged> {
    if (inFlight >= MAX_IN_FLIGHT) throw new ExchangeRefused('busy', 'too many exchanges under way: try again shortly', 429);
    inFlight++;
    try {
      return await this.#exchange(request, meta);
    } catch (error) {
      if (error instanceof ExchangeRefused) logRefusal(error, request.service, meta.sourceIp);
      throw error;
    } finally {
      inFlight--;
    }
  }

  async #exchange(request: ExchangeRequest, meta: { requestId: string; sourceIp: string | null }): Promise<Exchanged> {
    const { db, chainKey, transport, vault } = this.#deps;
    let decoded: DecodedToken;
    try {
      decoded = decodeWorkloadToken(request.token);
    } catch (error) {
      throw refused(error);
    }
    const issuer = decoded.claims.iss;
    const member = request.service;
    const unbound = () => new ExchangeRefused('no_match', `no binding of ${member} trusts tokens from ${issuer}`);
    if (!/^token:[a-z0-9][a-z0-9._-]{0,99}$/.test(member)) throw unbound();
    const pending = () => new ExchangeRefused('migration_pending', 'exchanges need this release\'s database migrations: an owner runs `coffre migrate`', 503);

    // The bindings first, so that a token none can take costs this one read:
    // the migrations are asked of a read that failed, or of a token that
    // verified and matched a binding.
    let candidates: BindingRow[];
    try {
      candidates = await exchangeCandidates(db, chainKey, member, issuer, MAX_BINDINGS);
    } catch (error) {
      await this.#migrated(BINDINGS_MIGRATION).catch(() => {
        throw pending();
      });
      throw error;
    }
    if (candidates.length === 0) throw unbound();
    // A service's bindings on one issuer share its keys' URL; one made after the keys moved replaced the rest.
    const jwksUri = candidates[candidates.length - 1]!.jwksUri;
    let claims: Record<string, unknown>;
    try {
      claims = await verifyWithKeys(transport, jwksUri, request.token, { issuer, audience: this.#deps.publicUrl, now: new Date() });
    } catch (error) {
      if (error instanceof IssuerUnavailable) throw new ExchangeRefused('issuer_unavailable', error.message, 503);
      throw refused(error);
    }
    const binding = matching(candidates.filter((candidate) => candidate.jwksUri === jwksUri), claims, member);

    // Only now, for a token a binding takes, whether spent tokens have their table.
    await this.#migrated(EXCHANGE_MIGRATION).catch(() => {
      throw pending();
    });
    if (await tokenConsumed(db, decoded.signingInputHash)) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your CI for a fresh one');
    const standing = await vault.access(member);
    if (standing.status !== 'active' || standing.generation !== binding.generation) throw unbound();

    const service = member.slice('token:'.length);
    const ctx = { caller: { principal: { type: 'service', id: service } }, requestId: meta.requestId, sourceIp: meta.sourceIp } as Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>;
    return audited(this.#deps, async (tx, log) => {
      const now = new Date();
      if (!(await stillMember(tx, member, standing)) || !(await bindingStands(tx, chainKey, binding.id, member, binding.generation))) {
        throw unbound();
      }
      // The times again, should the request have waited.
      const seconds = now.getTime() / 1000;
      if (decoded.claims.exp <= seconds - CLOCK_TOLERANCE_SECONDS) throw new ExchangeRefused('expired', 'the token has expired');
      if (seconds - decoded.claims.iat > MAX_TOKEN_AGE_SECONDS + CLOCK_TOLERANCE_SECONDS) {
        throw new ExchangeRefused('too_old', `the token was issued more than ${MAX_TOKEN_AGE_SECONDS / 60} minutes ago`);
      }
      const recent = await exchangesSince(tx, member, issuedBy(binding.id), new Date(now.getTime() - 60_000), EXCHANGES_PER_BINDING_MINUTE);
      if (recent >= EXCHANGES_PER_BINDING_MINUTE) {
        throw new ExchangeRefused('busy', `this binding issued ${EXCHANGES_PER_BINDING_MINUTE} credentials in the last minute: try again shortly`, 429);
      }
      if (!(await consumeToken(tx, decoded.signingInputHash))) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your CI for a fresh one');
      const expiresAt = new Date(now.getTime() + EXCHANGED_CREDENTIAL_MS);
      const credential = await this.#deps.signin.issueExchanged(tx, service, { generation: binding.generation, bindingId: binding.id, label: binding.label, expiresAt });
      await update(tx, serviceBindings, { id: binding.id }, { lastUsedAt: now });
      log.push(allowed(ctx, 'token.exchange', {
        metadata: {
          credentialId: credential.id,
          bindingId: binding.id,
          generation: binding.generation,
          issuer,
          expiresAt: credential.expiresAt,
          run: runClaims(claims),
        },
      }));
      return { token: credential.token, expiresAt: credential.expiresAt };
    });
  }

  /** Bindings, and spent tokens, live in tables this release's migrations add; until they run, coffre works without them. */
  async #migrated(tag = BINDINGS_MIGRATION): Promise<void> {
    const needed = knownMigrations(this.#deps.db).indexOf(tag) + 1;
    if ((await appliedMigrations(this.#deps.db)) < needed) {
      throw new ApiError('unavailable', 'trust bindings need this release\'s database migration: an owner runs `coffre migrate`');
    }
  }
}

/** A token refused on its own terms, as an exchange answers it. */
function refused(error: unknown): ExchangeRefused {
  if (error instanceof WorkloadTokenRefused) return new ExchangeRefused(error.reason, error.message);
  throw error;
}

/**
 * The binding whose every claim the token carries, exactly. None: the
 * claims that differ from the closest binding, by name, never the values it
 * expects.
 */
function matching(bindings: BindingRow[], claims: Record<string, unknown>, member: string): BindingRow {
  let closest: string[] | null = null;
  for (const binding of bindings) {
    const expected = JSON.parse(binding.claims) as BindingClaims;
    const differ = Object.entries(expected).filter(([name, value]) => claims[name] !== value).map(([name]) => name);
    if (differ.length === 0) return binding;
    if (closest === null || differ.length < closest.length) closest = differ;
  }
  throw new ExchangeRefused('no_match', `no binding of ${member} trusts these claims: ${(closest ?? []).join(', ')} differ`);
}

/** The run's claims, as the issuer stated them: those that say which run, each bounded. */
function runClaims(claims: Record<string, unknown>): Record<string, string | number> {
  const run: Record<string, string | number> = {};
  for (const name of RUN_CLAIMS) {
    const value = claims[name];
    if (typeof value === 'string') run[name] = value.slice(0, MAX_RUN_CLAIM);
    else if (typeof value === 'number' && Number.isFinite(value)) run[name] = value;
  }
  return run;
}

/** One line per reason and service a minute: enough to see a refusal, not a flood. */
function logRefusal(error: ExchangeRefused, service: string, sourceIp: string | null): void {
  const key = `${error.reason} ${String(service).slice(0, 120)}`;
  const now = Date.now();
  if ((refusalsLogged.get(key) ?? 0) > now - REFUSAL_LOG_MS) return;
  refusalsLogged.set(key, now);
  if (refusalsLogged.size > 1000) refusalsLogged.delete(refusalsLogged.keys().next().value!);
  console.error({ event: 'workload_exchange_refused', reason: error.reason, service: key.slice(error.reason.length + 1), sourceIp }, error.message);
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
