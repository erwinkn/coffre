import { randomUUID } from 'node:crypto';

import {
  BindingInvalid,
  canonicalClaims,
  claimAt,
  checkBinding,
  checkFetchUrl,
  CLOCK_TOLERANCE_SECONDS,
  decodeWorkloadToken,
  differingClaims,
  GitHubAppUnavailable,
  GITLAB_ISSUER,
  issuedRefusal,
  keySummaries,
  KeysInvalid,
  MAX_BINDINGS,
  MAX_TOKEN_AGE_SECONDS,
  uploadedKeys,
  verifyWorkloadToken,
  WorkloadTokenRefused,
  type BindingClaims,
  type DecodedToken,
  type GitHubAppRepositories,
  type JSONWebKeySet,
  type KeySummary,
  type UploadedKeys,
  type WorkloadProfile,
  type WorkloadsConfig,
} from '@coffre/core/identity';
import { shownMember } from '@coffre/core/schemas';
import type { Access, Vault } from '@coffre/core/vault';
import type { Database, Transaction } from '@coffre/db';
import { serviceBindings } from '@coffre/db/schema';

import { issuedBy } from '../auth-rows.ts';
import {
  consumeToken,
  exchangeCandidates,
  exchangesSince,
  findBinding,
  insertBinding,
  liveBindings,
  memberStanding,
  places,
  revokeLiveCredentials,
  standingBinding,
  tokenConsumed,
  update,
  updateAuth,
  type BindingRow,
} from '../db/queries.ts';
import { discoverKeys, DiscoveryFailed } from '../workloads/discovery.ts';
import { IssuerUnavailable, verifyWithKeys } from '../workloads/keys.ts';
import { FetchRefused, type WorkloadTransport } from '../workloads/transport.ts';
import { newestPolicySeq } from './caller.ts';
import type { Asker, SigninService } from './signin.ts';
import { allowed, audited, denied, Refusal, withRefusals, type ApiContext } from './context.ts';
import {
  inheritedScope,
  issuedScope,
  issuerNow,
  issuerStill,
  managedAccount,
  notManager,
  parseScope,
  readScope,
  scopeByPath,
  sealCredentials,
  unsealedScope,
  serviceSettingFor,
  setsUp,
  storedScope,
  type ScopeByPath,
} from './services.ts';
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
  | 'too_long'
  | 'not_yet_valid'
  | 'audience'
  | 'replayed'
  | 'busy'
  | 'issuer_unavailable';

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
  'sub', 'jti', 'actor', 'event_name', 'ref', 'base_ref', 'head_ref', 'sha', 'repository', 'repository_id', 'run_id', 'run_attempt',
  'workflow_ref', 'job_workflow_ref', 'job_workflow_sha', 'environment',
  'project_path', 'project_id', 'namespace_id', 'pipeline_id', 'pipeline_source', 'job_id',
  'kubernetes.io.pod.name',
] as const;
const MAX_RUN_CLAIM = 256;

/** A binding's `jwks_uri` when it carries its issuer's keys: the SHA-256 of those keys (`UploadedKeys`), where a fetched set's URL would be. */
const UPLOADED = 'sha256:';

/** Refusals logged, by reason and service, once a minute each. */
const refusalsLogged = new Map<string, number>();
const REFUSAL_LOG_MS = 60 * 1000;

/** A binding as an owner sees it. */
export type BindingView = {
  id: string;
  profile: WorkloadProfile;
  issuer: string;
  /** Where coffre fetches its issuer's keys; for one that carries them, `sha256:<hex>` of those. */
  jwksUri: string;
  /** The keys it carries, uploaded with it, under which coffre verifies and fetches nothing; null when they are fetched from `jwksUri`. */
  keys: KeySummary[] | null;
  claims: BindingClaims;
  /** What the credentials it issues reach, of what its account holds, by path; null for one 0.4 made and the app has not sealed yet, which reaches all of it. */
  scope: ScopeByPath | null;
  label: string | null;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
};

/** What saving a binding would do: the binding as checked, the keys its issuer names or it carries, and the bindings it replaces. */
export type BindingPlan = {
  profile: WorkloadProfile;
  issuer: string;
  jwksUri: string;
  keys: KeySummary[] | null;
  claims: BindingClaims;
  scope: ScopeByPath;
  /** The places of `scope` that hold a sensitive value its credentials will not read: only an Owner of their project binds one that does (R32). */
  withheld: string[];
  /** `asked`: named in `replaces`. `keys_moved`: the service's bindings on the issuer, under its old keys' URL. */
  replaces: { id: string; why: 'asked' | 'keys_moved' }[];
};

export type BindingInput = {
  profile: string;
  issuer: string | null;
  claims: BindingClaims;
  /** What the credentials it issues reach, by path (`issuedScope`): when left out, what the bindings it replaces reached, or all the account holds. */
  scope?: ScopeByPath;
  label: string | null;
  /** Bindings this one takes the place of, as a change to them: they are removed in the same step. */
  replaces: string[];
  /**
   * The issuer's public keys, a JWKS, for an issuer coffre cannot or should
   * not fetch them from, such as a private Kubernetes cluster's: then the
   * issuer is any string its tokens name, and coffre asks it nothing.
   */
  jwks?: JSONWebKeySet;
};

/**
 * What replacing a service's keys for an issuer would do: the keys, the
 * bindings on the issuer that new ones, the same but for those keys, take
 * the place of, and the places of their scopes that hold a sensitive value
 * the new ones will not read: one an Owner bound, re-keyed by anyone else.
 */
export type KeysPlan = { issuer: string; jwksUri: string; keys: KeySummary[]; replaces: string[]; withheld: string[] };

/**
 * A workload's ID token, verified for a service: the binding of the service
 * whose every claim it carries, and its claims as verified. Nothing spent:
 * whoever acts on it spends it (`consumeToken`).
 */
export type VerifiedWorkload = { binding: BindingRow; claims: Record<string, unknown>; token: DecodedToken };

/**
 * The IDs a binding names, as an owner would otherwise look them up, under
 * the names the host gives them: `Acme/API` looked up is `acme/api`, as its
 * tokens name it. A GitHub owner, a user or an organization, has an ID alone.
 */
export type WorkloadIds =
  | { github: string; repositoryId: string; ownerId: string }
  | { github: string; ownerId: string }
  | { gitlab: string; projectId: string; namespaceId: string };

const GITHUB_OWNER = /^[A-Za-z0-9-]{1,39}$/;
const GITHUB_REPOSITORY = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;
const GITLAB_PROJECT = /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+){1,20}$/;

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
    if (!self && !(await managedAccount(this.#deps, ctx.caller, serviceId)).managed) {
      throw forbidden('only those who manage this service account may see its trust bindings');
    }
    const member = `token:${serviceId}`;
    const standing = await memberStanding(this.#deps.db, member);
    if (standing === null) throw notFound('unknown service');
    const [live, known] = await Promise.all([liveBindings(this.#deps.db, this.#deps.chainKey, member, standing.generation), places(this.#deps.db)]);
    return live.map((row) => view(row, scopeByPath(readScope(row.scope), known)));
  }

  /**
   * A service's live bindings, those an older release made sealed first
   * (`sealCredentials`), as a request's own credential check seals them:
   * one that inherits their scope keeps what their issuer could give,
   * sensitive values included, never less than the seal would say. A dry
   * run seals nothing, as it writes nothing: its plan inherits their
   * scopes as read, and one a release before 0.11 made reads no sensitive
   * value there, so the plan may withhold more than the binding will.
   */
  async #sealedBindings(member: string, generation: number, { dryRun }: { dryRun: boolean }): Promise<BindingRow[]> {
    const { db, chainKey, vault } = this.#deps;
    const live = await liveBindings(db, chainKey, member, generation);
    const unsealed = live.filter((row) => unsealedScope(row.scope));
    if (dryRun || unsealed.length === 0) return live;
    const policySeq = await newestPolicySeq(db);
    const access = await vault.access(member);
    if (access.status !== 'active') return live;
    await sealCredentials(db, chainKey, vault, access, policySeq, unsealed.map((row) => ({ kind: 'binding' as const, id: row.id, principal: member, createdBy: row.createdBy, scope: row.scope })));
    return liveBindings(db, chainKey, member, generation);
  }

  /** Check a binding and ask its issuer where its keys are; with `dryRun`, write nothing and log nothing. */
  async bind(ctx: Asker, serviceId: string, input: BindingInput, options: { dryRun: boolean }): Promise<BindingPlan | { binding: BindingView; replaced: string[] }> {
    const member = `token:${serviceId}`;
    const details = { principalType: 'service', principalId: serviceId, profile: input.profile, issuer: input.issuer };
    const uploaded = input.jwks === undefined ? null : await keysOf(input.jwks);
    let policy: ReturnType<typeof checkBinding>;
    try {
      policy = checkBinding(input, { allowLoopback: this.#deps.config.allowLoopback, uploaded: uploaded !== null });
    } catch (error) {
      if (error instanceof BindingInvalid) throw badRequest(error.message);
      throw error;
    }
    // Its scope's shape too, before the issuer is asked anything: what it names is checked once the bindings it replaces are known.
    if (input.scope !== undefined) parseScope(input.scope, ctx.caller.policy);
    return withRefusals(this.#deps, async () => {
      // The issuer as the vault answers now, held to under the head: demoted meanwhile, they give it nothing (`issuerStill`).
      const { caller, accessSeq } = await issuerNow(this.#deps, ctx.caller.principal, ctx.caller.credentialScope);
      // Who runs the instance, or a person who reaches every grant it holds (`managesService`).
      const { standing, managed, setting } = await managedAccount(this.#deps, caller, serviceId);
      if (!managed) throw notManager(ctx, 'token.bind', details, 'trust workloads as it');
      const unknown = () => new Refusal(notFound('unknown service'), denied(ctx, 'token.bind', 'unknown_principal', { metadata: details }));
      if (standing.status !== 'active') throw unknown();
      // Keys uploaded with it, by their digest; else where its issuer's discovery says they are.
      let jwksUri: string;
      try {
        jwksUri = uploaded === null
          ? await discoverKeys(this.#deps.transport, policy.issuer, { allowLoopback: this.#deps.config.allowLoopback })
          : `${UPLOADED}${uploaded.digest}`;
      } catch (error) {
        if (error instanceof DiscoveryFailed) throw badRequest(`coffre could not use ${policy.issuer}: ${error.message}`);
        throw error;
      }
      /** The bindings it takes the place of, among those live. */
      type Replacing = BindingRow & { why: BindingPlan['replaces'][number]['why'] };
      const replacing = (live: BindingRow[]): Replacing[] => {
        const asked = new Set(input.replaces);
        const unknownReplaced = input.replaces.filter((id) => !live.some((row) => row.id === id));
        if (unknownReplaced.length > 0) throw conflict(`no live binding of ${shownMember(member)}'s is ${unknownReplaced.join(', ')}`);
        const replaces = live.flatMap((row): Replacing[] => {
          if (asked.has(row.id)) return [{ ...row, why: 'asked' }];
          return row.issuer === policy.issuer && row.jwksUri !== jwksUri ? [{ ...row, why: 'keys_moved' }] : [];
        });
        // Keys uploaded, on either side, are no move of the issuer's: the bindings that would go are still good.
        if (replaces.some((row) => row.why === 'keys_moved' && (row.jwksUri.startsWith(UPLOADED) || jwksUri.startsWith(UPLOADED)))) {
          throw conflict(
            `${shownMember(member)}'s other bindings on ${policy.issuer} verify with other keys: replace their keys with these first, or replace those bindings with this one`,
          );
        }
        if (live.length - replaces.length + 1 > MAX_BINDINGS) throw conflict(`a service holds at most ${MAX_BINDINGS} bindings`);
        return replaces;
      };
      const replaced = replacing(await this.#sealedBindings(member, standing.generation, options));
      // Left out, its scope is what those it replaces reached, so that trusting a workload again never widens it.
      const inherits = input.scope === undefined && replaced.length > 0;
      const { scope, byPath, withheld } = await issuedScope(
        this.#deps.db, { ...ctx, caller }, setting, standing, input.scope, { action: 'token.bind', metadata: details }, inherits ? inheritedScope(replaced) : undefined,
      );
      const plan = (replaces: typeof replaced): BindingPlan => ({
        ...policy, jwksUri, keys: uploaded?.keys ?? null, scope: byPath, withheld, replaces: replaces.map(({ id, why }) => ({ id, why })),
      });
      if (options.dryRun) return plan(replaced);

      // Its scope was weighed with the policy and the issuer as the vault answered: committed only while still so (`audited`, `issuerStill`).
      return audited({ ...this.#deps, caller }, async (tx, log) => {
        await issuerStill(tx, caller, accessSeq);
        if (!(await stillMember(tx, member, standing))) throw unknown();
        const planned = plan(replacing(await liveBindings(tx, this.#deps.chainKey, member, standing.generation)));
        if (inherits && planned.replaces.map(({ id }) => id).join() !== replaced.map(({ id }) => id).join()) {
          throw conflict('the bindings it replaces changed while it was made: try again');
        }
        const id = randomUUID();
        const now = new Date();
        const row = {
          id,
          principal: member,
          generation: standing.generation,
          profile: planned.profile,
          issuer: planned.issuer,
          jwksUri: planned.jwksUri,
          jwks: uploaded?.jwks ?? null,
          claims: canonicalClaims(planned.claims),
          scope: storedScope(scope),
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
            ...(uploaded === null ? {} : { keys: uploaded.keys }),
            claims: planned.claims,
            scope,
            replaces: planned.replaces.map((replaced) => replaced.id),
          },
        }));
        return {
          binding: view({ ...row, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null }, byPath),
          replaced: planned.replaces.map((replaced) => replaced.id),
        };
      });
    });
  }

  /**
   * Give a service's bindings on an issuer new keys, uploaded: when the
   * issuer rotates its keys, or when its keys are to be uploaded rather
   * than fetched. Bindings never change, so each is replaced by a new one,
   * the same but for its keys, in one step, and the old one's
   * `token.unbind` is its tombstone: the credentials it issued end with it.
   * A set that holds the old keys and the new verifies tokens of both while
   * the issuer moves from one to the other. With `dryRun`, write nothing and
   * log nothing.
   */
  async replaceKeys(
    ctx: Asker,
    serviceId: string,
    input: { issuer: string; jwks: JSONWebKeySet },
    options: { dryRun: boolean },
  ): Promise<KeysPlan | { bindings: BindingView[]; replaced: string[] }> {
    const member = `token:${serviceId}`;
    const details = { principalType: 'service', principalId: serviceId, issuer: input.issuer };
    const uploaded = await keysOf(input.jwks);
    const jwksUri = `${UPLOADED}${uploaded.digest}`;
    return withRefusals(this.#deps, async () => {
      // The issuer as the vault answers now, held to under the head (`issuerStill`), as in `bind`.
      const { caller, accessSeq } = await issuerNow(this.#deps, ctx.caller.principal, ctx.caller.credentialScope);
      const { standing, managed, setting } = await managedAccount(this.#deps, caller, serviceId);
      if (!managed) throw notManager(ctx, 'token.bind', details, 'trust workloads as it');
      const unknown = () => new Refusal(notFound('unknown service'), denied(ctx, 'token.bind', 'unknown_principal', { metadata: details }));
      if (standing.status !== 'active') throw unknown();
      /** Its live bindings on the issuer, each held to its profile as one that carries its keys. */
      const replacing = (live: BindingRow[]): BindingRow[] => {
        const on = live.filter((row) => row.issuer === input.issuer);
        if (on.length === 0) throw notFound(`no binding of ${shownMember(member)}'s trusts ${input.issuer}`);
        if (on.every((row) => row.jwksUri === jwksUri)) throw conflict(`${shownMember(member)}'s bindings on ${input.issuer} carry these keys already`);
        for (const row of on) {
          try {
            checkBinding({ profile: row.profile, issuer: row.issuer, claims: JSON.parse(row.claims) as BindingClaims }, { uploaded: true });
          } catch (error) {
            if (error instanceof BindingInvalid) throw badRequest(error.message);
            throw error;
          }
        }
        return on;
      };
      const replaced = replacing(await this.#sealedBindings(member, standing.generation, options));
      // Each reaches what the one it replaces did, of what the account still holds: replacing keys never widens a binding.
      const scopes = new Map<string, Awaited<ReturnType<typeof issuedScope>>>();
      for (const row of replaced) {
        scopes.set(row.id, await issuedScope(this.#deps.db, { ...ctx, caller }, setting, standing, undefined, { action: 'token.bind', metadata: details }, inheritedScope([row])));
      }
      const withheld = [...new Set([...scopes.values()].flatMap((issued) => issued.withheld))].sort();
      const plan: KeysPlan = { issuer: input.issuer, jwksUri, keys: uploaded.keys, replaces: replaced.map((row) => row.id), withheld };
      if (options.dryRun) return plan;

      // Its scope was weighed with the policy and the issuer as the vault answered: committed only while still so (`audited`, `issuerStill`).
      return audited({ ...this.#deps, caller }, async (tx, log) => {
        await issuerStill(tx, caller, accessSeq);
        if (!(await stillMember(tx, member, standing))) throw unknown();
        const live = replacing(await liveBindings(tx, this.#deps.chainKey, member, standing.generation));
        if (live.map((row) => row.id).join() !== plan.replaces.join()) throw conflict(`the bindings on ${input.issuer} changed while their keys were replaced: try again`);
        const now = new Date();
        const bindings: BindingView[] = [];
        for (const [i, old] of live.entries()) {
          const id = randomUUID();
          const { scope, byPath } = scopes.get(old.id)!;
          const row = {
            id,
            principal: member,
            generation: standing.generation,
            profile: old.profile,
            issuer: old.issuer,
            jwksUri,
            jwks: uploaded.jwks,
            claims: old.claims,
            scope: storedScope(scope),
            label: old.label,
            // A millisecond apart, in the order of those they replace: an exchange tries bindings oldest first, and still does.
            createdAt: new Date(now.getTime() + i),
            createdBy: ctx.caller.principal.id,
          };
          await insertBinding(tx, this.#deps.chainKey, row);
          await this.#revoke(tx, old.id, member, ctx.caller.principal.id, now);
          log.push(allowed(ctx, 'token.unbind', {
            metadata: { bindingId: old.id, principalType: 'service', principalId: serviceId, reason: 'keys_replaced', by: id },
          }));
          log.push(allowed(ctx, 'token.bind', {
            metadata: {
              bindingId: id,
              principalType: 'service',
              principalId: serviceId,
              profile: old.profile,
              issuer: old.issuer,
              jwksUri,
              keys: uploaded.keys,
              claims: JSON.parse(old.claims) as BindingClaims,
              scope,
              replaces: [old.id],
            },
          }));
          bindings.push(view({ ...row, authMac: Buffer.alloc(0), lastUsedAt: null, revokedAt: null, revokedBy: null }, byPath));
        }
        return { bindings, replaced: plan.replaces };
      });
    });
  }

  /** Remove a binding. Its successful `token.unbind` is its tombstone: no row put back brings it back. */
  async unbind(ctx: Asker, serviceId: string, bindingId: string): Promise<{ unbound: true }> {
    const member = `token:${serviceId}`;
    const metadata = { bindingId, principalType: 'service', principalId: serviceId };
    return withRefusals(this.#deps, async () => {
      // Logged as a denial, which no tombstone check counts.
      if (!(await managedAccount(this.#deps, ctx.caller, serviceId)).managed) throw notManager(ctx, 'token.unbind', metadata, 'remove its trust bindings');
      // Who manages it was weighed with the policy as the caller was loaded: committed only while still so (`audited`).
      return audited({ ...this.#deps, caller: ctx.caller }, async (tx, log) => {
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
   * A repository's, owner's or project's IDs, which bindings name rather
   * than names: GitHub's API, or a GitLab's. The pages cannot ask those
   * hosts themselves, since they may connect only to coffre; the CLI asks
   * itself. A GitHub repository resolves through the deployment's GitHub App
   * when it is installed there, private or not, and through the public API
   * otherwise. A private one neither reaches is not found, and its IDs are
   * typed in.
   *
   * Asked without signing in, GitHub answers 60 lookups an hour per
   * address, which every user of a Workers deployment shares: a 403 or a
   * 429 says the hour's are spent, as `too_many_requests`.
   */
  async lookup(ctx: Asker, input: { github?: string; gitlab?: string; gitlabUrl?: string }): Promise<WorkloadIds> {
    await this.#setsUp(ctx);
    const ask = async (url: URL, missing = notFound(`${url.hostname} did not find it: for a private one, type its IDs`)): Promise<Record<string, unknown>> => {
      try {
        const answer = await this.#deps.transport.json(url);
        return typeof answer === 'object' && answer !== null ? (answer as Record<string, unknown>) : {};
      } catch (error) {
        if (!(error instanceof FetchRefused)) throw error;
        if (error.status === 403 || error.status === 429) {
          throw new ApiError('too_many_requests', `${url.hostname} allows only so many lookups an hour without signing in, and this hour's are spent: try again later, or type the IDs`);
        }
        if (error.status === 404) throw missing;
        throw new ApiError('unavailable', `${url.hostname} did not answer (${error.message}): try again, or type the IDs`);
      }
    };
    const id = (value: unknown) => (typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : null);
    const name = (value: unknown, given: string) => (typeof value === 'string' && value.toLowerCase() === given.toLowerCase() ? value : given);
    if (input.github !== undefined && GITHUB_OWNER.test(input.github)) {
      const owner = await ask(new URL(`https://api.github.com/users/${input.github}`));
      const ownerId = id(owner.id);
      if (ownerId === null) throw notFound(`GitHub does not know ${input.github}`);
      return { github: name(owner.login, input.github), ownerId };
    }
    if (input.github !== undefined) {
      if (!GITHUB_REPOSITORY.test(input.github)) throw badRequest('a GitHub repository is <owner>/<name>, and an owner <owner>');
      const app = this.#deps.config.github;
      if (app !== null) {
        const found = await unavailable(() => app.repository(input.github!));
        if (found !== null) return { github: found.github, repositoryId: found.repositoryId, ownerId: found.ownerId };
      }
      const owner = input.github.split('/')[0]!;
      const repository = await ask(
        new URL(`https://api.github.com/repos/${input.github}`),
        // `not_installed`: the pages say this, where a 404 is otherwise theirs to word.
        app === null ? undefined : new ApiError('not_found', `GitHub did not find it, and the GitHub App is not installed on it: install it on ${owner}, or type its IDs`, 'not_installed'),
      );
      const [repositoryId, ownerId] = [id(repository.id), id((repository.owner as Record<string, unknown> | undefined)?.id)];
      if (repositoryId === null || ownerId === null) throw notFound(`GitHub does not know ${input.github}`);
      return { github: name(repository.full_name, input.github), repositoryId, ownerId };
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
      return { gitlab: name(project.path_with_namespace, input.gitlab), projectId, namespaceId };
    }
    throw badRequest('look up a GitHub repository or a GitLab project');
  }

  /**
   * The repositories the deployment's GitHub App is installed on, for the
   * pages' picker; `{ app: null }` when it has none. One call to coffre,
   * which asks GitHub for each installation (`GitHubApp.repositories`).
   */
  async repositories(ctx: Asker): Promise<GitHubAppRepositories | { app: null }> {
    await this.#setsUp(ctx);
    const app = this.#deps.config.github;
    return app === null ? { app: null } : unavailable(() => app.repositories());
  }

  /** Asked of GitHub or GitLab for whoever sets up any service account; what they trust, each binding's own check decides. */
  async #setsUp(ctx: Asker): Promise<void> {
    if (!setsUp(ctx.caller, await serviceSettingFor(this.#deps.vault, ctx.caller), await places(this.#deps.db))) {
      throw forbidden('only those who set up service accounts may trust workloads');
    }
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
   *    claims against those bindings (`verify`);
   * 4. that it is not spent yet, a read;
   * 5. the member, from the vault, outside any transaction, and a binding
   *    0.4 made sealed with what it holds (`sealCredentials`);
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

  /**
   * Which binding of `member`, `token:<id>`, a workload's ID token matches,
   * the exchange's steps 1 to 3: its shape, the service's live bindings on
   * its issuer, then its signature under that issuer's keys, fetched or
   * carried, its audience, times and claims. Nothing written, and the token
   * not spent: whoever acts on it checks that, and spends it. Throws
   * `ExchangeRefused`, saying why as a workload's owner can act on it.
   */
  async verify(member: string, token: string): Promise<VerifiedWorkload> {
    const { db, chainKey, transport } = this.#deps;
    let decoded: DecodedToken;
    try {
      decoded = decodeWorkloadToken(token);
    } catch (error) {
      throw refused(error);
    }
    const issuer = decoded.claims.iss;
    const unbound = () => new ExchangeRefused('no_match', `no binding of ${shownMember(member)} trusts tokens from ${issuer}`);
    if (!/^token:[a-z0-9][a-z0-9._-]{0,99}$/.test(member)) throw unbound();

    // The bindings first, so that a token none can take costs this one read.
    const candidates = await exchangeCandidates(db, chainKey, member, issuer, MAX_BINDINGS);
    if (candidates.length === 0) throw unbound();
    // A service's bindings on one issuer share its keys; one made after the keys moved replaced the rest.
    const newest = candidates[candidates.length - 1]!;
    const expected = { issuer, audience: this.#deps.publicUrl, now: new Date() };
    let claims: Record<string, unknown>;
    try {
      claims = newest.jwks === null
        ? await verifyWithKeys(transport, newest.jwksUri, token, expected)
        // Uploaded keys: nothing to fetch, and no issuer to ask whether a token still stands, so none lives past the hour.
        : await verifyWorkloadToken(token, JSON.parse(newest.jwks) as JSONWebKeySet, { ...expected, maxLifetime: MAX_TOKEN_AGE_SECONDS });
    } catch (error) {
      if (error instanceof IssuerUnavailable) throw new ExchangeRefused('issuer_unavailable', error.message, 503);
      if (newest.jwks !== null && error instanceof WorkloadTokenRefused && error.reason === 'unknown_key') {
        throw new ExchangeRefused('unknown_key', `the token's key is not among those uploaded for ${issuer}: if it rotated its keys, replace them`);
      }
      throw refused(error);
    }
    const binding = matching(candidates.filter((candidate) => candidate.jwksUri === newest.jwksUri), claims, member);
    return { binding, claims, token: decoded };
  }

  async #exchange(request: ExchangeRequest, meta: { requestId: string; sourceIp: string | null }): Promise<Exchanged> {
    const { db, chainKey, vault } = this.#deps;
    const member = request.service;
    const { binding, claims, token: decoded } = await this.verify(member, request.token);
    const issuer = decoded.claims.iss;
    const unbound = () => new ExchangeRefused('no_match', `no binding of ${shownMember(member)} trusts tokens from ${issuer}`);

    if (await tokenConsumed(db, decoded.signingInputHash)) throw new ExchangeRefused('replayed', 'this token was exchanged already: ask your CI for a fresh one');
    const policySeq = await newestPolicySeq(db);
    const standing = await vault.access(member);
    if (standing.status !== 'active' || standing.generation !== binding.generation) throw unbound();
    // One an older release made after the app sealed its own: sealed with the account's grants the vault just answered, before a run's credential reads it.
    if (unsealedScope(binding.scope)) {
      await sealCredentials(db, chainKey, vault, standing, policySeq, [{ kind: 'binding', id: binding.id, principal: member, createdBy: binding.createdBy, scope: binding.scope }]);
    }

    const service = member.slice('token:'.length);
    const ctx = { caller: { principal: { type: 'service', id: service } }, requestId: meta.requestId, sourceIp: meta.sourceIp } as Pick<ApiContext, 'caller' | 'requestId' | 'sourceIp'>;
    return audited(this.#deps, async (tx, log) => {
      const now = new Date();
      if (!(await stillMember(tx, member, standing)) || (await standingBinding(tx, chainKey, binding.id, member, binding.generation)) === null) {
        throw unbound();
      }
      // The times again, should the request have waited.
      const seconds = now.getTime() / 1000;
      if (decoded.claims.exp <= seconds - CLOCK_TOLERANCE_SECONDS) throw new ExchangeRefused('expired', 'the token has expired');
      const issued = issuedRefusal(decoded.claims.iat, seconds);
      if (issued !== null) throw refused(issued);
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
}

/** An uploaded key set, checked (`uploadedKeys`), or a 400 saying what is wrong with it. */
async function keysOf(jwks: JSONWebKeySet): Promise<UploadedKeys> {
  try {
    return await uploadedKeys(jwks);
  } catch (error) {
    if (error instanceof KeysInvalid) throw badRequest(error.message);
    throw error;
  }
}

/** GitHub not answering the app, or refusing it, as the API answers it: 503, saying which. */
async function unavailable<T>(ask: () => Promise<T>): Promise<T> {
  try {
    return await ask();
  } catch (error) {
    if (error instanceof GitHubAppUnavailable) throw new ApiError('unavailable', `${error.message}; type its IDs meanwhile`);
    throw error;
  }
}

/** A token refused on its own terms, as an exchange answers it. */
function refused(error: unknown): ExchangeRefused {
  if (error instanceof WorkloadTokenRefused) return new ExchangeRefused(error.reason, error.message);
  throw error;
}

/**
 * The binding whose every claim the token carries (`differingClaims`). None:
 * the claims that differ from the closest binding, by name, never the
 * values it expects.
 */
function matching(bindings: BindingRow[], claims: Record<string, unknown>, member: string): BindingRow {
  let closest: string[] | null = null;
  for (const binding of bindings) {
    const differ = differingClaims(binding.profile as WorkloadProfile, JSON.parse(binding.claims) as BindingClaims, claims);
    if (differ.length === 0) return binding;
    if (closest === null || differ.length < closest.length) closest = differ;
  }
  throw new ExchangeRefused('no_match', `no binding of ${shownMember(member)} trusts these claims: ${(closest ?? []).join(', ')} differ`);
}

/** The run's claims, as the issuer stated them: those that say which run, each bounded. */
function runClaims(claims: Record<string, unknown>): Record<string, string | number> {
  const run: Record<string, string | number> = {};
  for (const name of RUN_CLAIMS) {
    const value = claimAt(claims, name);
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

function view(row: BindingRow, scope: ScopeByPath | null): BindingView {
  return {
    id: row.id,
    profile: row.profile as WorkloadProfile,
    issuer: row.issuer,
    jwksUri: row.jwksUri,
    keys: row.jwks === null ? null : keySummaries(row.jwks),
    claims: JSON.parse(row.claims) as BindingClaims,
    scope,
    label: row.label,
    createdAt: row.createdAt.toISOString(),
    createdBy: row.createdBy,
    lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
  };
}
