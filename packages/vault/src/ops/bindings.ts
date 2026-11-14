import { randomUUID } from 'node:crypto';

import {
  allows,
  assignableToEnvironment,
  definitionOf,
  isCredentialScope,
  issuedGrant,
  issuesCredential,
  narrowest,
  NOTHING,
  ownsProject,
  scopeDefinition,
  scopeWithReads,
  type Holdings,
  type Place,
  type Policy,
  type ScopeGrant,
  type ServiceAccount,
} from '@coffre/core/access';
import {
  BindingInvalid,
  CARRIED,
  canonicalClaims,
  checkBinding,
  checkPolicy,
  isBearerProfile,
  KeysInvalid,
  MAX_BINDINGS,
  MAX_READ_KEYS,
  MAX_READ_PLACES,
  policyText,
  PROFILE_RULES,
  PROFILE_URNS,
  uploadedKeys,
  type BindingClaims,
  type BindingPolicy,
  type CheckedBinding,
  type UploadedKeys,
} from '@coffre/core/identity';
import type { Answers, NewBinding, Presented, TokenBind, TokenUnbind } from '@coffre/core/vault';
import { bindings, environments, projects, roles, secrets } from '@coffre/db/schema';
import { sql } from 'drizzle-orm';

import { callerParts, refusedTo } from '../caller.ts';
import { amended, part, put, type Operation, type Parts, type Refusal, type Seen, type Unsealed, type Write } from '../change.ts';
import type { Row } from '../rows.ts';
import type { Deciding } from '../vault.ts';
import { asking } from './asking.ts';
import type { Operations } from './index.ts';
import { long, presented, text } from './input.ts';
import { definitionsOf, manages, projectsOf, serviceOf, serviceParts, settingOf } from './services.ts';
import { by, labelled, scopeAsked, sealedScope, SLUG, type Wanted } from './signin.ts';

/** A binding's id, as the vault draws one. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** A service account, by its member id (`principals_id_check`). */
const SERVICE = /^token:[^\s:]\S*$/;
/** The longest issuer or keys' address the contract carries. */
const MOST_URL = 2048;
/** A key's name in a binding's `reads`, as 0.14.7 took one. */
const MOST_KEY = 256;

const NO_ACCESS: Refusal = { refused: 'no_access' };
const INVALID: Refusal = { refused: 'invalid' };

/** An environment a binding's `reads` names, by path, and the keys it lists there, by name, or every one. */
type ReadAsked = { project: string; environment: string; keys: string[] | '*' };

/** `reads` as the app names them, `{ "market/prod": ["STRIPE_KEY"] }`, copied: 64 environments at most, each its key names, 256 at most, or `"*"`. */
function readsAsked(value: unknown): ReadAsked[] | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > MAX_READ_PLACES) return undefined;
  const asked: ReadAsked[] = [];
  for (const [path, keys] of entries) {
    const [project, environment, ...more] = path.split('/');
    if (more.length > 0 || !SLUG.test(project!) || environment === undefined || !SLUG.test(environment)) return undefined;
    if (keys !== '*' && !(Array.isArray(keys) && keys.length <= MAX_READ_KEYS && keys.every((key) => text(key) && key !== '' && key.length <= MOST_KEY))) return undefined;
    asked.push({ project: project!, environment, keys: keys === '*' ? '*' : [...new Set(keys as string[])] });
  }
  return asked;
}

/** A URL or an issuer's name as the contract carries one: well-formed text, 2,048 characters at most. */
const url = (value: unknown): value is string => long(value, MOST_URL) && value !== '';

/** A binding asked for, checked as 0.14.7's route checked it before asking anything: its shape, its profile's rules, its policy but for `reads`. */
type Checked = {
  binding: CheckedBinding;
  /** The address of its keys, as the app found them; null for keys uploaded, whose address is their digest. */
  uri: string | null;
  jwks: unknown;
  /** Its policy, but for `reads`; null for a binding a CI run's exchange takes. */
  rules: BindingPolicy | null;
  reads: ReadAsked[];
  scope: Wanted[] | null;
  label: string | null;
  replaces: string[];
};

/** What `checkBinding`, `checkPolicy` and a profile's rule say of the binding asked, or undefined for one they refuse. */
function bindingAsked(given: NewBinding, member: string, useOnly: boolean): Checked | undefined {
  if (typeof given !== 'object' || given === null || typeof given.profile !== 'string' || !(given.issuer === null || url(given.issuer))
    || typeof given.claims !== 'object' || given.claims === null || Array.isArray(given.claims)
    || typeof given.keys !== 'object' || given.keys === null) return undefined;
  const uploaded = Object.hasOwn(given.keys, 'jwks');
  const uri = uploaded ? null : (given.keys as { uri: unknown }).uri;
  if (!uploaded && !url(uri)) return undefined;
  if (!(given.policy === null || (typeof given.policy === 'object' && !Array.isArray(given.policy)))) return undefined;
  const scope = given.scope === null ? null : scopeAsked(given.scope);
  if (scope === undefined || !(given.label === null || labelled(given.label))) return undefined;
  const replaces = Array.isArray(given.replaces) ? [...given.replaces] : undefined;
  if (replaces === undefined || replaces.length > MAX_BINDINGS || !replaces.every((id) => text(id) && UUID.test(id)) || new Set(replaces).size !== replaces.length) return undefined;
  try {
    // The vault fetches nothing: whether coffre may fetch the issuer, loopback included, is the app's, which discovered its keys.
    const binding = checkBinding({ profile: given.profile, issuer: given.issuer, claims: { ...given.claims } }, { allowLoopback: true, uploaded });
    // A URN profile's keys are no address: its issuer, which keeps one key source per issuer.
    if (uri !== null && Object.hasOwn(PROFILE_URNS, binding.profile) && uri !== binding.issuer) return undefined;
    let rules: BindingPolicy | null = null;
    let reads: ReadAsked[] = [];
    // A workload's binding: every one but a bearer binding with no policy, which a CI run's exchange takes; none under `useOnly`.
    if (!isBearerProfile(binding.profile) || given.policy !== null || useOnly) {
      const { reads: listed, ...rest } = { ...(given.policy ?? {}) } as Record<string, unknown>;
      rules = checkPolicy(binding.profile, rest, { service: member });
      PROFILE_RULES[binding.profile]?.binding(binding, rules);
      if (listed !== undefined) {
        const asked = readsAsked(listed);
        if (asked === undefined) return undefined;
        reads = asked;
      }
    }
    return { binding, uri: uri as string | null, jwks: uploaded ? (given.keys as { jwks: unknown }).jwks : null, rules, reads, scope, label: given.label, replaces };
  } catch (error) {
    if (error instanceof BindingInvalid) return undefined;
    throw error;
  }
}

/** A binding's scope as its row seals it, or none for one that does not read as a scope: it reaches nothing, and passes nothing on. */
function scopeOf(row: Row<typeof bindings>): ScopeGrant[] {
  if (row.scope === null) return [];
  try {
    const scope: unknown = JSON.parse(row.scope);
    return isCredentialScope(scope) ? [...scope] : [];
  } catch {
    return [];
  }
}

/**
 * Trust a workload as a service, or give its bindings on an issuer new keys
 * (`TokenBind`; docs/design/0.16.md, "A workload signing in"). 0.14.7's
 * `bind` and `replaceKeys`, on the vault's rows: the caller and who
 * manages the service (`token.create`'s, `serviceParts`), its live
 * bindings, the places the scope and the reads name, and the keys the
 * reads list. One statement writes the bindings made and revokes those
 * they replace, which ends what those issued, with one kept entry.
 *
 * Who binds, and what a binding reaches, is `token.create`'s rule for a
 * service's token, with nothing of the vault's own: the caller manages the
 * service, and each grant is one they could give it and it holds
 * (`issuesCredential`), its sensitive values only an Owner's to give. The
 * scope is always sealed on the row, never null: what was asked; or what
 * the bindings it replaces reached, each grant no more than it held and
 * the service still holds (`narrowest`), so that trusting a workload again
 * never widens it; or all the service holds.
 *
 * Rows hidden from the read: one that is not the vault's refuses,
 * `tampered`, wherever it is. One taken away for the decision and put back
 * after is `token.create`'s case: a grant of the service's hidden while a
 * Developer of dev binds, and the binding reaches dev, its sealed scope,
 * and never prod once the grant is back. A live binding hidden is one this
 * one neither replaces nor counts: it stays live as it was, and a replace
 * that names it is refused.
 */
function tokenBind(input: Presented & TokenBind, vault: Deciding): Operation<Parts, Answers['token.bind'], UploadedKeys | 'invalid' | null> {
  const shown = presented(input);
  const { member } = input;
  const asked = Object.hasOwn(input, 'binding') ? bindingAsked((input as { binding: NewBinding }).binding, member, vault.workloads?.useOnly === true) : undefined;
  const rekeyed = Object.hasOwn(input, 'keys') ? (input as { keys: { issuer: unknown; jwks: unknown } }).keys : undefined;
  if (!(text(member) && SERVICE.test(member))
    || (Object.hasOwn(input, 'binding') === Object.hasOwn(input, 'keys'))
    || (rekeyed === undefined ? asked === undefined : typeof rekeyed !== 'object' || rekeyed === null || !url(rekeyed.issuer))) {
    throw new TypeError("a binding is made for a service account (token:<name>) of a profile, an issuer, its claims, its keys' address or the keys, a policy or none, a scope or none, a label or none and the bindings it replaces; or a service's bindings on an issuer are given new keys");
  }
  // Keys uploaded, which `check` reads as `uploadedKeys` does: a change of keys's always, a binding's unless it names their address.
  const uploads = rekeyed !== undefined || asked!.uri === null;
  const jwks = rekeyed !== undefined ? rekeyed.jwks : asked!.jwks;
  // Drawn here: a decision draws nothing. One for each binding a change of keys may make, the most a service holds.
  const ids = Array.from({ length: rekeyed === undefined ? 1 : MAX_BINDINGS }, () => randomUUID());

  const wanted = asked?.scope ?? [];
  const reads = asked?.reads ?? [];
  const slugs = [...new Set([...wanted.map((place) => place.project), ...reads.map((read) => read.project)])];
  const pairs = [...wanted.flatMap((place) => (place.environment === null ? [] : [place as { project: string; environment: string }])), ...reads];
  const named = sql`(SELECT p.id FROM projects p WHERE p.slug = ANY(${sql.param(slugs)}::text[]))`;
  // Each project and environment pair through the two unique keys, so each is an index lookup.
  const onEnvironments = sql`(SELECT e.id FROM unnest(${sql.param(pairs.map((place) => place.project))}::text[], ${sql.param(pairs.map((place) => place.environment))}::text[]) AS a(project, environment) JOIN projects p ON p.slug = a.project JOIN environments e ON e.project_id = p.id AND e.slug = a.environment)`;
  // Each key a read lists, by its environment's path and its name: the secrets' unique key, (project, environment, key).
  const listed = reads.flatMap((read) => (read.keys === '*' ? [] : read.keys.map((key) => ({ ...read, key }))));
  const onKeys = sql`(SELECT s.id FROM unnest(${sql.param(listed.map((read) => read.project))}::text[], ${sql.param(listed.map((read) => read.environment))}::text[], ${sql.param(listed.map((read) => read.key))}::text[]) AS a(project, environment, key)
    JOIN projects p ON p.slug = a.project JOIN environments e ON e.project_id = p.id AND e.slug = a.environment JOIN secrets s ON s.project_id = p.id AND s.environment_id = e.id AND s.key = a.key)`;
  const read = {
    // The caller's grants and roles in every project the binding would reach, and the environments protected there.
    ...callerParts(shown.token, sql`(${named} UNION ${projectsOf(member)})`),
    project: part(projects, sql`${projects.slug} = ANY(${sql.param(slugs)}::text[])`),
    environment: part(environments, sql`${environments.id} IN ${onEnvironments}`),
    // The roles the scope asked names, and those its live bindings' scopes name, which a replacement or new keys inherit: read as text, a role's id being plain (`ROLE_ID`).
    asked: part(roles, sql`NOT ${roles.instance} AND (${roles.id} = ANY(${sql.param([...new Set(wanted.map((place) => place.role))])}::text[])
      OR ${roles.id} IN (SELECT m.found[1] FROM bindings b, regexp_matches(b.scope, '"role":"([a-z][a-z0-9-]{1,31})"', 'g') AS m(found) WHERE b.principal = ${member} AND b.revoked_at IS NULL
        AND b.generation = (SELECT p.generation FROM principals p WHERE p.id = ${member})))`),
    ...serviceParts(member),
    // The projects of the service's grants, by which the answer names the places it holds; `beside`, their environments.
    holding: part(projects, sql`${projects.id} IN ${projectsOf(member)}`),
    // Its live bindings in its generation, oldest first: one past the most it holds, to see there are more.
    live: part(bindings, sql`${bindings.id} IN (SELECT b.id FROM bindings b WHERE b.principal = ${member} AND b.revoked_at IS NULL
      AND b.generation = (SELECT p.generation FROM principals p WHERE p.id = ${member}) ORDER BY b.created_at, b.id LIMIT ${MAX_BINDINGS + 1})`),
    keys: part(secrets, sql`${secrets.id} IN ${onKeys}`),
  };
  type Read = Seen<typeof read>;

  return {
    read,
    denied: refusedTo('token.bind', shown, vault.workloads, { objects: (seen: Read) => seen.account.map((row) => `principal:${row.id}`) }),
    async check() {
      if (!uploads) return null;
      try {
        return await uploadedKeys(jwks);
      } catch (error) {
        if (error instanceof KeysInvalid) return 'invalid';
        throw error;
      }
    },
    decide(seen: Read, at: number, unsealed: Unsealed<typeof read>, keys: UploadedKeys | 'invalid' | null) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      // A row written behind the vault is not a row that is absent, wherever it is: a grant less, a binding less, a key's nature.
      if (Object.values(unsealed).some((count) => count > 0)) return { refused: 'tampered' };
      const manager = manages(caller, seen, unsealed, member, at);
      if (manager !== true) return manager === 'tampered' ? { refused: 'tampered' } : NO_ACCESS;
      const account = serviceOf(seen, member, at);
      if (account === null) return { refused: 'unknown_principal' };
      if (keys === 'invalid') return INVALID;
      const row = seen.account.find((other) => other.id === member)!;
      if (seen.live.length > MAX_BINDINGS) return { refused: 'too_many_bindings' };
      // Oldest first, as an exchange tries them: a read's rows come in no order.
      const live = seen.live.filter((binding) => binding.principal === member && binding.generation === row.generation && binding.revokedAt === null)
        .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : 1));
      const holder = caller.holds;
      const policy: Policy = { ...holder.policy, roles: { ...definitionsOf(seen.heldAs), ...definitionsOf(seen.asked), ...holder.policy.roles } };
      const issuer: Holdings & { policy: Policy } = { ...holder, policy };
      const setting = settingOf(seen);
      // What the service holds now, as a use weighs it: the column a service holds wherever it reaches.
      const holds: Holdings = { ...NOTHING, policy, service: true, grants: account.grants.map(({ role, place }) => ({ projectId: place.projectId, environmentId: place.environmentId ?? null, role })) };

      /** A place by its id, as the rows read have it, with its path: one deleted, or not read, is none. */
      const found = (grant: { projectId: string | null; environmentId?: string | null }): { place: Place; path: string } | undefined => {
        const project = [...seen.holding, ...seen.project].find((other) => other.id === grant.projectId);
        if (project === undefined || project.slug.includes('~')) return undefined;
        if (grant.environmentId == null) return { place: { projectId: project.id }, path: project.slug };
        const environment = [...seen.beside, ...seen.environment].find((other) => other.id === grant.environmentId && other.projectId === project.id);
        if (environment === undefined || environment.slug.includes('~')) return undefined;
        return { place: { projectId: project.id, environmentId: environment.id, environmentSlug: environment.slug }, path: `${project.slug}/${environment.slug}` };
      };
      /** A place asked by slug, as the rows read have it. */
      const placeOf = (project: string, environment: string | null) => {
        const there = seen.project.find((other) => other.slug === project);
        if (there === undefined) return undefined;
        if (environment === null) return { place: { projectId: there.id } as Place, path: there.slug };
        const at = seen.environment.find((other) => other.projectId === there.id && other.slug === environment);
        return at && { place: { projectId: there.id, environmentId: at.id, environmentSlug: at.slug } as Place, path: `${there.slug}/${at.slug}`, owner: at.owner };
      };
      /** A grant as the service is given it now: its role as the policy has it, and the sensitive values where the caller owns the project. */
      const anew = (role: string, place: Place): ScopeGrant => ({
        ...issuedGrant({ projectId: place.projectId, environmentId: place.environmentId ?? null, role }, policy),
        sensitive: ownsProject(issuer, place.projectId),
      });
      /**
       * What the bindings replaced reached, each place once, as the role is
       * now and no more than it held (`narrowest`), where the service still
       * holds all of that: a place deleted, or what it lost, drops out.
       * Undefined for two that reach a place with different roles.
       */
      const inherited = (replaced: readonly Row<typeof bindings>[]): { grant: ScopeGrant; path: string; place: Place }[] | undefined => {
        const byPlace = new Map<string, ScopeGrant>();
        for (const grant of replaced.flatMap(scopeOf)) {
          const key = `${grant.projectId}/${grant.environmentId ?? ''}`;
          const before = byPlace.get(key);
          if (before !== undefined && before.role !== grant.role) return undefined;
          byPlace.set(key, before === undefined ? grant : narrowest(grant, before));
        }
        return [...byPlace.values()].flatMap((was) => {
          const there = found(was);
          if (there === undefined) return [];
          const grant = narrowest(anew(was.role, there.place), was);
          const { permissions } = scopeDefinition(grant);
          return permissions.length > 0 && permissions.every((permission) => allows(holds, permission, there.place)) ? [{ grant, ...there }] : [];
        });
      };
      /** Whether the caller gives each grant, as it will be kept, and the service holds all of it (`issuesCredential`). */
      const gives = (scope: readonly { grant: ScopeGrant; place: Place }[]) =>
        issuesCredential(issuer, setting, caller.principal, account, scope.map(({ grant, place }) => ({ role: grant.role, place, kept: scopeDefinition(grant) })));
      /** A grant's place by path, as the answer names it. */
      const byPath = (scope: readonly ScopeGrant[]) => Object.fromEntries(scope.map((grant) => [found(grant)?.path ?? grant.environmentId ?? grant.projectId, grant.role]).sort(([a], [b]) => (a! < b! ? -1 : 1)));
      const now = new Date(at);
      const revoked = (old: Row<typeof bindings>) => amended(bindings, old, { revokedAt: now, revokedBy: caller.principal });
      const objects = (scope: readonly ScopeGrant[]) => scope.map((grant) => (grant.environmentId === null ? `project:${grant.projectId}` : `environment:${grant.environmentId}`));

      if (rekeyed !== undefined) {
        // New keys for its bindings on an issuer, uploaded: each binding replaced by one the same but for its keys.
        const uploaded = keys as UploadedKeys;
        const jwksUri = `${CARRIED}${uploaded.digest}`;
        const on = live.filter((binding) => binding.issuer === rekeyed.issuer);
        if (on.length === 0) return { refused: 'unknown_binding' };
        if (on.every((binding) => binding.jwksUri === jwksUri)) return { refused: 'same_keys' };
        const made: { id: string; scope: ScopeGrant[]; replaces: string }[] = [];
        const writes: Write[] = [];
        for (const [i, old] of on.entries()) {
          // Each still a binding that carries its keys: a URN profile's carries none.
          try {
            checkBinding({ profile: old.profile, issuer: old.issuer, claims: JSON.parse(old.claims) as BindingClaims }, { uploaded: true });
          } catch (error) {
            if (error instanceof BindingInvalid || error instanceof SyntaxError) return INVALID;
            throw error;
          }
          // Each reaches what the one it replaces did, of what the service still holds: new keys never widen a binding.
          const scope = inherited([old]);
          if (scope === undefined || scope.length === 0) return INVALID;
          if (!gives(scope)) return NO_ACCESS;
          const sealed = sealedScope(scope);
          const id = ids[i]!;
          // A millisecond apart, in the order of those they replace: an exchange tries bindings oldest first, and still does.
          writes.push(put(bindings, {
            id, principal: member, generation: row.generation, profile: old.profile, issuer: old.issuer, jwksUri, jwks: uploaded.jwks, claims: old.claims,
            scope: JSON.stringify(sealed), policy: old.policy, label: old.label, createdAt: new Date(at + i), createdBy: caller.principal,
            lastUsedAt: null, frozenAt: null, revokedAt: null, revokedBy: null,
          }), revoked(old));
          made.push({ id, scope: sealed, replaces: old.id });
        }
        return {
          writes,
          entry: {
            ...by(caller, shown),
            kept: true,
            action: 'token.bind',
            objects: [...new Set([`principal:${caller.principal}`, `credential:${caller.credential.id}`, `principal:${member}`, ...made.flatMap((binding) => [`binding:${binding.id}`, `binding:${binding.replaces}`]), ...made.flatMap((binding) => objects(binding.scope))])],
            detail: { principal: member, reason: 'keys_replaced', issuer: rekeyed.issuer, jwksUri, keys: uploaded.keys, bindings: made.map(({ id, scope, replaces }) => ({ binding: id, scope, replaces: [replaces] })) },
          },
          answer: { bindings: made.map(({ id, scope }) => ({ id, scope: byPath(scope) })), replaced: made.map((binding) => binding.replaces) },
        };
      }

      const { binding, uri, label } = asked!;
      let { rules } = asked!;
      const uploaded = keys as UploadedKeys | null;
      const jwksUri = uploaded === null ? uri! : `${CARRIED}${uploaded.digest}`;
      // What it replaces: those asked, each a live binding of the service's; and its issuer's whose keys are elsewhere.
      if (!asked!.replaces.every((id) => live.some((other) => other.id === id))) return { refused: 'unknown_binding' };
      const replaces = live.flatMap((other): { row: Row<typeof bindings>; why: 'asked' | 'keys_moved' }[] => {
        if (asked!.replaces.includes(other.id)) return [{ row: other, why: 'asked' }];
        return other.issuer === binding.issuer && other.jwksUri !== jwksUri ? [{ row: other, why: 'keys_moved' }] : [];
      });
      // Keys uploaded, on either side, are no move of the issuer's: the bindings that would go are still good.
      if (replaces.some(({ row: other, why }) => why === 'keys_moved' && (other.jwksUri.startsWith(CARRIED) || jwksUri.startsWith(CARRIED)))) return { refused: 'keys_differ' };
      if (live.length - replaces.length + 1 > MAX_BINDINGS) return { refused: 'too_many_bindings' };
      if (reads.length > 0 && vault.workloads?.noReads === true) return { refused: 'no_reads' };

      let scope: { grant: ScopeGrant; path: string; place: Place }[];
      if (asked!.scope !== null) {
        if (!wanted.every(({ role, environment }) => definitionOf(policy, role) !== undefined && (environment === null || assignableToEnvironment(role, policy)))) return INVALID;
        const places = wanted.map(({ project, environment, role }) => ({ role, at: placeOf(project, environment) }));
        if (places.some(({ at: there }) => there === undefined)) return NO_ACCESS;
        scope = places.map(({ role, at: there }) => ({ grant: anew(role, there!.place), path: there!.path, place: there!.place }));
      } else if (replaces.length > 0) {
        // Left out, its scope is what those it replaces reached, so that trusting a workload again never widens it.
        const kept = inherited(replaces.map(({ row: other }) => other));
        if (kept === undefined || kept.length === 0) return INVALID;
        scope = kept;
      } else {
        scope = account.grants.flatMap(({ role, place }) => {
          const there = found({ projectId: place.projectId, environmentId: place.environmentId ?? null });
          return there === undefined ? [] : [{ grant: anew(role, there.place), ...there }];
        });
      }
      // Nothing it is given later reaches a binding made before: it needs a grant first.
      if (scope.length === 0) return { refused: 'no_grants' };
      if (!gives(scope)) return NO_ACCESS;
      let grants = scope.map(({ grant }) => grant);

      if (reads.length > 0) {
        // Each environment by path, as it is now, and each key it lists by name: one of its own, with a value (a reference has none, `secrets_source_check`), not archived.
        const byId: Record<string, { keys: string[] | '*' }> = {};
        const projectOf = new Map<string, string>();
        for (const listing of reads) {
          const there = placeOf(listing.project, listing.environment);
          if (there === undefined || there.owner !== null) return NO_ACCESS;
          const environmentId = there.place.environmentId!;
          // A read is of an environment the binding's scope reaches.
          const covering = grants.find((grant) => grant.environmentId === environmentId) ?? grants.find((grant) => grant.environmentId === null && grant.projectId === there.place.projectId);
          if (covering === undefined) return INVALID;
          if (listing.keys !== '*') {
            const rows = listing.keys.map((key) => seen.keys.find((secret) => secret.environmentId === environmentId && secret.key === key));
            if (rows.some((secret) => secret === undefined || secret.archivedAt !== null || secret.currentVersion === null)) return INVALID;
            // A sensitive value only where an Owner of its project binds it (R32), as a service's token reads it.
            if (rows.some((secret) => secret!.nature === 'sensitive') && covering.sensitive !== true) return { refused: 'not_owner_issued' };
            byId[environmentId] = { keys: rows.map((secret) => secret!.id).sort() };
          } else {
            byId[environmentId] = { keys: '*' };
          }
          projectOf.set(environmentId, there.place.projectId);
        }
        try {
          rules = checkPolicy(binding.profile, { ...rules, reads: byId }, { service: member });
        } catch (error) {
          if (error instanceof BindingInvalid) return INVALID;
          throw error;
        }
        // Each listed environment a grant of its own, the project's share there where only the project's reached it; the lists are each request's.
        grants = scopeWithReads(grants, rules.reads, projectOf).map(({ reads: _, ...grant }) => grant);
      }
      const sealed = sealedScope(grants.map((grant) => ({ grant, path: '' })));
      const id = ids[0]!;
      return {
        writes: [
          put(bindings, {
            id, principal: member, generation: row.generation, profile: binding.profile, issuer: binding.issuer, jwksUri, jwks: uploaded?.jwks ?? null,
            claims: canonicalClaims(binding.claims), scope: JSON.stringify(sealed), policy: rules === null ? null : policyText(rules), label,
            createdAt: now, createdBy: caller.principal, lastUsedAt: null, frozenAt: null, revokedAt: null, revokedBy: null,
          }),
          ...replaces.map(({ row: other }) => revoked(other)),
        ],
        entry: {
          ...by(caller, shown),
          kept: true,
          action: 'token.bind',
          objects: [...new Set([`principal:${caller.principal}`, `credential:${caller.credential.id}`, `principal:${member}`, `binding:${id}`, ...replaces.map(({ row: other }) => `binding:${other.id}`), ...objects(sealed)])],
          detail: {
            binding: id, principal: member, profile: binding.profile, issuer: binding.issuer, jwksUri, ...(uploaded === null ? {} : { keys: uploaded.keys }),
            claims: binding.claims, scope: sealed, ...(rules === null ? {} : { policy: rules }), replaces: replaces.map(({ row: other, why }) => ({ binding: other.id, why })),
          },
        },
        answer: { bindings: [{ id, scope: byPath(sealed) }], replaced: replaces.map(({ row: other }) => other.id) },
      };
    },
  };
}

/**
 * Remove a binding (`TokenUnbind`): whoever manages its service, as 0.14.7's
 * `unbind`. Its row is revoked, which ends what it issued: a credential a
 * binding issued stands only while the binding does (caller.ts).
 *
 * Rows hidden from the read: the binding, and it is not found; who manages
 * the service, `credential.end`'s case (signin.ts): one written behind the
 * vault refuses, `tampered`, and one deleted for the decision lets the
 * caller remove a binding they would not have, which a row deleted behind
 * the vault removes as well.
 */
function tokenUnbind(input: Presented & TokenUnbind, vault: Deciding): Operation<Parts, Answers['token.unbind']> {
  const shown = presented(input);
  const { member, binding: id } = input;
  if (!(text(member) && SERVICE.test(member)) || !(text(id) && UUID.test(id))) throw new TypeError('a binding is removed by its service account (token:<name>) and its id');
  const read = {
    ...callerParts(shown.token, projectsOf(member)),
    ...serviceParts(member),
    binding: part(bindings, sql`${bindings.id} = ${id}::uuid`),
  };
  type Read = Seen<typeof read>;
  return {
    read,
    denied: refusedTo('token.unbind', shown, vault.workloads, { objects: () => [`principal:${member}`, `binding:${id}`] }),
    decide(seen: Read, at: number, unsealed: Unsealed<typeof read>) {
      const caller = asking(seen, shown, vault, at);
      if ('refused' in caller) return caller;
      if (Object.values(unsealed).some((count) => count > 0)) return { refused: 'tampered' };
      const manager = manages(caller, seen, unsealed, member, at);
      if (manager !== true) return manager === 'tampered' ? { refused: 'tampered' } : NO_ACCESS;
      const [row] = seen.binding;
      const account = seen.account.find((other) => other.id === member);
      // One of another service's, revoked, or of a generation before the service was last removed, is no live binding of its.
      if (row === undefined || row.principal !== member || row.revokedAt !== null || (account !== undefined && row.generation !== account.generation)) return { refused: 'unknown_binding' };
      return {
        writes: [amended(bindings, row, { revokedAt: new Date(at), revokedBy: caller.principal })],
        entry: {
          ...by(caller, shown),
          kept: true,
          action: 'token.unbind',
          objects: [`principal:${caller.principal}`, `credential:${caller.credential.id}`, `principal:${member}`, `binding:${id}`],
          detail: { binding: id, principal: member, reason: 'removed' },
        },
        answer: { binding: id },
      };
    },
  };
}

/** The changes of trust bindings (docs/design/0.16.md, "A workload signing in"). */
export const bindingOperations: Operations<TokenBind | TokenUnbind> = { 'token.bind': tokenBind, 'token.unbind': tokenUnbind };
