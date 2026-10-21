import type { CoffreClient, ConnectedApp, IdentityRow, MissingKey, OffboardingReport, SecretKey, SessionRow, TokenRow } from '@coffre/client';
import { EVERYWHERE, unscoped, type InstanceRole, type Role, type Scope } from '@coffre/core/access';
import type { QueryKey } from '@tanstack/react-query';

import { failureMessage, memberRef, Refusal } from './coffre.ts';
import { projectAccessLabel } from './project-access.ts';
import type { Change, ListShape, Target, Words } from './optimistic.ts';
import { affects, keys } from './queries.ts';
import { regenerateWrite, type Generation } from '@coffre/core/recipe';
import { regeneratedKeys, renamePairs } from './recipes.ts';
import { applySecretEditBatch, companionsOf, generationsOf, levelsOf, type SecretChange, type SecretDraft, type SecretEditBatchResult } from './secret-edit-batch.ts';
import type { DirectoryPrincipal, GrantRow, ProjectSummary } from '../shared/models.ts';

/**
 * Every change the pages make before the server answers, one per kind, each
 * with the list it shows in (`lib/optimistic.ts`). Issuing a token is not
 * here: only the server can show what it issued.
 */

type Failure = { ok: false; error: string };

/** A list held in a read's `field`, when the read answered. */
function listOf<TItem, TData extends { ok: boolean } | null>(
  queryKey: QueryKey,
  field: string,
  id: (item: TItem) => string,
): ListShape<TData, TItem> {
  return {
    queryKey,
    items: (data) => (data?.ok === true ? ((data as unknown as Record<string, TItem[]>)[field] ?? []) : []),
    withItems: (data, items) => (data?.ok === true ? { ...data, [field]: items } : data),
    id,
  };
}

const ARCHIVING: Words = { pending: 'Archiving…', done: 'archived', failed: 'Not archived.' };
const REVOKING: Words = { pending: 'Revoking…', done: 'revoked', failed: 'Not revoked.' };
const DISCONNECTING: Words = { pending: 'Disconnecting…', done: 'disconnected', failed: 'Not disconnected.' };
const MOVING: Words = { pending: 'Moving…', done: 'moved', failed: 'Not moved.' };
const REGENERATING: Words = { pending: 'Regenerating…', done: 'regenerated', failed: 'Not regenerated.' };

const saving = (id: string): Target => ({ id, kind: 'saving' });
const removing = (id: string): Target => ({ id, kind: 'removing' });

// --- access --------------------------------------------------------------------

type Grants = ({ ok: true; grants: GrantRow[] } | Failure);

/** A grant's identity, before the server has given it an id: who, and where; or who, by their instance role. */
export function grantId(grant: Pick<GrantRow, 'principalType' | 'principalId' | 'environmentSlug'> & { scope?: GrantRow['scope'] }): string {
  const member = memberRef(grant.principalType, grant.principalId);
  return grant.scope === 'instance-role' ? `${member}#role` : `${member}@${grant.environmentSlug ?? ''}`;
}

export function grantsList(project: string) {
  return listOf<GrantRow, Grants>(keys.grants(project), 'grants', grantId);
}

/** Where a grant applies, as the API names it: `market`, or `market/prod`. */
export function grantPlace(project: string, environmentSlug: string | null): string {
  return environmentSlug === null ? project : `${project}/${environmentSlug}`;
}

export type GrantVars = {
  principalType: GrantRow['principalType'];
  principalId: string;
  role: string;
  /** How the role is shown while it saves. */
  roleName: string;
  environmentSlug: string | null;
  expiresAt: string | null;
  /** A new service account, which the grant makes in the same call: refused, neither is made. */
  admit?: boolean;
};

/**
 * Give someone a role at one place. Access is declarative, so asking for what
 * they already hold is not an error, whoever asked first: `existed` says so.
 */
export function grantAccess(client: CoffreClient, project: string): Change<Grants, GrantRow, GrantVars, { existed: boolean }> {
  const list = grantsList(project);
  return {
    list,
    label: (vars) => `${projectAccessLabel(vars)} for ${vars.principalId}`,
    targets: (vars) => [saving(grantId(vars))],
    apply: (grants, vars) => {
      const row: GrantRow = {
        id: `pending:${grantId(vars)}`,
        principalType: vars.principalType,
        principalId: vars.principalId,
        role: vars.role,
        roleName: vars.roleName,
        permissions: [],
        scope: vars.environmentSlug === null ? 'project' : 'environment',
        environmentSlug: vars.environmentSlug,
        expiresAt: vars.expiresAt,
      };
      const id = grantId(vars);
      return grants.some((grant) => grantId(grant) === id)
        ? grants.map((grant) => (grantId(grant) === id ? { ...row, id: grant.id } : grant))
        : [...grants, row];
    },
    affects: (vars) => [
      ...affects.access(project, memberRef(vars.principalType, vars.principalId)),
      ...(vars.admit === true ? affects.admission(memberRef(vars.principalType, vars.principalId)) : []),
    ],
    run: async (vars) => {
      const place = grantPlace(project, vars.environmentSlug);
      const role = vars.role;
      const member = memberRef(vars.principalType, vars.principalId);
      const access = { [place]: vars.expiresAt === null ? role : { role, until: vars.expiresAt } };
      const { changes } = vars.admit === true ? await client.members.add(member, { access }) : await client.access.set(member, access);
      return { existed: changes?.[place] === 'unchanged' };
    },
  };
}

export function revokeGrant(client: CoffreClient, project: string): Change<Grants, GrantRow, GrantRow, unknown> {
  return {
    list: grantsList(project),
    label: (grant) => `${projectAccessLabel(grant)} for ${grant.principalId}`,
    targets: (grant) => [removing(grantId(grant))],
    removing: REVOKING,
    affects: (grant) => affects.access(project, memberRef(grant.principalType, grant.principalId)),
    run: (grant) =>
      client.access.set(memberRef(grant.principalType, grant.principalId), {
        [grantPlace(project, grant.environmentSlug)]: null,
      }),
  };
}

// --- the directory -------------------------------------------------------------

type Directory = ({ ok: true; principals: DirectoryPrincipal[] } | Failure);

const principalId = (principal: Pick<DirectoryPrincipal, 'principalType' | 'principalId'>) =>
  memberRef(principal.principalType, principal.principalId);

/** The directory as admins and owners read it: the only ones who change it. */
export const directoryList = listOf<DirectoryPrincipal, Directory>([...keys.directory, { owner: true }], 'principals', principalId);

/** A person's instance role and where it applies, projects by slug: what Add and Change role set. */
export type RoleVars = { role: InstanceRole; scope: Scope };

export type InviteVars = { principalType: DirectoryPrincipal['principalType']; principalId: string } & RoleVars;

/** What the API takes for a role: the scope only when it narrows anything. */
function roleInput({ role, scope }: RoleVars): RoleVars | { role: InstanceRole } {
  return role === 'member' || unscoped(scope) ? { role } : { role, scope };
}

export function invite(client: CoffreClient): Change<Directory, DirectoryPrincipal, InviteVars, void> {
  return {
    list: directoryList,
    label: (vars) => vars.principalId,
    targets: (vars) => [saving(principalId(vars))],
    // Someone already listed is not added twice: the server will say they exist.
    apply: (principals, vars) =>
      principals.some((principal) => principalId(principal) === principalId(vars)) ? principals : [
      ...principals,
      {
        principalType: vars.principalType,
        principalId: vars.principalId,
        instanceRole: vars.principalType === 'user' ? vars.role : 'member',
        scope: vars.principalType === 'user' ? vars.scope : EVERYWHERE,
      },
    ],
    affects: (vars) => affects.admission(principalId(vars)),
    run: async (vars) => {
      // Adding is an idempotent PUT that would also set the role of someone
      // already here; this is only for someone new.
      const member = memberRef(vars.principalType, vars.principalId);
      const { members } = await client.members.list();
      if (members.some((entry) => entry.member === member)) throw new Refusal('That principal already exists.');
      await client.members.add(member, vars.principalType === 'user' ? roleInput(vars) : {});
    },
  };
}

export function changeRole(client: CoffreClient): Change<Directory, DirectoryPrincipal, { principalId: string } & RoleVars, unknown> {
  const id = (vars: { principalId: string }) => memberRef('user', vars.principalId);
  return {
    list: directoryList,
    label: (vars) => `the role of ${vars.principalId}`,
    targets: (vars) => [saving(id(vars))],
    apply: (principals, vars) =>
      principals.map((principal) =>
        principalId(principal) === id(vars) ? { ...principal, instanceRole: vars.role, scope: vars.scope } : principal,
      ),
    affects: (vars) => affects.role(id(vars)),
    run: (vars) => client.members.add(id(vars), roleInput(vars)),
  };
}

export function removeMember(client: CoffreClient): Change<Directory, DirectoryPrincipal, DirectoryPrincipal, unknown> {
  return {
    list: directoryList,
    label: (principal) => principal.principalId,
    targets: (principal) => [removing(principalId(principal))],
    affects: (principal) => affects.removal(principalId(principal)),
    run: (principal) => client.members.remove(principalId(principal)),
  };
}

// --- credentials, sessions, linked accounts --------------------------------------

type Credentials = ({ ok: true; tokens: TokenRow[] } | Failure) | null;

/** Revoking a member's token: a service account's bearer token, on its page, or a personal token of your own, on your account. */
export function revokeCredential(client: CoffreClient, member: string): Change<Credentials, TokenRow, TokenRow, unknown> {
  return {
    list: listOf<TokenRow, Credentials>([...keys.credentials(member), { allowed: true }], 'tokens', (token) => token.id),
    label: (token) => `token ${token.hint}`,
    targets: (token) => [removing(token.id)],
    removing: REVOKING,
    affects: () => affects.credentials(member),
    run: (token) => client.tokens.revoke(member, token.id),
  };
}

type Binding = { id: string; label: string | null };
type Bindings = ({ ok: true; bindings: Binding[] } | Failure) | null;

/** Removing a trust binding: its tombstone, as far as the page goes, is the row leaving. */
export function removeBinding(client: CoffreClient, serviceId: string): Change<Bindings, Binding, Binding, unknown> {
  const member = memberRef('service', serviceId);
  return {
    list: listOf<Binding, Bindings>([...keys.bindings(member), { allowed: true }], 'bindings', (binding) => binding.id),
    label: (binding) => (binding.label === null ? 'the binding' : `binding ${binding.label}`),
    targets: (binding) => [removing(binding.id)],
    removing: { pending: 'Removing…', done: 'removed', failed: 'Not removed.' },
    affects: () => affects.bindings(member),
    run: (binding) => client.bindings.remove(member, binding.id),
  };
}

type Sessions = ({ ok: true; sessions: SessionRow[] } | Failure);

export function endSession(client: CoffreClient): Change<Sessions, SessionRow, SessionRow, unknown> {
  return {
    list: listOf<SessionRow, Sessions>(keys.sessions, 'sessions', (session) => session.id),
    label: () => 'the session',
    targets: (session) => [removing(session.id)],
    removing: { pending: 'Ending…', done: 'ended', failed: 'Not ended.' },
    affects: () => affects.sessions(),
    run: (session) => client.sessions.revoke(session.id),
  };
}

type Apps = ({ ok: true; apps: ConnectedApp[] } | Failure);

export function disconnectApp(client: CoffreClient): Change<Apps, ConnectedApp, ConnectedApp, unknown> {
  return {
    list: listOf<ConnectedApp, Apps>(keys.apps, 'apps', (app) => app.id),
    label: (app) => app.name,
    targets: (app) => [removing(app.id)],
    removing: DISCONNECTING,
    affects: () => affects.apps(),
    run: (app) => client.apps.disconnect(app.id),
  };
}

type Report = { ok: true; report: OffboardingReport | null } | Failure | null;

/** Whoever runs the instance revoking someone's personal token, on their page: their report lists it, as they read it. */
export function revokeMemberToken(client: CoffreClient, member: string): Change<Report, TokenRow, TokenRow, unknown> {
  return {
    list: {
      queryKey: [...keys.report(member), { owner: true }],
      items: (data) => (data?.ok === true ? (data.report?.personalTokens ?? []) : []),
      withItems: (data, personalTokens) => (data?.ok === true && data.report !== null ? { ...data, report: { ...data.report, personalTokens } } : data),
      id: (token) => token.id,
    },
    label: (token) => `token ${token.hint}`,
    targets: (token) => [removing(token.id)],
    removing: REVOKING,
    // Their report counts what removing them would end; the list on their account is theirs to read again.
    affects: () => [keys.report(member), keys.credentials(member)],
    run: (token) => client.tokens.revoke(member, token.id),
  };
}

/** An owner disconnecting someone's app, on their page: their report lists it, as the owner reads it. */
export function disconnectMemberApp(client: CoffreClient, member: string): Change<Report, ConnectedApp, ConnectedApp, unknown> {
  return {
    list: {
      queryKey: [...keys.report(member), { owner: true }],
      items: (data) => (data?.ok === true ? (data.report?.apps ?? []) : []),
      withItems: (data, apps) => (data?.ok === true && data.report !== null ? { ...data, report: { ...data.report, apps } } : data),
      id: (app) => app.id,
    },
    label: (app) => app.name,
    targets: (app) => [removing(app.id)],
    removing: DISCONNECTING,
    // Their report counts what removing them would end; an owner's own apps may be among them.
    affects: () => [keys.report(member), ...affects.apps()],
    run: (app) => client.apps.disconnect(app.id),
  };
}

type Identities = ({ ok: true; identities: IdentityRow[] } | Failure);

export function unlinkIdentity(client: CoffreClient): Change<Identities, IdentityRow, IdentityRow & { label: string }, unknown> {
  return {
    list: listOf<IdentityRow, Identities>(keys.identities, 'identities', (identity) => identity.id),
    label: (identity) => `the ${identity.label} account`,
    targets: (identity) => [removing(identity.id)],
    removing: { pending: 'Unlinking…', done: 'unlinked', failed: 'Not unlinked.' },
    affects: () => affects.identities(),
    run: (identity) => client.identities.unlink(identity.id),
  };
}

// --- projects and environments ---------------------------------------------------

type Projects = ({ ok: true; projects: ProjectSummary[] } | Failure);

export const projectsList = listOf<ProjectSummary, Projects>(keys.projects, 'projects', (project) => project.slug);

export function createProject(client: CoffreClient): Change<Projects, ProjectSummary, { slug: string }, void> {
  return {
    list: projectsList,
    label: (vars) => `project ${vars.slug}`,
    targets: (vars) => [saving(vars.slug)],
    apply: (projects, vars) => [
      ...projects,
      {
        slug: vars.slug,
        name: vars.slug,
        archivedAt: null,
        folder: null,
        // Its maker manages it by their instance role, an Admin's or an Owner's.
        permissions: ['audit.read', 'environment.manage', 'grant.manage', 'project.manage'],
        environments: [],
        secretCount: null,
      },
    ],
    affects: () => affects.places(),
    run: async (vars) => {
      // Creating is an idempotent PUT; a slug that is taken is refused here.
      const { created } = await client.projects.create(vars.slug);
      if (!created) throw new Refusal(`A project named "${vars.slug}" already exists.`);
    },
  };
}

type Environment = ProjectSummary['environments'][number];

/** One project's environments, held in the project list. */
/** File a project in a folder, or in none: shown at once, under its new heading. */
export function moveProject(client: CoffreClient): Change<Projects, ProjectSummary, { slug: string; folder: string | null }, unknown> {
  return {
    list: projectsList,
    label: (vars) => `project ${vars.slug}`,
    targets: (vars) => [saving(vars.slug)],
    apply: (projects, vars) => projects.map((project) => (project.slug === vars.slug ? { ...project, folder: vars.folder } : project)),
    affects: () => affects.places(),
    run: (vars) => client.projects.update(vars.slug, { folder: vars.folder }),
  };
}

export function environmentsList(project: string): ListShape<Projects, Environment> {
  const environmentsOf = (data: Projects) =>
    data.ok ? (data.projects.find((entry) => entry.slug === project)?.environments ?? []) : [];
  return {
    queryKey: keys.projects,
    items: environmentsOf,
    withItems: (data, environments) =>
      data.ok
        ? { ...data, projects: data.projects.map((entry) => (entry.slug === project ? { ...entry, environments } : entry)) }
        : data,
    // Under the project's name: the projects list, in the same read, uses bare slugs.
    id: (environment) => environmentId(project, environment.slug),
  };
}

export function environmentId(project: string, environment: string): string {
  return `${project}/${environment}`;
}

/** A new environment, empty or, `from` a sibling, forked: each of its keys copied. */
export function createEnvironment(client: CoffreClient, project: string): Change<Projects, Environment, { slug: string; from?: string; references?: boolean; inherit?: boolean }, void> {
  return {
    list: environmentsList(project),
    label: (vars) => `environment ${vars.slug}`,
    targets: (vars) => [saving(environmentId(project, vars.slug))],
    apply: (environments, vars) => [
      ...environments,
      {
        slug: vars.slug,
        name: vars.slug,
        accessible: false,
        parent: vars.inherit === true ? (vars.from ?? null) : null,
        // A fork of a protected environment, however made, is protected from its first moment.
        protected: vars.from !== undefined && environments.some((environment) => environment.slug === vars.from && environment.protected),
        personal: false,
        details: { archivedAt: null, secretCount: 0 },
      },
    ],
    affects: () => affects.places(),
    run: async (vars) => {
      const { created } = await client.environments.create(`${project}/${vars.slug}`, {
        ...(vars.from === undefined ? {} : { from: vars.from }),
        ...(vars.references === true ? { references: true } : {}),
        ...(vars.inherit === true ? { inherit: true } : {}),
      });
      if (!created) throw new Refusal(`An environment named "${vars.slug}" already exists.`);
    },
  };
}

export type RenameVars = { from: string; slug: string };

export function renameEnvironment(client: CoffreClient, project: string): Change<Projects, Environment, RenameVars, unknown> {
  return {
    list: environmentsList(project),
    label: (vars) => `environment ${vars.from}`,
    targets: (vars) =>
      vars.slug === vars.from
        ? [saving(environmentId(project, vars.from))]
        : [saving(environmentId(project, vars.from)), saving(environmentId(project, vars.slug))],
    apply: (environments, vars) =>
      environments.map((environment) =>
        environment.slug === vars.from ? { ...environment, slug: vars.slug } : environment,
      ),
    affects: () => affects.places(),
    run: (vars) => client.environments.update(`${project}/${vars.from}`, { slug: vars.slug }),
  };
}

/**
 * Protect an environment, or take its protection off (docs/design/roles.md):
 * shown at once, on its card and its page, which say if the server
 * refuses. Only an Owner of the whole instance unprotects one, which the
 * page offers to them alone. What everyone holds there changes, so the
 * roles' readers are refetched too.
 */
export function protectEnvironment(client: CoffreClient, project: string): Change<Projects, Environment, { slug: string; protected: boolean }, unknown> {
  return {
    list: environmentsList(project),
    label: (vars) => `environment ${vars.slug}`,
    targets: (vars) => [saving(environmentId(project, vars.slug))],
    apply: (environments, vars) =>
      environments.map((environment) => (environment.slug === vars.slug ? { ...environment, protected: vars.protected } : environment)),
    affects: () => [...affects.places(), ...affects.roles()],
    run: (vars) => client.environments.protect(`${project}/${vars.slug}`, vars.protected),
  };
}

/**
 * Archive an environment or bring it back. Archiving ends every read of it,
 * so it waits for the server, as a removal does; restoring shows at once.
 */
export function archiveEnvironment(client: CoffreClient, project: string): Change<Projects, Environment, { slug: string; archived: boolean }, unknown> {
  const archivedAt = (archived: boolean) => (archived ? new Date().toISOString() : null);
  const withArchived = (environment: Environment, archived: boolean): Environment =>
    environment.details === null
      ? environment
      : { ...environment, details: { ...environment.details, archivedAt: archivedAt(archived) } };
  return {
    list: environmentsList(project),
    label: (vars) => `environment ${vars.slug}`,
    targets: (vars) => [
      vars.archived ? removing(environmentId(project, vars.slug)) : saving(environmentId(project, vars.slug)),
    ],
    removing: ARCHIVING,
    apply: (environments, vars) =>
      vars.archived
        ? environments
        : environments.map((environment) => (environment.slug === vars.slug ? withArchived(environment, false) : environment)),
    confirmed: (environments, _vars, archived) =>
      environments.map((environment) =>
        archived.has(environmentId(project, environment.slug)) ? withArchived(environment, true) : environment,
      ),
    affects: () => affects.places(),
    run: (vars) => client.environments.update(`${project}/${vars.slug}`, { archived: vars.archived }),
  };
}

// --- secrets ---------------------------------------------------------------------

type Secrets = ({ ok: true; keys: SecretKey[] } | Failure);

export function secretsList(place: { project: string; environment: string }) {
  return listOf<SecretKey, Secrets>(keys.secrets(place), 'keys', (entry) => entry.key);
}

/** A save that stopped partway: what is left to retry, as the ledger holds it. */
export class UnsavedEdits extends Refusal {
  readonly outcome: SecretEditBatchResult;

  constructor(outcome: SecretEditBatchResult) {
    const message = outcome.error instanceof Error ? outcome.error.message : failureMessage(outcome.error);
    // Only renames can have landed before a failure: the patch is all or nothing.
    super(
      outcome.applied === 0
        ? message
        : `${message} The renames before it were saved; nothing else was, and the rest is ready to retry.`,
    );
    this.outcome = outcome;
  }
}

export type SaveSecretsVars = {
  active: SecretKey[];
  drafts: SecretDraft[];
  changes: Record<string, SecretChange>;
};

/**
 * Write the ledger's pending edits, as `applySecretEditBatch` does: renames
 * one by one, then the rest as one patch that lands whole or not at all.
 * New and edited secrets show at once; archived ones stay, struck through,
 * until the server confirms.
 */
export function saveSecrets(
  client: CoffreClient,
  place: { project: string; environment: string },
  /** Who is saving, shown as the author until the list is read back. */
  author: string | null,
): Change<Secrets, SecretKey, SaveSecretsVars, number> {
  const path = `${place.project}/${place.environment}`;
  const edits = (vars: SaveSecretsVars) =>
    vars.active.flatMap((entry) => {
      const change = vars.changes[entry.key];
      return change === undefined ? [] : [{ entry, change }];
    });
  // A key pair's public key lands as a new row would, beside its private key.
  const written = (vars: SaveSecretsVars) => [...vars.drafts, ...companionsOf(vars.active, vars.drafts, vars.changes)];
  return {
    list: secretsList(place),
    label: (vars) => {
      const named = [...vars.drafts.map((draft) => draft.key.trim()), ...edits(vars).map(({ entry }) => entry.key)];
      return named.length === 1 ? named[0]! : `${named.length} changes`;
    },
    targets: (vars) => [
      ...written(vars).map((draft) => saving(draft.key.trim())),
      ...edits(vars).flatMap(({ entry, change }) =>
        change.archived
          ? [removing(entry.key)]
          : change.key.trim() === entry.key
            ? [saving(entry.key)]
            : [saving(entry.key), saving(change.key.trim())],
      ),
    ],
    removing: ARCHIVING,
    apply: (entries, vars) => {
      const now = new Date().toISOString();
      // A value typed by hand has no recipe; a generated one has the one it was made by. A plain one shows as it is.
      const generations = generationsOf(vars.active, vars.drafts, vars.changes);
      const levels = levelsOf(vars.active, vars.drafts, vars.changes);
      const bumped = (entry: SecretKey | undefined, key: string): SecretKey => {
        // In a fork, a value written over the parent's is an override, whose own version the list read back says.
        const inherited = entry?.parent != null && entry.parent.state !== 'overridden' && entry.key === key;
        const level = levels.get(key);
        return {
          key,
          // A rename keeps its folder; a new secret is in none.
          folder: entry?.folder ?? null,
          // A value of its own: no longer a reference.
          reference: null,
          archived: false,
          version: inherited ? null : (entry?.version ?? 0) + 1,
          // Known once the list is read back: until then, nothing regenerates it.
          versionId: null,
          updatedAt: now,
          updatedBy: author,
          generated: generations.get(key) ?? null,
          value: level?.value ?? null,
          sensitivity: level?.sensitivity ?? 'secret',
          // Until the list is read back: a plain value as it is listed, a secret over one its writer read here, and nothing else.
          readable: level?.value != null
            || ((level?.sensitivity ?? 'secret') === 'secret' && !inherited && entry?.sensitivity === 'secret' && entry.readable),
          parent: entry?.parent == null || entry.key !== key ? null : { ...entry.parent, state: 'overridden', changed: false, reset: false },
        };
      };
      const renames = new Map<string, string>();
      let next = entries.map((entry) => {
        const change = vars.changes[entry.key];
        if (change === undefined || change.archived) return entry;
        const key = change.key.trim();
        if (key !== entry.key) renames.set(entry.key, key);
        if (change.value !== null) return bumped(entry, key);
        // A mark: the same value, as a new version, stricter, so a plain one no longer listed, nor read until the list says so.
        return change.sensitivity === undefined
          ? { ...entry, key }
          : { ...entry, key, version: (entry.version ?? 0) + 1, versionId: null, updatedAt: now, updatedBy: author, value: null, sensitivity: change.sensitivity, readable: false };
      });
      // A rename moves no value: a pair it touches names the new key, in both halves.
      next = renamePairs(next, renames);
      for (const draft of written(vars)) {
        const key = draft.key.trim();
        const existing = next.find((entry) => entry.key === key);
        next = existing === undefined ? [bumped(undefined, key), ...next] : next.map((entry) => (entry.key === key ? bumped(entry, key) : entry));
      }
      return next;
    },
    confirmed: (entries, _vars, archived) =>
      entries.map((entry) => (archived.has(entry.key) ? { ...entry, archived: true } : entry)),
    affects: () => affects.secrets(place),
    run: async (vars) => {
      const outcome = await applySecretEditBatch({
        active: vars.active,
        drafts: vars.drafts,
        changes: vars.changes,
        operations: {
          rename: async (key, nextKey) => {
            try {
              await client.secrets.rename(`${path}/${key}`, nextKey);
            } catch (error) {
              // A refused rename names the key it stopped at.
              throw new Refusal(`${key}: ${failureMessage(error)}`);
            }
          },
          write: async (patch) => {
            try {
              await client.secrets.set(path, patch);
            } catch (error) {
              throw new Refusal(failureMessage(error));
            }
          },
        },
      });
      if (outcome.error !== null) throw new UnsavedEdits(outcome);
      return outcome.applied;
    },
  };
}

/** File a secret in a folder, or in none: shown at once, under its new heading. */
export function moveSecret(
  client: CoffreClient,
  place: { project: string; environment: string },
): Change<Secrets, SecretKey, { key: string; folder: string | null }, unknown> {
  return {
    list: secretsList(place),
    saving: MOVING,
    label: (vars) => vars.key,
    targets: (vars) => [saving(vars.key)],
    apply: (entries, vars) => entries.map((entry) => (entry.key === vars.key ? { ...entry, folder: vars.folder } : entry)),
    affects: () => affects.secrets(place),
    run: (vars) => client.secrets.update(`${place.project}/${place.environment}/${vars.key}`, { folder: vars.folder }),
  };
}

/** What Regenerate is asked: the key, its recipe, and the version id of each key it writes, as listed. */
export type RegenerateVars = { key: string; generated: Generation; versions: Readonly<Record<string, string>> };

/**
 * Regenerate a key by its recipe: the value made in this browser as the
 * change runs, and sent at once, never on the page. Each key it writes, a
 * key pair's two halves, shows it pending, so neither is edited, renamed
 * or regenerated again until it lands. The server holds it to the versions
 * listed, which settles a race with any other write.
 */
export function regenerateSecret(
  client: CoffreClient,
  place: { project: string; environment: string },
  /** Who is regenerating, shown as the author until the list is read back. */
  author: string | null,
): Change<Secrets, SecretKey, RegenerateVars, unknown> {
  const path = `${place.project}/${place.environment}`;
  return {
    list: secretsList(place),
    saving: REGENERATING,
    label: (vars) => regeneratedKeys(vars.key, vars.generated).join(' and '),
    targets: (vars) => regeneratedKeys(vars.key, vars.generated).map(saving),
    apply: (entries, vars) => {
      const keys = new Set(regeneratedKeys(vars.key, vars.generated));
      const now = new Date().toISOString();
      return entries.map((entry) => {
        if (!keys.has(entry.key)) return entry;
        // In a fork, regenerating a key it inherits writes an override here, never the parent:
        // its own version is the one the list read back says.
        const inherited = entry.parent != null && entry.parent.state !== 'overridden';
        return {
          ...entry,
          reference: null,
          version: inherited ? null : (entry.version ?? 0) + 1,
          versionId: null,
          updatedAt: now,
          updatedBy: author,
          generated: vars.generated,
          // A generated value is a secret, and sensitive where the key is.
          value: null,
          sensitivity: entry.sensitivity === 'sensitive' ? 'sensitive' : 'secret',
          parent: entry.parent == null ? null : { ...entry.parent, state: 'overridden', changed: false, reset: false },
        };
      });
    },
    affects: () => affects.secrets(place),
    // Each key replaces the version the page listed, or the server refuses the write.
    run: async (vars) => client.secrets.set(path, await regenerateWrite(vars.key, vars.generated, (key) => (Object.hasOwn(vars.versions, key) ? vars.versions[key]! : null))),
  };
}

/** Restore an archived secret, from the Archived list. */
export function restoreSecret(
  client: CoffreClient,
  place: { project: string; environment: string },
): Change<Secrets, SecretKey, { key: string }, unknown> {
  return {
    list: secretsList(place),
    label: (vars) => vars.key,
    targets: (vars) => [saving(vars.key)],
    apply: (entries, vars) => entries.map((entry) => (entry.key === vars.key ? { ...entry, archived: false } : entry)),
    affects: () => affects.secrets(place),
    run: (vars) => client.secrets.update(`${place.project}/${place.environment}/${vars.key}`, { archived: false }),
  };
}

/** Archive one secret, as Undo after a restore does: it stays, struck through, until confirmed. */
export function archiveSecret(
  client: CoffreClient,
  place: { project: string; environment: string },
): Change<Secrets, SecretKey, { key: string }, unknown> {
  return {
    list: secretsList(place),
    label: (vars) => vars.key,
    targets: (vars) => [removing(vars.key)],
    removing: ARCHIVING,
    confirmed: (entries, _vars, archived) =>
      entries.map((entry) => (archived.has(entry.key) ? { ...entry, archived: true } : entry)),
    affects: () => affects.secrets(place),
    run: (vars) => client.secrets.update(`${place.project}/${place.environment}/${vars.key}`, { archived: true }),
  };
}

/**
 * In a fork, a key's standing to its parent's (docs/design/forking.md):
 * `remove` does without the parent's key and `restore` inherits it again,
 * a dismissal and its end; `reset` drops an override for the parent's
 * value, its own kept, and `override` serves its own again. Each shows at
 * once, and is undone by its opposite.
 */
export type ForkAction = 'remove' | 'restore' | 'reset' | 'override';

const FORK_WORDS: Record<ForkAction, Words> = {
  remove: { pending: 'Removing…', done: 'removed', failed: 'Not removed.' },
  restore: { pending: 'Restoring…', done: 'restored', failed: 'Not restored.' },
  reset: { pending: 'Resetting…', done: 'reset', failed: 'Not reset.' },
  override: { pending: 'Overriding…', done: 'overridden', failed: 'Not overridden.' },
};

export function forkKey(
  client: CoffreClient,
  place: { project: string; environment: string },
  action: ForkAction,
): Change<Secrets, SecretKey, { key: string }, unknown> {
  const path = `${place.project}/${place.environment}`;
  const standing = (entry: SecretKey): SecretKey => {
    if (entry.parent === null) return entry;
    switch (action) {
      // Not served: nothing of the parent's value is shown for it.
      case 'remove':
        return { ...entry, reference: null, version: null, updatedAt: null, updatedBy: null, parent: { ...entry.parent, state: 'removed' } };
      // The parent's value, which the list read back brings.
      case 'restore':
      case 'reset':
        return { ...entry, parent: { ...entry.parent, state: 'inherited', changed: false, reset: action === 'reset' || entry.parent.reset } };
      case 'override':
        return { ...entry, parent: { ...entry.parent, state: 'overridden', changed: false, reset: false } };
    }
  };
  return {
    list: secretsList(place),
    saving: FORK_WORDS[action],
    label: (vars) => vars.key,
    targets: (vars) => [saving(vars.key)],
    // A removal of a key the parent archived since, restored, leaves nothing to list.
    apply: (entries, vars) => entries.flatMap((entry) =>
      entry.key !== vars.key ? [entry] : action === 'restore' && entry.parent?.held === false ? [] : [standing(entry)]),
    affects: () => affects.secrets(place),
    run: (vars) =>
      action === 'remove' || action === 'restore'
        ? client.environments.dismiss(path, { [vars.key]: action === 'remove' ? true : null })
        : client.secrets.inherit(`${path}/${vars.key}`, action === 'reset'),
  };
}

// --- missing keys ----------------------------------------------------------------

type Missing = ({ ok: true; missing: MissingKey[] } | Failure);

export function missingList(place: { project: string; environment: string }) {
  return listOf<MissingKey, Missing>(keys.missing(place), 'missing', (entry) => entry.key);
}

const DISMISSING: Words = { pending: 'Dismissing…', done: 'dismissed', failed: 'Not dismissed.' };
const RESTORING: Words = { pending: 'Restoring…', done: 'restored', failed: 'Not restored.' };

/**
 * Dismiss missing keys for the whole team. It shows at once: a dismissal
 * hides nothing anyone may read, so it need not wait for the server, and a
 * refusal puts the keys back.
 */
export function dismissMissing(client: CoffreClient, place: { project: string; environment: string }) {
  return missingChange(client, place, true);
}

/** Bring dismissed keys back, as Undo after a dismissal does: listed again at once. */
export function restoreMissing(client: CoffreClient, place: { project: string; environment: string }) {
  return missingChange(client, place, false);
}

function missingChange(
  client: CoffreClient,
  place: { project: string; environment: string },
  dismissed: boolean,
): Change<Missing, MissingKey, MissingKey[], unknown> {
  return {
    list: missingList(place),
    saving: dismissed ? DISMISSING : RESTORING,
    label: (entries) => (entries.length === 1 ? entries[0]!.key : `${entries.length} missing keys`),
    targets: (entries) => entries.map((entry) => saving(entry.key)),
    apply: (entries, named) => {
      const names = new Set(named.map((entry) => entry.key));
      const others = entries.filter((entry) => !names.has(entry.key));
      // Listed by name, as the server lists them.
      return dismissed ? others : [...others, ...named].sort((a, b) => (a.key < b.key ? -1 : 1));
    },
    affects: () => [],
    run: (entries) =>
      client.environments.dismiss(
        `${place.project}/${place.environment}`,
        Object.fromEntries(entries.map((entry) => [entry.key, dismissed ? true : null])),
      ),
  };
}
