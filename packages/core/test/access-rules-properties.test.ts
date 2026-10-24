import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import {
  allows,
  definitionProblem,
  givesService,
  heldColumns,
  issuedGrant,
  issuesCredential,
  isCredentialScope,
  mayManageAccess,
  normalDefinition,
  ownsProject,
  readsSensitive,
  runsInstance,
  type CredentialScope,
  type Holdings,
  type Place,
  type Policy,
  type RoleDefinition,
} from '../src/access.ts';
import * as domain from '../../../scripts/properties/domain.ts';
import { propertySettings } from './properties.ts';

// Random policies, protected environments and credentials against the
// domain model's reading of docs/design/roles.md. The model is
// scripts/properties/domain.ts's tables and the few lines below, never
// access.ts's helpers.

/** The policy as core takes it, from the model's. */
function corePolicy(projects: readonly domain.Project[], policy: domain.Policy): Policy {
  const definitions = <K extends string>(roles: Readonly<Record<K, domain.Columns>>) =>
    Object.fromEntries(Object.entries<domain.Columns>(roles).map(([name, held]) => [name, { name, description: '', permissions: held.permissions, protected: held.protected }])) as Record<K, RoleDefinition>;
  return {
    roles: definitions(policy.roles),
    instanceRoles: definitions(policy.instanceRoles),
    protected: policy.protected,
    protectedIn: Object.fromEntries(projects.map((project) => [project.id, project.environments
      .filter((environment) => policy.protected.includes(environment.id))
      .map((environment) => ({ environmentId: environment.id, slug: environment.slug }))])),
  };
}

const placeOf = ({ projectId, environmentId, slug }: ReturnType<typeof domain.placesOf>[number]): Place =>
  environmentId === null ? { projectId } : { projectId, environmentId, environmentSlug: slug };

/** A grant's place, named as checks name it. */
function grantPlace(projects: readonly domain.Project[], grant: domain.Grant): Place {
  if (grant.environmentId === null) return { projectId: grant.projectId };
  const environment = projects.flatMap((project) => project.environments).find((each) => each.id === grant.environmentId)!;
  return { projectId: grant.projectId, environmentId: environment.id, environmentSlug: environment.slug };
}

function admits(filter: domain.Filter, value: string | null): boolean {
  if (filter === 'all') return true;
  if (value === null) return false;
  return 'only' in filter ? filter.only.includes(value) : !filter.except.includes(value);
}

/** A project as a whole is in a scope only when the scope keeps all its environments. */
function modelInScope(scope: domain.Scope, place: Place): boolean {
  if (!admits(scope.projects, place.projectId)) return false;
  return place.environmentId == null ? scope.environments === 'all' : admits(scope.environments, place.environmentSlug);
}

/**
 * The model's holder: a person (their instance role and scope count, and
 * a protected environment's column is theirs there) or a service account
 * (grants alone, the normal column everywhere), and the credential the
 * request came in on, each of its grants with the columns it kept.
 */
type ModelHolder = {
  policy: domain.Policy;
  role: domain.InstanceRole;
  scope: domain.Scope;
  grants: readonly domain.Grant[];
  service: boolean;
  credential?: readonly { grant: domain.Grant; kept: domain.Columns }[];
};

function modelAllows(holder: ModelHolder, permission: domain.Permission, place: Place): boolean {
  const guarded = !holder.service && place.environmentId != null && holder.policy.protected.includes(place.environmentId);
  const column = (held: domain.Columns | undefined) => held !== undefined
    && (domain.PROJECT_ONLY.includes(permission) ? held.permissions : guarded ? held.protected : held.permissions).includes(permission);
  const covers = (grant: domain.Grant) => grant.projectId === place.projectId && (grant.environmentId === null || grant.environmentId === place.environmentId);
  if (holder.credential !== undefined && !holder.credential.some(({ grant, kept }) => covers(grant) && column(kept))) return false;
  if (!holder.service && modelInScope(holder.scope, place) && column(holder.policy.instanceRoles[holder.role])) return true;
  return holder.grants.some((grant) => covers(grant) && column(holder.policy.roles[grant.role]));
}

function holdings(projects: readonly domain.Project[], holder: ModelHolder): Holdings {
  const policy = corePolicy(projects, holder.policy);
  const credentialScope: CredentialScope | undefined = holder.credential?.map(({ grant, kept }) => ({
    ...grant, permissions: { normal: kept.permissions, protected: kept.protected },
  }));
  return holder.service
    ? { role: 'member', scope: { projects: 'all', environments: 'all' }, grants: holder.grants, policy, service: true, credentialScope }
    : { role: holder.role, scope: holder.scope, grants: holder.grants, policy, credentialScope };
}

/** A world's projects, a policy over their environments, and a person and a service account under it. */
const setting = gs.composite((tc) => {
  const projects = tc.draw(domain.projects({ maxEnvironments: 4 }));
  const environmentIds = projects.flatMap((project) => project.environments.map((environment) => environment.id));
  const policy = tc.draw(domain.policy(environmentIds));
  const person = { principal: 'user:ada@acme.example', policy, role: tc.draw(gs.sampledFrom(domain.INSTANCE_ROLE_NAMES)), scope: tc.draw(domain.scope(projects.map((project) => project.id))), grants: tc.draw(domain.grants(projects, policy.roles)), service: false };
  // A service account often holds some of what the person does, which is what lets them manage it.
  const serviceGrants = tc.draw(gs.booleans()) ? person.grants.filter(() => tc.draw(gs.booleans())) : tc.draw(domain.grants(projects, policy.roles));
  const service = { policy, role: 'member' as const, scope: { projects: 'all' as const, environments: 'all' as const }, grants: serviceGrants, service: true };
  return { projects, policy, person, service, places: domain.placesOf(projects).map(placeOf) };
});

const settings = propertySettings(200);

test(`every permission at every place matches the model, under any policy, protection and credential, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { projects, person, service, places } = tc.draw(setting);
  for (const holder of [person, service]) {
    const credential = tc.draw(gs.booleans())
      ? tc.draw(domain.grants(projects, holder.policy.roles)).map((grant) => ({ grant, kept: tc.draw(domain.columns) }))
      : undefined;
    const model: ModelHolder = { ...holder, credential };
    const core = holdings(projects, model);
    for (const place of places) {
      for (const permission of domain.PERMISSIONS) {
        assert.equal(allows(core, permission, place), modelAllows(model, permission, place), JSON.stringify({ model, permission, place }));
      }
      assert.equal(mayManageAccess(core, place), modelAllows(model, 'grant.manage', place));
    }
  }
}, settings));

test(`protecting an environment never widens what a person holds anywhere, and changes nothing for a service account, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { projects, policy, person, service, places } = tc.draw(setting);
  const environments = projects.flatMap((project) => project.environments);
  const more = { ...policy, protected: [...new Set([...policy.protected, tc.draw(gs.sampledFrom(environments)).id])] };
  for (const place of places) {
    for (const permission of domain.PERMISSIONS) {
      if (allows(holdings(projects, { ...person, policy: more }), permission, place)) {
        assert.ok(allows(holdings(projects, person), permission, place), JSON.stringify({ person, more: more.protected, permission, place }));
      }
      assert.equal(allows(holdings(projects, { ...service, policy: more }), permission, place), allows(holdings(projects, service), permission, place));
    }
  }
}, settings));

test(`losing a grant or narrowing a scope never widens anything, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { projects, person, places } = tc.draw(setting);
  const ids = projects.map((project) => project.id);
  const fewer = { ...person, grants: person.grants.filter(() => tc.draw(gs.booleans())) };
  // A scope narrowed: `only` keeps fewer, `except` names more, `all` becomes either.
  const narrow = (filter: domain.Filter, values: readonly string[]): domain.Filter => {
    if (filter === 'all') return tc.draw(gs.booleans()) ? { except: [tc.draw(gs.sampledFrom(values))] } : { only: values.filter(() => tc.draw(gs.booleans())) };
    if ('only' in filter) return { only: filter.only.filter(() => tc.draw(gs.booleans())) };
    return { except: [...new Set([...filter.except, tc.draw(gs.sampledFrom(values))])] };
  };
  const slugs = [...new Set(projects.flatMap((project) => project.environments.map((environment) => environment.slug)))];
  const narrower = { ...person, scope: { projects: narrow(person.scope.projects, ids), environments: tc.draw(gs.booleans()) ? narrow(person.scope.environments, slugs) : person.scope.environments } };
  for (const smaller of [fewer, narrower]) {
    for (const place of places) {
      for (const permission of domain.PERMISSIONS) {
        if (allows(holdings(projects, smaller), permission, place)) assert.ok(allows(holdings(projects, person), permission, place), JSON.stringify({ person, smaller, permission, place }));
      }
    }
  }
}, settings));

/**
 * R15: a personal token keeps what its role held when it was issued, no
 * more than its person held there, column by column (`issuedGrant`,
 * `heldColumns`). Later, the roles edited, the environments protected or
 * not, the person given more or less: a request on it holds no more than
 * the person holds now, and no more than they held at issue in the column
 * the place uses now.
 */
test(`a personal token never holds more than its person now, nor more than they held when they issued it, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { projects, person: issuer, places } = tc.draw(setting);
  const environmentIds = projects.flatMap((project) => project.environments.map((environment) => environment.id));
  const atIssue = holdings(projects, issuer);
  const wanted = tc.draw(domain.grants(projects, issuer.policy.roles, 3));
  const scope = wanted.map((grant) => issuedGrant(grant, atIssue.policy, heldColumns(atIssue, grantPlace(projects, grant))));
  assert.ok(isCredentialScope(JSON.parse(JSON.stringify(scope))), JSON.stringify(scope));
  // Later: a new policy over the same places, the person changed or not.
  const later = tc.draw(domain.policy(environmentIds));
  const now = tc.draw(gs.booleans())
    ? { ...issuer, policy: later }
    : { ...issuer, policy: later, role: tc.draw(gs.sampledFrom(domain.INSTANCE_ROLE_NAMES)), grants: tc.draw(domain.grants(projects, later.roles)) };
  const current = holdings(projects, now);
  for (const place of places) {
    // The column the place uses now: was the person's, at issue, in that column.
    const guardedNow = place.environmentId != null && later.protected.includes(place.environmentId);
    const then = holdings(projects, { ...issuer, policy: { ...issuer.policy, protected: guardedNow ? [place.environmentId!] : [] } });
    for (const permission of domain.PERMISSIONS) {
      if (!allows({ ...current, credentialScope: scope }, permission, place)) continue;
      const context = JSON.stringify({ issuer, wanted, scope, now, permission, place });
      assert.ok(allows(current, permission, place), `beyond the person now: ${context}`);
      assert.ok(allows(then, permission, place), `beyond what they held at issue: ${context}`);
    }
  }
}, settings));

test(`a service token holds no more than its account now and its role when it was issued, whatever the role becomes, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { projects, policy, service, places } = tc.draw(setting);
  const environmentIds = projects.flatMap((project) => project.environments.map((environment) => environment.id));
  const scope = service.grants.filter(() => tc.draw(gs.booleans())).map((grant) => issuedGrant(grant, corePolicy(projects, policy)));
  const later = tc.draw(domain.policy(environmentIds));
  const account = { ...service, policy: later, grants: tc.draw(gs.booleans()) ? service.grants : tc.draw(domain.grants(projects, later.roles)) };
  const current = holdings(projects, account);
  for (const place of places) {
    for (const permission of domain.PERMISSIONS) {
      if (!allows({ ...current, credentialScope: scope }, permission, place)) continue;
      const context = JSON.stringify({ service, scope, account, permission, place });
      assert.ok(allows(current, permission, place), `beyond the account now: ${context}`);
      const held = scope.some((grant) => grant.projectId === place.projectId && (grant.environmentId === null || grant.environmentId === place.environmentId)
        && policy.roles[grant.role]!.permissions.includes(permission));
      assert.ok(held, `beyond its role at issue: ${context}`);
    }
  }
}, settings));

/**
 * A person sets up a service account with what they hold, never more: a
 * service account holds a role's normal column even in a protected
 * environment, so a person who gives one a role, without managing access
 * there, holds every permission it gives at each place it reaches, in the
 * column they hold there themselves. Those who manage access give anything:
 * that is their role.
 */
test(`a person who does not manage access gives a service account nothing they do not hold, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { projects, policy, person: drawn, places } = tc.draw(setting);
  const person = { ...drawn, grants: drawn.grants.length > 0 ? drawn.grants : [tc.draw(domain.grant(projects, policy.roles))] };
  const giver = holdings(projects, person);
  const setting_ = tc.draw(gs.oneOf(gs.just({ projects: 'all', environments: 'all' } as domain.Scope), domain.scope(projects.map((project) => project.id))));
  // Mostly where the person holds a grant, a role holding no more than theirs there, which is what they may give.
  const fits = (held: domain.Grant) => Object.keys(policy.roles).filter((role) => {
    const { permissions } = policy.roles[role]!;
    return (held.environmentId === null || !permissions.some((permission) => domain.PROJECT_ONLY.includes(permission)))
      && permissions.every((permission) => policy.roles[held.role]!.permissions.includes(permission));
  });
  const given = person.grants.length > 0 && tc.draw(gs.integers({ minValue: 0, maxValue: 3 })) > 0
    ? tc.draw(gs.sampledFrom(person.grants).flatMap((held) => gs.sampledFrom([held.role, ...fits(held)]).map((role) => ({ ...held, role }))))
    : tc.draw(domain.grant(projects, policy.roles));
  const at = grantPlace(projects, given);
  if (!givesService(giver, setting_, given.role, at) || mayManageAccess(giver, at)) return;
  const account = holdings(projects, { policy, role: 'member', scope: { projects: 'all', environments: 'all' }, grants: [given], service: true });
  for (const place of places) {
    for (const permission of domain.PERMISSIONS) {
      if (allows(account, permission, place)) assert.ok(allows(giver, permission, place), JSON.stringify({ person, given, permission, place, protected: policy.protected }));
    }
  }
}, settings));

test(`a service credential its issuer may issue reaches nothing its account lacks, nor anything its issuer lacks unless they manage access there, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { projects, policy, person, service, places } = tc.draw(setting);
  const issuer = holdings(projects, person);
  const account = { grants: service.grants.map((grant) => ({ role: grant.role, place: grantPlace(projects, grant) })), admittedBy: null };
  // Mostly what the account holds, which is all a credential for it may name; never nothing, which reaches nothing.
  const held = service.grants.filter(() => tc.draw(gs.booleans()));
  const named = held.length > 0 && tc.draw(gs.booleans()) ? held : [tc.draw(domain.grant(projects, policy.roles)), ...tc.draw(domain.grants(projects, policy.roles, 2))];
  const wanted = [...new Map(named.map((grant) => [`${grant.projectId}/${grant.environmentId ?? ''}`, grant])).values()]
    .map((grant) => ({ role: grant.role, place: grantPlace(projects, grant) }));
  const everywhere = { projects: 'all' as const, environments: 'all' as const };
  if (!issuesCredential(issuer, everywhere, person.principal, account, wanted)) return;
  const core = corePolicy(projects, policy);
  const scope = wanted.map(({ role, place }) => issuedGrant({ projectId: place.projectId, environmentId: place.environmentId ?? null, role }, core));
  const through = { ...holdings(projects, service), credentialScope: scope };
  for (const place of places) {
    for (const permission of domain.PERMISSIONS) {
      if (!allows(through, permission, place)) continue;
      assert.ok(allows(holdings(projects, service), permission, place));
      // Past what the issuer holds only through a grant of the scope given where they manage access, which gives anything.
      const reaching = wanted.filter((grant) => grant.place.projectId === place.projectId && (grant.place.environmentId == null || grant.place.environmentId === place.environmentId));
      if (!runsInstance(issuer) && !reaching.some((grant) => mayManageAccess(issuer, grant.place))) {
        assert.ok(allows(issuer, permission, place), JSON.stringify({ person, wanted, permission, place, protected: policy.protected }));
      }
    }
  }
}, settings));

/**
 * R30, R32: an Owner of a project, as a person on no credential, reads and
 * does anything in it but its sensitive values, which no person reads: an
 * instance Owner whose scope takes the project in whole, or one by a grant
 * on the project. An Owner of every `prod`, or one's token, owns no project.
 */
test(`who owns a project matches the model, holds everything there, and only a service credential reads sensitive values, seed ${settings.seed}`, () => hegel.test((tc) => {
  const { projects, person, service, places } = tc.draw(setting);
  const credential = tc.draw(gs.booleans()) ? tc.draw(domain.grants(projects, person.policy.roles)).map((grant) => ({ grant, kept: tc.draw(domain.columns) })) : undefined;
  const core = holdings(projects, { ...person, credential });
  for (const project of projects) {
    const model = credential === undefined && (
      (person.role === 'owner' && modelInScope(person.scope, { projectId: project.id }))
      || person.grants.some((grant) => grant.role === 'owner' && grant.projectId === project.id && grant.environmentId === null));
    assert.equal(ownsProject(core, project.id), model, JSON.stringify({ person, credential, project: project.id }));
    if (model) {
      for (const place of places.filter((each) => each.projectId === project.id)) {
        for (const permission of domain.PERMISSIONS) assert.ok(allows(core, permission, place), JSON.stringify({ person, permission, place }));
      }
    }
    assert.equal(readsSensitive(core, project.id), false, 'a person reads no sensitive value, Owners included');
    const flags = service.grants.map((grant) => ({ ...grant, sensitive: tc.draw(gs.booleans()) }));
    const through = { ...holdings(projects, service), credentialScope: flags };
    assert.equal(readsSensitive(through, project.id), flags.some((grant) => grant.sensitive && grant.projectId === project.id));
    assert.equal(readsSensitive(holdings(projects, service), project.id), false, 'a service account reads sensitive values on an Owner-issued credential alone');
    assert.equal(ownsProject(through, project.id), false);
  }
}, settings));

test(`a role an Owner may write passes the definition check and is its own normal form; one broken any way does not pass, seed ${settings.seed}`, () => hegel.test((tc) => {
  const held = tc.draw(domain.columns);
  const definition: RoleDefinition = { name: tc.draw(gs.sampledFrom(['Release manager', ' On call '])), description: '', ...held };
  assert.equal(definitionProblem(definition), null, JSON.stringify(definition));
  const normal = normalDefinition(definition);
  assert.deepEqual(normalDefinition(normal), normal);
  assert.equal(definitionProblem(normal), null);
  const shuffled = { ...definition, permissions: [...definition.permissions].reverse(), protected: [...definition.protected].reverse() };
  assert.deepEqual(normalDefinition(shuffled), normal);
  const broken = tc.draw(gs.sampledFrom(['read without use', 'protected beyond', 'project-wide protected', 'twice', 'unknown'] as const));
  const bad: RoleDefinition = (() => {
    switch (broken) {
      case 'read without use': return { ...definition, permissions: [...definition.permissions.filter((permission) => permission !== 'secret.use' && permission !== 'secret.read'), 'secret.read'], protected: [] };
      case 'protected beyond': {
        const missing = domain.PERMISSIONS.find((permission) => !domain.PROJECT_ONLY.includes(permission) && !definition.permissions.includes(permission) && permission !== 'secret.read');
        return missing === undefined ? { ...definition, permissions: ['secret.use'], protected: ['secret.use', 'secret.write'] } : { ...definition, protected: [...definition.protected, missing] };
      }
      case 'project-wide protected': return { ...definition, permissions: [...new Set([...definition.permissions, 'grant.manage' as const])], protected: [...definition.protected, 'grant.manage'] };
      case 'twice': return { ...definition, permissions: ['secret.use', 'secret.use'], protected: [] };
      case 'unknown': return { ...definition, permissions: ['secret.peek' as domain.Permission], protected: [] };
    }
  })();
  assert.notEqual(definitionProblem(bad), null, `${broken}: ${JSON.stringify(bad)}`);
}, settings));
