import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import {
  allows,
  isCredentialScope,
  issuedGrant,
  readsSensitive,
  scopeWithReads,
  useOnly,
  type CallerKind,
  type Holdings,
  type Permission,
  type Place,
  type ScopeGrant,
} from '../src/access.ts';
import { propertySettings } from './properties.ts';

// A workload's reads (docs/design/workload-access.md, section 6.1), against
// an independent statement of the rule: a workload is handed back key `k` of
// environment `e` only if its binding lists `k`, or `"*"`, at `e` itself, and
// its scope reaches `e` at all. Materializing the list onto the scope changes
// nothing the scope holds.

const permissions = ['secret.read', 'secret.use', 'secret.write', 'secret.archive', 'audit.read', 'environment.manage', 'grant.manage', 'project.manage'] as const;
const roles = ['viewer', 'contributor', 'developer', 'maintainer', 'access-manager', 'auditor', 'owner'] as const;
const projects = ['market', 'ops'] as const;
const slugs = ['dev', 'prod'] as const;
/** Two keys an environment, each ID naming its place, so that a key of one place is never another's. */
const keysOf = (environmentId: string) => [`${environmentId}#a`, `${environmentId}#b`];
const environmentIds = projects.flatMap((projectId) => slugs.map((slug) => `${projectId}/${slug}`));
const projectOf = new Map(environmentIds.map((id) => [id, id.split('/')[0]!]));

const grant = gs.record({
  projectId: gs.sampledFrom(projects),
  environment: gs.sampledFrom([null, ...slugs]),
  role: gs.sampledFrom(roles),
  sensitive: gs.booleans(),
}).map(({ projectId, environment, role, sensitive }): ScopeGrant => {
  const onEnvironment = environment !== null && !['maintainer', 'access-manager', 'owner'].includes(role);
  return { ...issuedGrant({ projectId, environmentId: onEnvironment ? `${projectId}/${environment}` : null, role }), ...(sensitive ? { sensitive } : {}) };
});
/** One grant a place, as a scope holds them. */
const scope = gs.arrays(grant, { maxSize: 5 }).map((held) => [...new Map(held.map((item) => [`${item.projectId}/${item.environmentId}`, item])).values()]);
/** A binding's reads: per environment, some of its keys, or every one; now and then one already on the scope, to be replaced. */
const reads = gs.arrays(gs.record({
  environmentId: gs.sampledFrom(environmentIds),
  every: gs.booleans(),
  some: gs.arrays(gs.sampledFrom([0, 1]), { maxSize: 2, unique: true }),
}), { maxSize: 4 }).map((listed) => Object.fromEntries(listed.map(({ environmentId, every, some }) =>
  [environmentId, { keys: every ? ('*' as const) : some.map((i) => keysOf(environmentId)[i]!) }])));

function everyPlace(): Place[] {
  return projects.flatMap((projectId): Place[] => [{ projectId }, ...slugs.map((slug): Place => ({ projectId, environmentId: `${projectId}/${slug}`, environmentSlug: slug }))]);
}

const settings = propertySettings(256);

test(`a binding's reads on its scope hold nothing the scope did not, seed ${settings.seed}`, () => hegel.test((tc) => {
  const held = tc.draw(scope);
  const listed = tc.draw(reads);
  const stale = tc.draw(gs.booleans());
  // A scope that carried a list before: the binding's replaces it.
  const before = stale ? held.map((item) => ({ ...item, reads: '*' as const })) : held;
  const after = scopeWithReads(before, listed, projectOf);
  assert.equal(isCredentialScope(after), true, JSON.stringify(after));
  const account: Holdings = { role: 'member', scope: { projects: 'all', environments: 'all' }, grants: held.map(({ projectId, environmentId, role }) => ({ projectId, environmentId, role })), service: true };
  for (const place of everyPlace()) {
    for (const permission of permissions as readonly Permission[]) {
      assert.equal(allows({ ...account, credentialScope: after }, permission, place), allows({ ...account, credentialScope: held }, permission, place), JSON.stringify({ held, listed, permission, place }));
    }
  }
  for (const projectId of projects) assert.equal(readsSensitive({ ...account, credentialScope: after }, projectId), readsSensitive({ ...account, credentialScope: held }, projectId));
}, settings));

test(`a workload is handed back exactly the keys its binding lists where they are held, by ID, seed ${settings.seed}`, () => hegel.test((tc) => {
  const held = tc.draw(scope);
  const listed = tc.draw(reads);
  const kind = tc.draw(gs.sampledFrom<CallerKind | undefined>(['workload', 'bearer', 'person', undefined]));
  const holder: Holdings = { role: 'member', scope: { projects: 'all', environments: 'all' }, grants: [], credentialScope: scopeWithReads(held, listed, projectOf), service: true, ...(kind === undefined ? {} : { kind }) };
  for (const environmentId of environmentIds) {
    const projectId = projectOf.get(environmentId)!;
    const reached = held.some((item) => item.projectId === projectId && (item.environmentId === null || item.environmentId === environmentId));
    for (const secretId of [...keysOf(environmentId), 'elsewhere#a']) {
      const list = listed[environmentId]?.keys;
      const readable = reached && (list === '*' || (list?.includes(secretId) ?? false));
      assert.equal(useOnly(holder, { projectId, environmentId, secretId }), kind === 'workload' && !readable, JSON.stringify({ held, listed, kind, environmentId, secretId }));
    }
  }
}, settings));
