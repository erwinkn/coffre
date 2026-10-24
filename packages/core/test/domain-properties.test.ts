import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';

import * as domain from '../../../scripts/properties/domain.ts';
import { propertySettings } from './properties.ts';

// The shared generators make worlds the database would take, row for row:
// a world it refuses fails a property on the generator, not the code. Each
// check names the constraint of packages/db/src/schema.ts it transcribes.
const PLACE_SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const ROLE_ID = /^[a-z][a-z0-9-]{1,31}$/;

function unique<T>(values: readonly T[], what: string, world: domain.World): void {
  const keys = values.map((value) => JSON.stringify(value));
  assert.equal(new Set(keys).size, keys.length, `${what}: ${JSON.stringify(world)}`);
}

const settings = propertySettings(500);

test(`every generated world satisfies the schema's keys and checks, seed ${settings.seed}`, () => hegel.test((tc) => {
  const world = tc.draw(domain.world());
  const environments = world.projects.flatMap((project) => project.environments);
  const byId = new Map(environments.map((environment) => [environment.id, environment]));
  unique(world.projects.map((project) => project.id), 'projects_pkey', world);
  unique(world.projects.map((project) => project.slug), 'projects_slug_key', world);
  unique([...world.projects.map((project) => project.id), ...environments.map((environment) => environment.id), ...world.secrets.map((secret) => secret.id)], 'ids, one place each', world);
  unique(environments.map((environment) => [environment.projectId, environment.slug]), 'environments_project_id_slug_key', world);
  unique(environments.filter((environment) => environment.owner !== null).map((environment) => [environment.parentId, environment.owner]), 'environments_parent_id_owner_key', world);
  for (const environment of environments) {
    assert.match(environment.slug, PLACE_SLUG, 'environments_slug_check');
    assert.notEqual(environment.parentId, environment.id, 'environments_parent_check');
    if (environment.owner !== null) {
      assert.ok(environment.parentId !== null && /^user:.+/.test(environment.owner), 'environments_owner_check');
    }
    if (environment.parentId !== null) {
      const parent = byId.get(environment.parentId);
      assert.ok(parent !== undefined && parent.projectId === environment.projectId, 'a fork inherits from its own project');
      assert.equal(parent.owner, null, 'nothing forks a personal config');
      assert.ok(domain.parentsOf(environments, environment.id).length <= domain.MAX_PARENTS, 'a chain coffre makes');
    }
  }
  for (const project of world.projects) assert.match(project.slug, PLACE_SLUG, 'projects_slug_check');
  unique(world.secrets.map((secret) => [secret.environmentId, secret.key]), 'secrets_project_id_environment_id_key_key', world);
  for (const secret of world.secrets) {
    assert.match(secret.key, KEY, 'secrets_key_check');
    assert.ok(byId.has(secret.environmentId));
    if (secret.reference !== null) {
      const source = world.secrets.find((each) => each.id === secret.reference);
      assert.ok(source !== undefined && source.reference === null && source.environmentId !== secret.environmentId, 'a reference names a value of its own elsewhere');
      assert.equal(byId.get(secret.environmentId)!.owner, null, 'no reference in a personal config');
    }
  }
  unique(world.dismissals.map((dismissal) => [dismissal.environmentId, dismissal.key]), 'dismissed_keys_pkey', world);
  for (const dismissal of world.dismissals) assert.notEqual(byId.get(dismissal.environmentId)?.parentId ?? null, null, 'a removal is a fork\'s');
  for (const member of [...world.people, ...world.services]) {
    // `vault_grants_on_project` and `_on_environment`: one grant a place a member.
    unique(member.grants.map((grant) => [grant.projectId, grant.environmentId]), 'vault_grants_on_project, vault_grants_on_environment', world);
    for (const grant of member.grants) {
      assert.match(grant.role, ROLE_ID, 'vault_grants_role_check');
      if (grant.environmentId !== null) assert.equal(byId.get(grant.environmentId)?.projectId, grant.projectId);
    }
  }
}, settings));
