import test from 'node:test';
import assert from 'node:assert/strict';

import {
  accessChanges,
  accessPatch,
  dateFromExpiry,
  environmentAccess,
  expiryFromDate,
  planFromGrants,
  withEnvironment,
  withLevel,
  type AccessPlan,
  type HeldGrant,
} from '../src/lib/access-plan.ts';

const environments = ['dev', 'prod', 'staging'];

function held(
  id: string,
  role: string,
  environmentSlug: string | null = null,
  expiresAt: string | null = null,
): HeldGrant {
  return { id, role, roleName: role, environmentSlug, expiresAt };
}

function perEnvironment(
  access: Record<string, 'viewer' | 'developer' | [role: 'viewer' | 'developer', expiresAt: string]>,
): AccessPlan {
  return {
    level: 'env',
    expiresAt: null,
    environments: Object.fromEntries(
      Object.entries(access).map(([slug, value]) =>
        typeof value === 'string'
          ? [slug, { role: value, expiresAt: null }]
          : [slug, { role: value[0], expiresAt: value[1] }],
      ),
    ),
  };
}

test('owner, read and write everywhere read back as one level, with their expiry', () => {
  assert.deepEqual(planFromGrants([], environments), {
    level: 'none',
    expiresAt: null,
    environments: {},
  });
  assert.equal(planFromGrants([held('g1', 'owner')], environments).level, 'owner');
  assert.equal(planFromGrants([held('g1', 'viewer')], environments).level, 'viewer');
  assert.deepEqual(
    planFromGrants([held('g1', 'developer', null, '2026-12-31T23:59:59.000Z')], environments),
    { level: 'developer', expiresAt: '2026-12-31T23:59:59.000Z', environments: {} },
  );
});

test('read and write on single environments read back per environment', () => {
  assert.deepEqual(
    planFromGrants(
      [held('g1', 'developer', 'dev'), held('g2', 'viewer', 'prod', '2026-12-31T23:59:59.000Z')],
      environments,
    ),
    perEnvironment({ dev: 'developer', prod: ['viewer', '2026-12-31T23:59:59.000Z'] }),
  );
});

test('grants outside the editor’s shape are custom and left alone', () => {
  for (const grants of [
    [held('g1', 'auditor')],
    [held('g1', 'viewer'), held('g2', 'developer', 'dev')],
    [held('g1', 'viewer', 'dev'), held('g2', 'developer', 'dev')],
    [held('g1', 'developer', 'retired')],
  ]) {
    const plan = planFromGrants(grants, environments);
    assert.equal(plan.level, 'custom');
    assert.deepEqual(accessChanges(grants, plan), []);
  }
});

test('the plan read from what is held changes nothing', () => {
  const grants = [
    held('g1', 'developer', 'dev'),
    held('g2', 'viewer', 'prod', '2026-12-31T12:00:00.000Z'),
  ];
  assert.deepEqual(accessChanges(grants, planFromGrants(grants, environments)), []);
});

test('asking for access already held creates only what is missing', () => {
  // The case that used to fail: write on dev was held, and asked for again.
  const grants = [held('g1', 'developer', 'dev')];
  assert.deepEqual(
    accessChanges(grants, perEnvironment({ dev: 'developer', prod: 'viewer', staging: 'viewer' })),
    [
      { kind: 'create', role: 'viewer', environmentSlug: 'prod', expiresAt: null },
      { kind: 'create', role: 'viewer', environmentSlug: 'staging', expiresAt: null },
    ],
  );
});

test('a change of level creates the new grant before revoking the old one', () => {
  const grants = [held('g1', 'developer')];
  assert.deepEqual(accessChanges(grants, { level: 'viewer', expiresAt: null, environments: {} }), [
    { kind: 'create', role: 'viewer', environmentSlug: null, expiresAt: null },
    { kind: 'revoke', grant: grants[0] },
  ]);
});

test('each grant keeps its own expiry, and moving one is its own change', () => {
  const grants = [held('g1', 'developer', 'dev'), held('g2', 'viewer', 'prod')];
  const plan = perEnvironment({
    dev: ['developer', '2026-10-31T23:59:59.000Z'],
    prod: 'viewer',
    staging: ['viewer', '2026-12-31T23:59:59.000Z'],
  });
  assert.deepEqual(accessChanges(grants, plan), [
    {
      kind: 'create',
      role: 'viewer',
      environmentSlug: 'staging',
      expiresAt: '2026-12-31T23:59:59.000Z',
    },
    { kind: 'expiry', grant: grants[0], expiresAt: '2026-10-31T23:59:59.000Z' },
  ]);
});

test('the same instant spelled differently is not a change', () => {
  const grants = [held('g1', 'viewer', null, '2026-12-31T23:59:59Z')];
  assert.deepEqual(
    accessChanges(grants, {
      level: 'viewer',
      expiresAt: '2026-12-31T23:59:59.000Z',
      environments: {},
    }),
    [],
  );
});

test('no access revokes everything, including grants the editor cannot express', () => {
  const grants = [held('g1', 'auditor'), held('g2', 'developer', 'dev')];
  assert.deepEqual(
    accessChanges(grants, { level: 'none', expiresAt: null, environments: {} }).map(
      (change) => change.kind,
    ),
    ['revoke', 'revoke'],
  );
});

test('switching from everywhere to per environment starts from the same access', () => {
  const expiresAt = '2026-12-31T23:59:59.000Z';
  const plan = withLevel({ level: 'viewer', expiresAt, environments: {} }, 'env', environments);
  assert.deepEqual(
    plan.environments,
    perEnvironment({
      dev: ['viewer', expiresAt],
      prod: ['viewer', expiresAt],
      staging: ['viewer', expiresAt],
    }).environments,
  );
  assert.deepEqual(
    accessChanges([held('g1', 'viewer', null, expiresAt)], plan).map((change) => change.kind),
    ['create', 'create', 'create', 'revoke'],
  );
});

test('environments are set and taken away one at a time', () => {
  const plan = perEnvironment({ dev: 'developer', prod: 'viewer' });
  assert.deepEqual(withEnvironment(plan, 'prod', null), perEnvironment({ dev: 'developer' }));
  assert.deepEqual(
    withEnvironment(plan, 'staging', { role: 'viewer', expiresAt: null }),
    perEnvironment({ dev: 'developer', prod: 'viewer', staging: 'viewer' }),
  );
});

test('environment slugs that name prototype properties are not inherited', () => {
  const plan = perEnvironment({});
  assert.equal(environmentAccess(plan, 'constructor'), null);
  assert.equal(environmentAccess(plan, 'toString'), null);
});

test('a date means access ends as that day closes, in UTC', () => {
  assert.equal(expiryFromDate('2026-10-31'), '2026-10-31T23:59:59.000Z');
  assert.equal(expiryFromDate(''), null);
  assert.equal(dateFromExpiry('2026-10-31T23:59:59.000Z'), '2026-10-31');
  assert.equal(dateFromExpiry(null), '');
});

test('the changes become one patch: a new level replaces the old at the same place', () => {
  const expiresAt = '2026-12-31T23:59:59.000Z';
  const grants = [held('g1', 'viewer', null), held('g2', 'developer', 'dev'), held('g3', 'viewer', 'prod')];
  const plan = perEnvironment({ dev: 'developer', prod: ['viewer', expiresAt], staging: 'viewer' });
  assert.deepEqual(accessPatch('market', accessChanges(grants, plan)), {
    market: null,
    'market/prod': { role: 'viewer', until: expiresAt },
    'market/staging': 'viewer',
  });
  assert.deepEqual(
    accessPatch('market', accessChanges([held('g1', 'viewer', null)], { level: 'developer', expiresAt: null, environments: {} })),
    { market: 'developer' },
  );
});
