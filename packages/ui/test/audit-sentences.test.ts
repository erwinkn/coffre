import test from 'node:test';
import assert from 'node:assert/strict';

import {
  decidedBy,
  describe,
  lines,
  perSecret,
  plain,
  who,
  type AuditEntry, runLabel } from '../src/lib/audit-sentences.ts';

let next = 1000;
function entry(fields: Partial<AuditEntry> & Pick<AuditEntry, 'action'>): AuditEntry {
  return {
    seq: next++,
    author: 'app',
    actorType: 'user',
    actorId: 'ada@acme.example',
    decision: 'allow',
    reason: null,
    detail: false,
    subject: null,
    project: null,
    environment: null,
    key: null,
    version: null,
    secrets: null,
    operationId: null,
    metadata: {},
    ...fields,
  };
}

const said = (...batch: AuditEntry[]) => plain(describe(batch).parts);
const prod = { project: 'market', environment: 'prod' };
const dev = { project: 'market', environment: 'dev' };

function batch(count: number, fields: Partial<AuditEntry> & Pick<AuditEntry, 'action'>): AuditEntry[] {
  return Array.from({ length: count }, (_, i) => entry({ ...fields, key: `KEY_${i}`, operationId: 'op-1' }));
}

// The sample log the design asks the page to read as.
test('a run of twelve secrets is one line', () => {
  const run = batch(12, { action: 'secret.read', author: 'vault', ...prod, metadata: { purpose: 'run' } });
  assert.equal(said(...run), 'ran market/prod: 12 secrets');
  assert.equal(decidedBy(run), 'vault');
});

test("a run of a fork is a run of the fork, its parent's values counted as inherited", () => {
  const own = entry({ action: 'secret.read', author: 'vault', project: 'market', environment: 'prod-eu', key: 'DATABASE_URL', operationId: 'op-1', metadata: { purpose: 'run' } });
  const inherited = batch(2, { action: 'secret.read', author: 'vault', ...prod, metadata: { purpose: 'run', through: { environmentId: 'e', slug: 'prod-eu' } } });
  assert.equal(said(own, ...inherited), 'ran market/prod-eu: 3 secrets, 2 inherited');
});

test('a run of twelve secrets the vault logged as one entry reads the same, and opens to each', () => {
  const keys = Array.from({ length: 12 }, (_, i) => ({ key: `KEY_${i}`, version: i + 1 }));
  const run = entry({
    action: 'secret.read', author: 'vault', ...prod, operationId: 'op-1', secrets: keys,
    metadata: { purpose: 'run', secrets: keys.map(({ key, version }) => ({ subject: `market/prod/${key}`, version })) },
  });
  assert.equal(said(run), 'ran market/prod: 12 secrets');
  const each = perSecret(run);
  assert.deepEqual(each.map((one) => [one.seq, plain(describe([one]).parts), one.version]), keys.map(({ key, version }) => [run.seq, `ran market/prod/${key}`, version]));
  // Refused as one, it says so once, with its size.
  assert.equal(said({ ...run, decision: 'deny', reason: 'no_grant' }), 'tried to run market/prod, 12 secrets: no grant');
});

test("a fork's run that inherits several values reads as a run of the fork, from one entry of its parent's", () => {
  const keys = [{ key: 'SENTRY_DSN', version: 1 }, { key: 'STRIPE_KEY', version: 2 }];
  const own = entry({ action: 'secret.read', author: 'vault', project: 'market', environment: 'prod-eu', key: 'DATABASE_URL', operationId: 'op-3', metadata: { purpose: 'run' } });
  const inherited = entry({
    action: 'secret.read', author: 'vault', ...prod, operationId: 'op-3', secrets: keys,
    metadata: { purpose: 'run', through: { environmentId: 'e', slug: 'prod-eu' }, secrets: keys.map(({ key, version }) => ({ subject: `market/prod/${key}`, version })) },
  });
  assert.equal(said(own, inherited), 'ran market/prod-eu: 3 secrets, 2 inherited');
  assert.equal(plain(describe([perSecret(inherited)[0]!]).parts), 'ran market/prod/SENTRY_DSN in market/prod-eu');
});

test('a read whose list was emptied or mangled around coffre still reads, as its place', () => {
  const emptied = entry({ action: 'secret.read', author: 'vault', ...prod, secrets: [], metadata: { purpose: 'run', secrets: [] } });
  assert.deepEqual(perSecret(emptied), [emptied]);
  assert.equal(said(emptied), 'ran market/prod');
  const mangled = entry({ action: 'secret.read', author: 'vault', ...prod, secrets: [{ key: null, version: null }, { key: 'B', version: 2 }], metadata: { purpose: 'run', secrets: ['x', { subject: 'market/prod/B', version: 2 }] } });
  assert.deepEqual(perSecret(mangled).map((one) => plain(describe([one]).parts)), ['ran market/prod', 'ran market/prod/B']);
});

test('values read through references, one entry for their source, read as a run of the holder', () => {
  const keys = [{ key: 'DATABASE_URL', version: 3 }, { key: 'STRIPE_KEY', version: 1 }];
  const through = entry({
    action: 'secret.read', author: 'vault', ...prod, operationId: 'op-2', secrets: keys,
    metadata: { purpose: 'run', secrets: keys.map(({ key, version }) => ({ subject: `market/prod/${key}`, version, via: { path: `billing/prod/${key}` } })) },
  });
  const own = entry({ action: 'secret.read', author: 'vault', project: 'billing', environment: 'prod', key: 'PORT', version: 1, operationId: 'op-2', metadata: { purpose: 'run' } });
  assert.equal(said(own, through), 'ran billing/prod: 3 secrets, 2 through references');
  assert.equal(plain(describe([perSecret(through)[1]!]).parts), 'ran market/prod/STRIPE_KEY through billing/prod/STRIPE_KEY');
});

test('a write says the version it made', () => {
  assert.equal(
    said(entry({ action: 'secret.write', ...prod, key: 'DATABASE_URL', version: 5 })),
    'changed market/prod/DATABASE_URL, now version 5',
  );
  assert.equal(said(entry({ action: 'secret.write', ...prod, key: 'NEW', version: 1 })), 'added market/prod/NEW');
  // A save of several keys is one line, named for what it did to them.
  assert.equal(said(...batch(4, { action: 'secret.write', ...prod, version: 1 })), 'added market/prod: 4 secrets');
  const mixed = batch(3, { action: 'secret.write', ...prod, version: 2 });
  mixed[0] = { ...mixed[0]!, version: 1 };
  assert.equal(said(...mixed), 'wrote market/prod: 3 secrets');
});

test('a write says who sees the value where it is no secret, and a level changed as made that', () => {
  const write = (metadata: Record<string, unknown>, version = 4) => said(entry({ action: 'secret.write', ...prod, key: 'STRIPE_KEY', version, metadata }));
  assert.equal(write({ plain: true }, 1), 'added market/prod/STRIPE_KEY, as a plain value, no secret');
  assert.equal(write({ sensitive: true }, 1), 'added market/prod/STRIPE_KEY, as a sensitive value, shown to nobody');
  // A mark: the value kept, made stricter.
  assert.equal(write({ sensitive: true, was: 'secret', kept: 3 }), 'made market/prod/STRIPE_KEY sensitive, now version 4');
  assert.equal(write({ was: 'plain', kept: 3 }), 'made market/prod/STRIPE_KEY secret, now version 4');
  // More visible, which only a new value makes it.
  assert.equal(write({ plain: true, was: 'secret' }), 'made market/prod/STRIPE_KEY plain with a new value, now version 4');
  assert.equal(write({ was: 'sensitive' }), 'made market/prod/STRIPE_KEY secret with a new value, now version 4');
});

test('a refusal says the value is sensitive, and an entry from 0.9 still says why', () => {
  const refused = (reason: string) => said(entry({ action: 'secret.read', author: 'vault', ...prod, key: 'STRIPE_KEY', decision: 'deny', reason }));
  assert.equal(refused('sensitive'), 'tried to reveal market/prod/STRIPE_KEY: the value is sensitive');
  assert.equal(refused('stand_ins'), 'tried to reveal market/prod/STRIPE_KEY: people get placeholders');
  assert.equal(
    said(entry({ action: 'secret.write', ...prod, key: 'STRIPE_KEY', decision: 'deny', reason: 'looser', metadata: { sensitivity: 'plain', was: 'secret' } })),
    'tried to change market/prod/STRIPE_KEY: making it visible takes a new value',
  );
});

test("a grant on every project of 0.4 names its place in words, and what the vault replaced it by", () => {
  const grant = entry({
    action: 'access.grant',
    author: 'vault',
    actorId: 'bob@acme.example',
    subject: 'user:carol@acme.example',
    metadata: { role: 'developer', place: '*/dev' },
  });
  assert.equal(said(grant), 'gave carol@acme.example developer on dev in every project');
  assert.equal(
    said(entry({ ...grant, action: 'access.revoke', metadata: { previousRole: 'viewer', place: '*' } })),
    'took viewer on every project from carol@acme.example',
  );
  const replaced = { ...grant, action: 'access.revoke', actorId: 'vault', metadata: { previousRole: 'developer', place: '*/dev', replacedBy: { role: 'developer' } } };
  assert.equal(said(entry(replaced)), 'took developer on dev in every project from carol@acme.example, replaced by the instance role Developer');
  assert.equal(
    said(entry({ ...replaced, metadata: { ...replaced.metadata, replacedBy: { role: 'member' } } })),
    'took developer on dev in every project from carol@acme.example, replaced by project grants',
  );
});

test('a grant names whom, which role and where', () => {
  const grant = entry({
    action: 'access.grant',
    author: 'vault',
    actorId: 'bob@acme.example',
    subject: 'user:carol@acme.example',
    ...dev,
    metadata: { role: 'developer' },
  });
  assert.equal(said(grant), 'gave carol@acme.example developer on market/dev');
  assert.deepEqual(describe([grant]).parts.slice(2, 3), [{ member: 'user:carol@acme.example' }]);
  assert.equal(
    said(entry({ ...grant, metadata: { role: 'owner', previousRole: 'viewer', expiresAt: '2026-12-31T00:00:00.000Z' } })),
    'gave carol@acme.example owner on market/dev, was viewer, until 2026-12-31',
  );
  assert.equal(
    said(entry({ ...grant, action: 'access.revoke', metadata: { previousRole: 'developer' } })),
    'took developer on market/dev from carol@acme.example',
  );
});

test('a reveal, and a refused one with its reason', () => {
  assert.equal(
    said(entry({ action: 'secret.read', author: 'vault', ...dev, key: 'API_KEY', metadata: { purpose: 'reveal' } })),
    'revealed market/dev/API_KEY',
  );
  const refused = entry({
    action: 'secret.read',
    author: 'vault',
    actorId: 'carol@acme.example',
    decision: 'deny',
    reason: 'no_grant',
    ...prod,
    key: 'API_KEY',
    metadata: { purpose: 'reveal' },
  });
  assert.equal(said(refused), 'tried to reveal market/prod/API_KEY: no grant');
  assert.equal(describe([refused]).refused, true);
});

test('a removal counts the grants it took', () => {
  assert.equal(
    said(entry({ action: 'member.remove', author: 'vault', subject: 'user:dave@acme.example', metadata: { revoked: 2, generation: 3 } })),
    'removed dave@acme.example, who held 2 grants',
  );
});

test('a refused batch keeps its size, and says why', () => {
  const run = batch(50, {
    action: 'secret.read',
    author: 'vault',
    actorType: 'service',
    actorId: 'ci-deploy',
    decision: 'deny',
    reason: 'bulk_limit',
    ...prod,
    metadata: { purpose: 'run' },
  });
  assert.equal(said(...run), 'tried to run market/prod, 50 secrets: bulk limit');
  // The member as the log keeps it; shownMember says it as people read it, service:ci-deploy, where it is shown.
  assert.deepEqual(who(run[0]!), { member: 'token:ci-deploy' });
});

test('a batch partly refused says how much was', () => {
  const run = batch(3, { action: 'secret.read', author: 'vault', ...prod, metadata: { purpose: 'run' } });
  run[2] = { ...run[2]!, decision: 'deny', reason: 'expired' };
  assert.equal(said(...run), 'ran market/prod: 3 secrets, 1 refused: grant expired');
});

test('a restore names both versions', () => {
  assert.equal(
    said(entry({ action: 'secret.restore', ...prod, key: 'DATABASE_URL', version: 6, metadata: { from: 3 } })),
    'restored market/prod/DATABASE_URL to version 3, now 6',
  );
});

test('places are created, changed, archived and restored', () => {
  assert.equal(said(entry({ action: 'project.create', project: 'billing' })), 'created project billing');
  assert.equal(said(entry({ action: 'environment.archive', ...dev })), 'archived environment market/dev');
});

test('every other action has a sentence', () => {
  const cases: [Partial<AuditEntry> & Pick<AuditEntry, 'action'>, string][] = [
    [{ action: 'secret.rename', ...prod, key: 'OLD', metadata: { key: 'OLD', nextKey: 'NEW' } }, 'renamed market/prod/OLD to NEW'],
    [{ action: 'secret.archive', ...prod, key: 'OLD' }, 'archived market/prod/OLD'],
    [{ action: 'secret.unarchive', ...prod, key: 'OLD' }, 'brought back market/prod/OLD'],
    [{ action: 'secret.move', ...prod, key: 'STRIPE_KEY', metadata: { from: null, to: 'stripe' } }, 'moved market/prod/STRIPE_KEY to the folder stripe'],
    [{ action: 'secret.move', ...prod, key: 'STRIPE_KEY', metadata: { from: 'stripe', to: null } }, 'moved market/prod/STRIPE_KEY out of its folder'],
    [{ action: 'environment.create', project: 'market', environment: 'staging', metadata: { slug: 'staging', from: 'prod' } }, 'created environment market/staging, a fork of prod'],
    [{ action: 'environment.create', project: 'market', environment: 'prod-eu', metadata: { slug: 'prod-eu', from: 'prod', inherits: 'prod' } }, 'created environment market/prod-eu, inheriting from prod'],
    [{ action: 'environment.create', project: 'market', environment: 'dev-p-3f9c2a1b', metadata: { slug: 'dev-p-3f9c2a1b', personal: 'dev' } }, 'created a personal config of market/dev'],
    [{ action: 'environment.delete', project: 'market', environment: 'dev-p-3f9c2a1b~deleted-2026-10-17', metadata: { path: 'market/dev@ada@acme.example', personal: true } }, 'deleted a personal config, market/dev@ada@acme.example'],
    [{ action: 'secret.reset', project: 'market', environment: 'prod-eu', key: 'DATABASE_URL', metadata: { key: 'DATABASE_URL', from: 'prod' } }, "reset market/prod-eu/DATABASE_URL to prod's value"],
    [{ action: 'secret.rename', project: 'market', environment: 'prod-eu', key: 'OLD', metadata: { key: 'OLD', nextKey: 'NEW', parent: 'prod' } }, 'renamed market/prod-eu/OLD to NEW, as prod did'],
    [{ action: 'secret.read', ...prod, key: 'STRIPE_KEY', metadata: { purpose: 'run', through: { environmentId: 'e', slug: 'prod-eu' } } }, 'ran market/prod/STRIPE_KEY in market/prod-eu'],
    [{ action: 'secret.read', project: 'billing', environment: 'prod', key: 'SOURCE', metadata: { purpose: 'run', via: { path: 'market/prod/SHARED' }, through: { environmentId: 'e', slug: 'prod-eu' } } }, 'ran billing/prod/SOURCE through market/prod/SHARED in market/prod-eu'],
    [{ action: 'environment.fork', ...prod, decision: 'deny', reason: 'missing_secret_read', metadata: { from: 'prod', slug: 'staging' } }, 'tried to fork market/prod into staging: no grant to read it'],
    [{ action: 'missing.dismiss', ...prod, metadata: { key: 'SENTRY_DSN' } }, 'dismissed SENTRY_DSN in market/prod as not needed'],
    [{ action: 'missing.restore', ...prod, metadata: { key: 'SENTRY_DSN' } }, 'restored SENTRY_DSN in market/prod to the missing keys'],
    [{ action: 'secret.reference', project: 'billing', environment: 'prod', key: 'DATABASE_URL', metadata: { key: 'DATABASE_URL', source: 'market/prod/DATABASE_URL' } }, 'made billing/prod/DATABASE_URL a reference to market/prod/DATABASE_URL'],
    [{ action: 'reference.end', project: 'billing', environment: 'prod', metadata: { reason: 'broken', subject: 'billing/prod/DATABASE_URL', source: { path: 'market/prod/DATABASE_URL' } } }, 'broke the reference billing/prod/DATABASE_URL to market/prod/DATABASE_URL'],
    [{ action: 'reference.end', project: 'billing', environment: 'prod', metadata: { reason: 'replaced', subject: 'billing/prod/DATABASE_URL', source: { path: 'market/prod/DATABASE_URL' } } }, 'gave a value of its own to billing/prod/DATABASE_URL, no longer a reference to market/prod/DATABASE_URL'],
    [{ action: 'secret.read', ...prod, key: 'DATABASE_URL', metadata: { purpose: 'run', via: { path: 'billing/prod/DATABASE_URL' } } }, 'ran market/prod/DATABASE_URL through billing/prod/DATABASE_URL'],
    [{ action: 'project.move', project: 'acme', metadata: { from: null, to: 'Clients' } }, 'moved project acme to the folder Clients'],
    [{ action: 'member.add', subject: 'user:eve@acme.example' }, 'added eve@acme.example'],
    [{ action: 'member.restore', subject: 'user:eve@acme.example' }, 'brought back eve@acme.example'],
    [{ action: 'member.owner', subject: 'user:eve@acme.example', metadata: { owner: true } }, 'made eve@acme.example an owner'],
    [{ action: 'member.owner', subject: 'user:eve@acme.example', metadata: { owner: false } }, 'took owner from eve@acme.example'],
    [{ action: 'member.add', subject: 'user:eve@acme.example', metadata: { role: 'developer', scope: { projects: 'all', environments: { only: ['dev'] } } } }, 'added eve@acme.example as a Developer, with a scope'],
    [{ action: 'member.add', subject: 'user:eve@acme.example', metadata: { role: 'member', scope: { projects: 'all', environments: 'all' } } }, 'added eve@acme.example'],
    [{ action: 'member.role', subject: 'user:eve@acme.example', metadata: { role: 'admin', scope: { projects: 'all', environments: 'all' }, previousRole: 'member' } }, 'made eve@acme.example an Admin, was Member'],
    [{ action: 'member.role', actor: 'system:vault', subject: 'user:eve@acme.example', metadata: { role: 'developer', scope: { projects: 'all', environments: 'all' }, previousRole: 'member', reason: 'every-project' } }, 'made eve@acme.example a Developer, was Member, for their grants on every project'],
    [{ action: 'member.role', decision: 'deny', reason: 'own_role', subject: 'user:eve@acme.example', metadata: { role: 'owner' } }, 'tried to make eve@acme.example an Owner: nobody changes their own role'],
    [{ action: 'member.add', decision: 'deny', reason: 'requires_instance_admin', metadata: { principalType: 'user', principalId: 'eve@acme.example', role: 'owner' } }, 'tried to add eve@acme.example as an Owner: requires an admin or owner of the whole instance'],
    [{ action: 'vault.tampered', subject: 'user:eve@acme.example', reason: 'mac' }, "found eve@acme.example's record tampered with: it does not carry the vault's seal"],
    [{ action: 'settings.change', metadata: { serviceAccounts: { projects: 'all', environments: { except: ['prod'] } }, previous: { serviceAccounts: { projects: 'all', environments: 'all' } } } }, 'set where people set up service accounts: All projects · all but prod, was All projects'],
    [{ action: 'settings.change', metadata: { serviceAccounts: { projects: { only: ['3f2c', '9a1b'] }, environments: { only: ['dev'] } } } }, 'set where people set up service accounts: 2 projects · dev only'],
    [{ action: 'policy.change', author: 'vault', ...prod, metadata: { change: { kind: 'protect', projectId: 'p1', environmentIds: ['e1'], protected: true }, before: { protected: [] } } }, 'protected market/prod'],
    [{ action: 'policy.change', author: 'vault', ...prod, metadata: { change: { kind: 'protect', projectId: 'p1', environmentIds: ['e1'], protected: false }, before: { protected: ['e1'] } } }, 'unprotected market/prod'],
    [{ action: 'policy.change', author: 'vault', project: 'market', metadata: { change: { kind: 'protect', projectId: 'p1', environmentIds: ['e2'], protected: true }, before: { protected: [] } } }, 'protected a new environment of market'],
    [{ action: 'policy.change', author: 'vault', decision: 'deny', reason: 'not_allowed', ...prod, metadata: { change: { kind: 'protect', projectId: 'p1', environmentIds: ['e1'], protected: false } } }, 'tried to unprotect market/prod: not allowed'],
    [{ action: 'policy.change', author: 'vault', metadata: { change: { kind: 'role', role: 'developer', definition: { name: 'Developer', description: '', permissions: ['secret.read', 'secret.use'], protected: ['secret.use'] } }, before: { definition: { name: 'Developer', description: '', permissions: [], protected: [] } } } }, 'edited the Developer role'],
    [{ action: 'policy.change', author: 'vault', metadata: { change: { kind: 'role', role: 'developer', definition: null }, before: { definition: { name: 'Engineer', description: '', permissions: [], protected: [] } } } }, 'reset the Engineer role'],
    [{ action: 'policy.change', author: 'vault', metadata: { change: { kind: 'role', role: 'release-manager', definition: { name: 'Release manager', description: '', permissions: ['secret.use'], protected: [] } }, before: { definition: null } } }, 'made the Release manager role'],
    [{ action: 'policy.change', author: 'vault', metadata: { change: { kind: 'role', role: 'release-manager', definition: null }, before: { definition: { name: 'Release manager', description: '', permissions: ['secret.use'], protected: [] } } } }, 'deleted the Release manager role'],
    [{ action: 'policy.change', author: 'vault', metadata: { change: { kind: 'instance-role', role: 'auditor', definition: null }, before: { definition: { name: 'Auditor', description: '', permissions: [], protected: [] } } } }, 'reset the Auditor instance role'],
    [{ action: 'policy.change', decision: 'deny', reason: 'role_granted', metadata: { role: 'release-manager', grants: 2 } }, 'tried to delete the release-manager role: grants still name it'],
    [{ action: 'policy.change', decision: 'deny', reason: 'requires_instance_owner', metadata: { role: 'developer', kind: 'role' } }, 'tried to edit the Developer role: requires an instance owner'],
    [{ action: 'policy.change', decision: 'deny', reason: 'requires_instance_owner', metadata: { role: 'developer', kind: 'role', definition: null } }, 'tried to reset the Developer role: requires an instance owner'],
    [{ action: 'policy.change', decision: 'deny', reason: 'requires_instance_owner', metadata: { role: 'release-manager', kind: 'role', definition: null } }, 'tried to delete the release-manager role: requires an instance owner'],
    [{ action: 'token.create', decision: 'deny', reason: 'not_service_manager', metadata: { principalType: 'service', principalId: 'ci-deploy' } }, 'tried to issue a bearer token to service:ci-deploy: they hold less than the service account, or than they gave it'],
    [{ action: 'key.rotate', metadata: { from: 'vault:1a2b3c4d' } }, 'rotated its key'],
    [{ action: 'sign_in', metadata: { kind: 'cli' } }, 'signed in to the CLI'],
    [{ action: 'sign_out' }, 'signed out'],
    [{ action: 'token.create', metadata: { principalType: 'service', principalId: 'ci-deploy' } }, 'issued a bearer token to service:ci-deploy'],
    [{ action: 'token.bind', metadata: { principalType: 'service', principalId: 'api-deploy' } }, 'trusted CI runs to sign in as service:api-deploy'],
    [{ action: 'token.bind', metadata: { principalType: 'service', principalId: 'api-deploy', profile: 'github', claims: { environment: 'production' }, scope: [{ role: 'viewer' }] } }, 'trusted CI runs to sign in as service:api-deploy, in GitHub environment production, reaching viewer on 1 place'],
    [{ action: 'token.bind', metadata: { principalType: 'service', principalId: 'api-deploy', profile: 'custom', claims: { sub: 'x', environment: 'production' } } }, 'trusted CI runs to sign in as service:api-deploy'],
    [{ action: 'token.unbind', metadata: { principalType: 'service', principalId: 'api-deploy' } }, 'stopped trusting CI runs to sign in as service:api-deploy'],
    [{ action: 'token.seal', actor: 'system:app', metadata: { principalType: 'service', principalId: 'ci-web', tokens: ['t1', 't2'], bindings: ['b1'], scope: [{ role: 'developer' }, { role: 'viewer' }] } }, 'sealed 2 tokens and 1 trust binding of service:ci-web, reaching developer on 1 place, viewer on 1 place'],
    [{ action: 'token.seal', actor: 'system:app', metadata: { principalType: 'service', principalId: 'ci-web', tokens: ['t1'], bindings: [], scope: [] } }, 'sealed 1 token of service:ci-web, reaching nothing'],
    [{ action: 'token.unbind', decision: 'deny', reason: 'requires_instance_owner', metadata: { principalType: 'service', principalId: 'api-deploy' } }, 'tried to stop trusting CI runs to sign in as service:api-deploy: requires an instance owner'],
    [{ action: 'device.approve' }, 'approved a CLI sign-in'],
    [{ action: 'mcp.connect', metadata: { clientName: 'Claude' } }, 'connected Claude'],
    [{ action: 'mcp.read', metadata: { tool: 'list_secrets', names: ['market/prod'], via: { clientName: 'Claude Code' } } }, 'used list_secrets on market/prod via Claude Code'],
    [{ action: 'mcp.call', decision: 'deny', reason: 'insufficient_scope', metadata: { tool: 'archive_secret', names: ['market/prod/OLD'] } }, 'tried to use archive_secret on market/prod/OLD: insufficient scope'],
    [{ action: 'mcp.approve', metadata: { tool: 'archive_secret', names: ['market/prod/OLD'], clientName: 'Claude' } }, 'approved archive_secret on market/prod/OLD for Claude'],
    [{ action: 'mcp.deny', metadata: { tool: 'set_access', names: ['user:bob@acme.example'], clientName: 'Claude' } }, 'turned down set_access on user:bob@acme.example for Claude'],
    [{ action: 'mcp.connect', decision: 'deny', reason: 'person_denied', metadata: { clientName: 'Claude' } }, 'tried to connect Claude: they said no'],
    [{ action: 'mcp.cancel', metadata: { tool: 'archive_secret', names: ['market/prod/OLD'], via: { clientName: 'Claude Code' } } }, 'cancelled archive_secret on market/prod/OLD via Claude Code'],
    [{ action: 'mcp.approve', decision: 'deny', reason: 'replaced', metadata: { tool: 'request_secret_value', names: ['market/prod/KEY'], clientName: 'Claude' } }, 'tried to approve request_secret_value on market/prod/KEY: what it replaces changed since it was shown'],
    [{ action: 'mcp.token', metadata: { clientName: 'Claude', grant: 'refresh_token' } }, 'refreshed the tokens of Claude'],
    [{ action: 'mcp.disconnect', metadata: { clientName: 'Claude', reason: 'refresh_reused' } }, 'disconnected Claude: a refresh token it had replaced was used again'],
    [{ action: 'mcp.disconnect', metadata: { clientName: 'Claude', reason: 'superseded' } }, 'disconnected Claude: a connection with more scopes replaced it'],
    [{ action: 'mcp.disconnect', metadata: { clientName: 'Claude', reason: 'owner', principalType: 'user', principalId: 'ada@acme.example' } }, 'disconnected Claude of ada@acme.example'],
    [{ action: 'environment.archive', project: 'market', environment: 'prod', decision: 'deny', reason: 'referenced' }, 'tried to archive environment market/prod: references read it'],
    [{ action: 'secret.archive', ...prod, key: 'DATABASE_URL', decision: 'deny', reason: 'referenced', metadata: { key: 'DATABASE_URL' } }, 'tried to archive market/prod/DATABASE_URL: references read it'],
    [{ action: 'secret.archive', ...prod, decision: 'deny', reason: 'referenced', metadata: { keys: ['DATABASE_URL', 'STRIPE_KEY'] } }, 'tried to archive DATABASE_URL and STRIPE_KEY in market/prod: references read it'],
    [{ action: 'reference.end', project: 'billing', environment: 'prod', metadata: { reason: 'abandoned', subject: 'billing/prod/DATABASE_URL', source: { path: 'market/prod/DATABASE_URL' } } }, 'abandoned the reference billing/prod/DATABASE_URL to market/prod/DATABASE_URL, which its write never stored'],
    [{ action: 'account.link', metadata: { provider: 'github' } }, 'linked a github account'],
    [{ action: 'key.wrap', ...prod, key: 'DATABASE_URL', version: 5 }, 'sealed the key of market/prod/DATABASE_URL, version 5'],
    [{ action: 'key.check', metadata: { kekProvider: 'local', kekId: 'kek-1' } }, 'recorded the check value of the vault key kek-1'],
    [{ action: 'secret.read', ...prod, key: 'API_KEY', decision: 'deny', reason: 'wrong_kek' }, "tried to reveal market/prod/API_KEY: the vault's key is not the one that wrapped the data"],
    [{ action: 'audit.heartbeat' }, 'checked in'],
    [{ action: 'audit.checkpoint', metadata: { seq: 5170 } }, 'signed the log through entry 5170'],
    [{ action: 'secret.list', ...prod, decision: 'deny', reason: 'no_grant' }, 'tried to list market/prod: no grant'],
    [{ action: 'something.new', ...prod }, 'something.new market/prod'],
  ];
  for (const [fields, sentence] of cases) assert.equal(said(entry(fields)), sentence, fields.action);
});

test("the app's missing permissions are said as the grant that was missing", () => {
  assert.equal(
    said(entry({ action: 'secret.read', ...prod, key: 'K', decision: 'deny', reason: 'missing_secret_read', metadata: { purpose: 'reveal' } })),
    'tried to reveal market/prod/K: no grant to read it',
  );
  assert.equal(
    said(entry({ action: 'member.add', author: 'vault', actorType: 'system', actorId: 'vault', subject: 'user:root@acme.example', metadata: { rootAdmin: true } })),
    'added root@acme.example as a root admin',
  );
});

test('the vault making an Owner says why: the deployment names them', () => {
  const vault = { author: 'vault', actorType: 'system', actorId: 'vault' } as const;
  assert.equal(
    said(entry({ action: 'member.add', ...vault, subject: 'user:root@acme.example', metadata: { role: 'owner', scope: { projects: 'all', environments: 'all' }, reason: 'owners' } })),
    'added root@acme.example as an Owner: the deployment names them one',
  );
  assert.equal(
    said(entry({ action: 'member.role', ...vault, subject: 'user:root@acme.example', metadata: { role: 'owner', scope: { projects: 'all', environments: 'all' }, previousRole: 'member', reason: 'owners' } })),
    'made root@acme.example an Owner, was Member: the deployment names them one',
  );
  assert.equal(
    said(entry({ action: 'member.remove', author: 'vault', subject: 'user:root@acme.example', decision: 'deny', reason: 'last_owner' })),
    'tried to remove root@acme.example: they are the last Owner of the whole instance',
  );
});

test('the scheduler and the vault are named; an unknown reason is spelled out', () => {
  assert.equal(who({ actorType: 'system', actorId: 'scheduler' }), 'the scheduler');
  assert.equal(
    said(entry({ action: 'secret.read', ...prod, key: 'K', decision: 'deny', reason: 'some_new_code', metadata: { purpose: 'reveal' } })),
    'tried to reveal market/prod/K: some new code',
  );
});

test('lines group a batch at its newest entry', () => {
  const entries = [
    entry({ action: 'secret.write', ...prod, key: 'A', version: 2 }),
    ...batch(3, { action: 'secret.read', author: 'vault', ...prod, metadata: { purpose: 'run' } }),
    entry({ action: 'secret.read', author: 'vault', ...prod, key: 'B', metadata: { purpose: 'reveal' } }),
  ];
  assert.deepEqual(lines(entries).map((line) => line.length), [1, 3, 1]);
});


test('an entry a CI run wrote reads with its run, as its issuer stated it', () => {
  assert.equal(runLabel(null), null);
  assert.equal(runLabel({ claims: { repository: 'acme/api', run_id: '7001', sha: 'f'.repeat(40) } }), 'acme/api run 7001 at fffffff');
  assert.equal(runLabel({ claims: { project_path: 'acme/api', pipeline_id: 99 } }), 'acme/api pipeline 99');
  assert.equal(runLabel({ claims: { sub: '104000' } }), 'CI run 104000');
  assert.equal(runLabel({ claims: {} }), 'a CI run');
});

test("a credential's use names its upstream's host, and the deployment's egress where its requests left through one", () => {
  const use = (metadata: Record<string, unknown>) => said(entry({ action: 'credential.use', ...dev, metadata: { purpose: 'use', credential: 'schumann', host: 'dev.api.europ.schuman.io', ...metadata } }));
  assert.equal(use({}), 'used the credential schumann on dev.api.europ.schuman.io');
  assert.equal(use({ egress: true }), "used the credential schumann on dev.api.europ.schuman.io, through the deployment's egress");
});
