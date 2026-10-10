import test from 'node:test';
import assert from 'node:assert/strict';

import {
  decidedBy,
  describe,
  lines,
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
    [{ action: 'key.rotate', metadata: { from: 'vault:1a2b3c4d' } }, 'rotated its key'],
    [{ action: 'sign_in', metadata: { kind: 'cli' } }, 'signed in to the CLI'],
    [{ action: 'sign_out' }, 'signed out'],
    [{ action: 'token.create', metadata: { principalType: 'service', principalId: 'ci-deploy' } }, 'issued a bearer token to service:ci-deploy'],
    [{ action: 'token.bind', metadata: { principalType: 'service', principalId: 'api-deploy' } }, 'trusted CI runs to sign in as service:api-deploy'],
    [{ action: 'token.unbind', metadata: { principalType: 'service', principalId: 'api-deploy' } }, 'stopped trusting CI runs to sign in as service:api-deploy'],
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
