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

test('a grant on every project names its place in words', () => {
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

test("a sync's run reads as its push, decided by both", () => {
  const sync = { actorType: 'system' as const, actorId: 'sync:7f0c', ...prod, operationId: 'op-sync' };
  const run = [
    ...['A', 'B', 'C'].map((key) => entry({ ...sync, action: 'secret.read', author: 'vault', key, metadata: { purpose: 'sync', provider: 'github-actions' } })),
    ...['A', 'B', 'C'].map((key) =>
      entry({ ...sync, action: 'sync.push', key, metadata: { destination: 'acme/market', provider: 'github-actions' } }),
    ),
  ];
  assert.equal(said(...run), 'pushed market/prod to acme/market: 3 secrets');
  assert.equal(decidedBy(run), 'vault, app');
  assert.equal(who(run), 'sync to GitHub');
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
  assert.deepEqual(who(run), { member: 'token:ci-deploy' });
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
    [{ action: 'member.add', subject: 'user:eve@acme.example' }, 'added eve@acme.example'],
    [{ action: 'member.restore', subject: 'user:eve@acme.example' }, 'brought back eve@acme.example'],
    [{ action: 'member.owner', subject: 'user:eve@acme.example', metadata: { owner: true } }, 'made eve@acme.example an owner'],
    [{ action: 'member.owner', subject: 'user:eve@acme.example', metadata: { owner: false } }, 'took owner from eve@acme.example'],
    [{ action: 'sync.create', ...prod, metadata: { destination: 'acme/market' } }, 'set up a sync of market/prod to acme/market'],
    [{ action: 'sync.update', ...prod, metadata: { paused: true } }, 'paused the sync of market/prod'],
    [{ action: 'sync.delete', ...prod, metadata: { destination: 'acme/market' } }, 'removed the sync of market/prod to acme/market'],
    [{ action: 'sync.remove', ...prod, key: 'OLD', metadata: { destination: 'acme/market' } }, 'removed market/prod/OLD from acme/market'],
    [{ action: 'vault.tampered', subject: 'user:eve@acme.example', reason: 'mac' }, "found eve@acme.example's record tampered with: it does not carry the vault's seal"],
    [{ action: 'key.rotate', metadata: { from: 'vault:1a2b3c4d' } }, 'rotated its key'],
    [{ action: 'sign_in', metadata: { kind: 'cli' } }, 'signed in to the CLI'],
    [{ action: 'sign_out' }, 'signed out'],
    [{ action: 'token.create', metadata: { principalType: 'service', principalId: 'ci-deploy' } }, 'issued a bearer token to service:ci-deploy'],
    [{ action: 'token.bind', metadata: { principalType: 'service', principalId: 'api-deploy' } }, 'trusted CI runs to sign in as service:api-deploy'],
    [{ action: 'token.unbind', metadata: { principalType: 'service', principalId: 'api-deploy' } }, 'stopped trusting CI runs to sign in as service:api-deploy'],
    [{ action: 'token.unbind', decision: 'deny', reason: 'requires_instance_owner', metadata: { principalType: 'service', principalId: 'api-deploy' } }, 'tried to stop trusting CI runs to sign in as service:api-deploy: requires instance owner'],
    [{ action: 'device.approve' }, 'approved a CLI sign-in'],
    [{ action: 'account.link', metadata: { provider: 'github' } }, 'linked a github account'],
    [{ action: 'key.wrap', ...prod, key: 'DATABASE_URL', version: 5 }, 'sealed the key of market/prod/DATABASE_URL, version 5'],
    [{ action: 'key.check', metadata: { kekProvider: 'local', kekId: 'kek-1' } }, 'recorded the check value of the vault key kek-1'],
    [{ action: 'secret.read', ...prod, key: 'API_KEY', decision: 'deny', reason: 'wrong_kek' }, "tried to reveal market/prod/API_KEY: the vault's key is not the one that wrapped the data"],
    [{ action: 'sync.run', ...prod, metadata: { destination: 'acme/market' } }, 'ran the sync of market/prod to acme/market'],
    [{ action: 'audit.heartbeat' }, 'checked in'],
    [{ action: 'audit.checkpoint', metadata: { seq: 5170 } }, 'signed the log through entry 5170'],
    [{ action: 'secret.list', ...prod, decision: 'deny', reason: 'no_grant' }, 'tried to list market/prod: no grant'],
    [{ action: 'sync.list', ...prod, decision: 'deny', reason: 'no_grant' }, 'tried to list the syncs of market/prod: no grant'],
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
  assert.equal(who([{ actorType: 'system', actorId: 'scheduler', metadata: {} }]), 'the scheduler');
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


// These templates remain part of the stored log's vocabulary after sync removal.
test('every historical sync action still renders as a human sentence', () => {
  const cases = {
    'sync.create': 'set up a sync of market/prod to acme/market',
    'sync.update': 'paused the sync of market/prod to acme/market',
    'sync.delete': 'removed the sync of market/prod to acme/market',
    'sync.push': 'pushed market/prod to acme/market',
    'sync.remove': 'removed market/prod from acme/market',
    'sync.run': 'ran the sync of market/prod to acme/market',
    'sync.list': 'listed the syncs of market/prod',
  };
  for (const [action, sentence] of Object.entries(cases)) {
    assert.equal(said(entry({ action, ...prod, metadata: { destination: 'acme/market', paused: true } })), sentence, action);
  }
});

test('an entry a CI run wrote reads with its run, as its issuer stated it', () => {
  assert.equal(runLabel(null), null);
  assert.equal(runLabel({ claims: { repository: 'acme/api', run_id: '7001', sha: 'f'.repeat(40) } }), 'acme/api run 7001 at fffffff');
  assert.equal(runLabel({ claims: { project_path: 'acme/api', pipeline_id: 99 } }), 'acme/api pipeline 99');
  assert.equal(runLabel({ claims: { sub: '104000' } }), 'CI run 104000');
  assert.equal(runLabel({ claims: {} }), 'a CI run');
});
