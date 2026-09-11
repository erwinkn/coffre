import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Miniflare } from 'miniflare';
import { Client } from 'pg';
import { createConnection } from 'mysql2/promise';
import { d1Storage, postgresStorage, mysqlStorage } from '../../packages/storage/src/index';
import { Vault } from '../../packages/core/src/vault';
import { verifyChain } from '../../packages/core/src/audit';
import { LocalKeyProvider, random } from '../../packages/crypto/src/index';
import { archivePending } from '../../packages/archive/src/index';
import type { Authenticator, Command, Environment, Grant, KeyProvider, Principal, Project, Secret, Storage, StorageCapabilities } from '../../packages/contracts/src/index';
const instanceId = '9fca0d10-d8a7-4e16-ae97-b396a08c0eb1';
const localIdentity: Authenticator = { async verify(credentials) { return credentials.bearer ? { kind: 'token', id: credentials.bearer.split('_')[1]!.split('.')[0]!, digest: await (await import('../../packages/crypto/src/index')).sha256(credentials.bearer) } : { kind: 'human', subject: credentials.accessJwt ?? 'owner' }; } };

for (const engine of ['d1', 'postgres', 'mysql'] as const) test(`${engine}: storage and vault contract`, { timeout: 240000, skip: engine !== 'd1' && !process.env[engine === 'postgres' ? 'TEST_POSTGRES_URL' : 'TEST_MYSQL_URL'] ? 'Database is not configured in this process; CI supplies a disposable instance' : false }, async t => {
  let mf: Miniflare | undefined;
  let factory: () => Storage;
  const schema = (await readFile(`packages/storage/migrations/${engine}.sql`, 'utf8')).replace(/^--.*$/gm, '').split(';').map(x => x.trim()).filter(Boolean);
  if (engine === 'd1') {
    mf = new Miniflare({ cf: false, modules: true, script: 'export default {fetch(){return new Response("test")}}', d1Databases: ['DB'], compatibilityDate: '2026-07-01' });
    await mf.ready;
    const db = await mf.getD1Database('DB');
    for (const statement of schema) await db.prepare(statement).run();
    await db.prepare('INSERT INTO coffre_meta(singleton,instance_id,revision,audit_seq,audit_hash) VALUES (1,?,0,0,?)').bind(instanceId, 'GENESIS').run();
    factory = () => d1Storage(db as unknown as D1Database);
  } else if (engine === 'postgres') {
    const url = process.env.TEST_POSTGRES_URL!;
    const admin = new Client({ connectionString: url }); await admin.connect();
    for (const q of schema) await admin.query(q);
    await admin.query('INSERT INTO coffre_meta(singleton,instance_id,revision,audit_seq,audit_hash) VALUES (1,$1,0,0,$2)', [instanceId, 'GENESIS']);
    await admin.end(); factory = () => postgresStorage({ url, local: true });
  } else {
    const url = process.env.TEST_MYSQL_URL!; const admin = await createConnection(url);
    for (const q of schema) await admin.query(q);
    await admin.query('INSERT INTO coffre_meta(singleton,instance_id,revision,audit_seq,audit_hash) VALUES (1,?,0,0,?)', [instanceId, 'GENESIS']);
    await admin.end(); factory = () => mysqlStorage({ url, local: true });
  }
  const keys = new LocalKeyProvider(new Map([['local:v1', random(32)]]), 'local:v1');
  const requestKey = random(32);
  const run = async <T = unknown>(command: Command, args: { identity?: string; requestId?: string; wrap?: (storage: Storage) => Storage; keys?: KeyProvider; bearer?: string; requireAppendOnly?: boolean } = {}): Promise<T> => {
    const base = factory(), storage = args.wrap ? args.wrap(base) : base;
    try { return await new Vault({ auth: localIdentity, storage, keys: args.keys ?? keys, requestKey, bootstrapSubject: 'owner', instanceId, requireAppendOnly: args.requireAppendOnly }).execute(args.bearer ? { bearer: args.bearer } : { accessJwt: args.identity ?? 'owner' }, { requestId: args.requestId ?? crypto.randomUUID(), command }) as T; }
    finally { await base.close(); }
  };
  const inspect = async (command: Command = { type: 'workspace.get' }) => { const store = factory(); try { return await store.snapshot(command, crypto.randomUUID()); } finally { await store.close(); } };
  let project: Project, env: Environment, secret: Secret;
  try {
    await t.test('only the configured bootstrap subject can initialize the installation', async () => { await assert.rejects(run({ type: 'workspace.get' }, { identity: 'stranger' })); const s = await inspect(); assert.equal(s.principals.length, 0); await run({ type: 'workspace.get' }); assert.equal((await inspect()).principals.length, 1); });
    await t.test('create project, environment, and encrypted secret', async () => {
      project = await run({ type: 'project.create', name: 'Core API', description: '' }); env = await run({ type: 'environment.create', projectId: project.id, name: 'Development', protected: false });
      secret = await run({ type: 'secret.create', envId: env.id, key: 'DATABASE_URL', value: '  synthetic-first\nline2 ', note: 'Primary database', tag: 'Database', category: 'Credential', confirmed: false });
      const s = await inspect({ type: 'secret.history', id: secret.id }); assert.equal(s.versions.length, 1); assert.ok(!JSON.stringify(s).includes('synthetic-first'));
    });
    await t.test('metadata listing contains neither plaintext nor encrypted envelopes', async () => { const list = await run<Secret[]>({ type: 'secret.list', envId: env.id }); assert.equal(list[0]!.key, 'DATABASE_URL'); assert.ok(!JSON.stringify(list).includes('synthetic-first')); assert.ok(!JSON.stringify(list).includes('wrappedKey')); });
    await t.test('reads commit a per-version audit event before returning exact plaintext', async () => { const before = await inspect(); const value = await run<{ value: string; version: number }>({ type: 'secret.read', id: secret.id, purpose: 'edit' }); assert.equal(value.value, '  synthetic-first\nline2 '); const after = await inspect({ type: 'audit.list', limit: 200 }); assert.equal(after.auditSeq, before.auditSeq + 1); assert.equal(after.events[0]!.action, 'secret.read_authorized'); assert.ok(!JSON.stringify(after.events).includes(value.value)); });
    await t.test('concurrent edits have one winner and no duplicate version numbers', async () => {
      const attempts = await Promise.allSettled(['synthetic-winner-a', 'synthetic-winner-b'].map(value => run<Secret>({ type: 'secret.write', id: secret.id, expectedVersion: 1, value, confirmed: false })));
      assert.equal(attempts.filter(x => x.status === 'fulfilled').length, 1); assert.equal(attempts.filter(x => x.status === 'rejected').length, 1);
      secret = (attempts.find(x => x.status === 'fulfilled') as PromiseFulfilledResult<Secret>).value;
    });
    await t.test('idempotent writes return the original result without another version', async () => { const requestId = crypto.randomUUID(); const cmd = { type: 'secret.write', id: secret.id, expectedVersion: secret.currentVersion, value: 'synthetic-idempotent', confirmed: false } as const; const a = await run<Secret>(cmd, { requestId }), b = await run<Secret>(cmd, { requestId }); assert.deepEqual(a, b); await assert.rejects(run({ ...cmd, value: 'different' }, { requestId })); secret = a; });
    await t.test('audit insert failure rolls back the new version, head, and outbox', async () => {
      const before = await inspect({ type: 'audit.list', limit: 200 }); const duplicate = before.events[0]!.id;
      const broken = (storage: Storage): Storage => ({ capabilities: () => storage.capabilities(), snapshot: (c, r) => storage.snapshot(c, r), commit: plan => storage.commit({ ...plan, events: plan.events.map(e => ({ ...e, id: duplicate })) }), pendingArchive: l => storage.pendingArchive(l), acknowledgeArchive: e => storage.acknowledgeArchive(e), close: () => storage.close() });
      await assert.rejects(run({ type: 'secret.write', id: secret.id, expectedVersion: secret.currentVersion, value: 'must-not-commit', confirmed: false }, { wrap: broken }));
      const after = await inspect({ type: 'secret.history', id: secret.id }); assert.equal(after.auditSeq, before.auditSeq); assert.equal(after.auditHash, before.auditHash); assert.equal(after.secrets.find(x => x.id === secret.id)!.currentVersion, secret.currentVersion);
      await assert.rejects(run({ type: 'secret.read', id: secret.id, purpose: 'reveal' }, { wrap: broken }));
    });
    await t.test('metadata editing does not decrypt or change a value version', async () => {
      const failingKeys: KeyProvider = { async wrap() { throw Error('unexpected encrypt'); }, async unwrap() { throw Error('unexpected decrypt'); } };
      secret = await run({ type: 'secret.metadata', id: secret.id, expectedRevision: secret.revision, key: 'DB_URL', note: 'Revised', tag: 'Database', category: 'Credential' }, { keys: failingKeys });
      assert.equal(secret.currentVersion, 3);
    });
    let reader: Principal, grant: Grant;
    await t.test('auditor and reader roles do not imply write or global access', async () => {
      reader = await run({ type: 'principal.add', kind: 'human', subject: 'reader', name: 'Reader' });
      grant = await run({ type: 'grant.put', principalId: reader.id, scope: { type: 'environment', id: env.id }, permissions: ['secret.list', 'secret.read'], expiresAt: null });
      await run({ type: 'secret.read', id: secret.id, purpose: 'reveal' }, { identity: 'reader' });
      await assert.rejects(run({ type: 'secret.write', id: secret.id, expectedVersion: secret.currentVersion, value: 'forbidden', confirmed: false }, { identity: 'reader' }));
      await assert.rejects(run({ type: 'audit.list', limit: 20 }, { identity: 'reader' }));
    });
    await t.test('revocation during decryption prevents the stale value release', async () => {
      let revoked = false;
      const revoking: KeyProvider = { wrap: (d,c) => keys.wrap(d,c), async unwrap(k,c) { if (!revoked) { revoked = true; await run({ type: 'grant.revoke', id: grant.id }); } return keys.unwrap(k,c); } };
      await assert.rejects(run({ type: 'secret.read', id: secret.id, purpose: 'reveal' }, { identity: 'reader', keys: revoking }));
      const s = await inspect({ type: 'audit.list', limit: 200 }); assert.equal(s.events[0]!.outcome, 'denied');
    });
    await t.test('machine tokens are scoped, hash-only at rest, and immediately revocable', async () => {
      const issued = await run<{ principal: Principal; token: string }>({ type: 'machine.create', name: 'CI', expiresAt: new Date(Date.now() + 86400000).toISOString() });
      assert.ok(!JSON.stringify(await inspect()).includes(issued.token));
      await assert.rejects(run({ type: 'secret.read', id: secret.id, purpose: 'cli' }, { bearer: issued.token }));
      await run({ type: 'grant.put', principalId: issued.principal.id, scope: { type: 'environment', id: env.id }, permissions: ['secret.read'], expiresAt: null });
      await run({ type: 'secret.read', id: secret.id, purpose: 'cli' }, { bearer: issued.token });
      await run({ type: 'principal.disable', id: issued.principal.id, disabled: true });
      await assert.rejects(run({ type: 'secret.read', id: secret.id, purpose: 'cli' }, { bearer: issued.token }));
    });
    await t.test('protected environments require confirmation independently of permission', async () => {
      await run({ type: 'environment.update', id: env.id, name: env.name, protected: true, archived: false });
      await assert.rejects(run({ type: 'secret.write', id: secret.id, expectedVersion: secret.currentVersion, value: 'blocked', confirmed: false }));
      secret = await run({ type: 'secret.write', id: secret.id, expectedVersion: secret.currentVersion, value: 'confirmed', confirmed: true });
    });
    await t.test('restoration appends a newly encrypted version instead of changing history', async () => { secret = await run({ type: 'secret.restore', id: secret.id, expectedVersion: secret.currentVersion, version: 1, confirmed: true }); const v = await run<{ value: string }>({ type: 'secret.read', id: secret.id, purpose: 'reveal' }); assert.equal(v.value, '  synthetic-first\nline2 '); assert.equal(secret.currentVersion, 5); });
    await t.test('archive refuses reads and retains version history', async () => { secret = await run({ type: 'secret.archive', id: secret.id, expectedRevision: secret.revision, archived: true, confirmed: true }); await assert.rejects(run({ type: 'secret.read', id: secret.id, purpose: 'reveal' })); assert.equal((await inspect({ type: 'secret.history', id: secret.id })).versions.length, 5); });
    await t.test('the audit chain verifies after rollbacks and concurrent operations', async () => { const s = await inspect({ type: 'audit.list', limit: 200 }); const head = await verifyChain([...s.events].reverse()); assert.equal(head.seq, s.auditSeq); assert.equal(head.hash, s.auditHash); });
    await t.test('archive failure retains outbox and retry acknowledges only persisted objects', async () => {
      const store = factory(); try { const pending = await store.pendingArchive(200); assert.ok(pending.length > 0); await assert.rejects(archivePending(store, { async putIfAbsent() { throw Error('offline'); } }, instanceId)); assert.equal((await store.pendingArchive(200)).length, pending.length); const objects = new Map(); await archivePending(store, { async putIfAbsent(k,v) { objects.set(k,v); } }, instanceId, 200); assert.equal((await store.pendingArchive(1)).length, 0); assert.equal(objects.size, pending.length); } finally { await store.close(); }
    });
    if (engine === 'd1') await t.test('D1 refuses installations requiring database-enforced append-only privileges', async () => { await assert.rejects(run({ type: 'workspace.get' }, { requireAppendOnly: true })); });
  } finally { await mf?.dispose(); }
});
