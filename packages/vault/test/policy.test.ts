// The access policy (docs/design/roles.md): roles in two columns, as an
// Owner of the whole instance edits and makes them, and the protected
// environments, which whoever manages a project's environments protects and
// only an Owner unprotects. The vault keeps it in its newest `policy.change`
// entry, by its MAC, and decides every read with it: a person holds a role's
// protected column in a protected environment, a service account never.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { INSTANCE_ROLES, ROLES, UNWRITTEN_FORK_MS, type RoleDefinition } from '@coffre/core/access';
import type { SecretRef } from '@coffre/core/vault';
import { entryHash } from '@coffre/core/audit';
import { tablesOf, type Database } from '@coffre/db';
import { sql } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { openLocalVault, type LocalVault } from '../src/local.ts';
import { emptyDatabase, openTestDatabase, places, postgresOnly, rows, storedVersions, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const CI = 'token:ci';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
});
after(() => db.close());
beforeEach(() => emptyDatabase(db.owner));

function configure(): ResolvedVaultConfig {
  return {
    keks: new KekRegistry(LocalKekProvider.generate('test-kek-1')),
    owners: ['root@acme.example'],
    signingKeys: [randomBytes(32)],
    bulkLimit: { count: 1000, windowMs: 15 * 60_000 },
  };
}

async function world() {
  const config = configure();
  const clock = { offset: 0 };
  const vault = await openLocalVault(db.vault, config, { clockOffset: () => clock.offset });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const where = await places(db.owner);
  const grant = async (principal: string, environmentId: string | null, role: string) => {
    assert.equal((await vault.admit({ actor: ROOT, principal })).ok, true);
    const set = await vault.setAccess({ actor: ROOT, principal, changes: [{ projectId: where.project, environmentId, role, expiresAt: null }] });
    assert.equal(set.ok, true, JSON.stringify(set));
  };
  /** A secret of `environmentId` with a value stored: what a read names. */
  const stored = async (environmentId: string) => {
    const secret: SecretRef = await where.secret(environmentId);
    const wrap = await vault.wrap({ principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] });
    assert.ok(wrap.ok);
    return storedVersions(db.owner, [{ secret, wrapped: wrap.wrapped[0]! }]);
  };
  return { vault, config, clock, ...where, grant, stored };
}

const protect = (vault: LocalVault, actor: string, projectId: string, environmentIds: string[], on = true) =>
  vault.changePolicy({ actor, change: { kind: 'protect', projectId, environmentIds, protected: on } });

test('a protected environment gives a person the protected column of their role, and a service account its other one', async () => {
  const w = await world();
  await w.grant(ADA, null, 'developer');
  await w.grant(CI, w.prod, 'viewer');
  const prod = await w.stored(w.prod);
  const dev = await w.stored(w.dev);
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: prod })).ok, true, 'before it is protected');
  assert.ok((await protect(w.vault, ROOT, w.project, [w.prod])).ok);
  const refused = await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: prod });
  assert.equal(!refused.ok && refused.refusal.code, 'no_grant');
  // She still uses it, through the proxy, and reads dev as before; CI reads prod as it always did.
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'use', items: prod })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: dev })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: CI, purpose: 'run', items: prod })).ok, true);
  // The app is told the policy with every member's access.
  assert.deepEqual((await w.vault.access(ADA)).policy?.protected, [w.prod]);
});

test('whoever manages a project\'s environments protects one, before its row exists too; only an Owner of the whole instance unprotects', async () => {
  const w = await world();
  await w.grant(ADA, null, 'maintainer');
  const fork = randomUUID();
  assert.ok((await protect(w.vault, ADA, w.project, [w.prod, fork])).ok);
  assert.deepEqual((await w.vault.policy()).protected, [w.prod, fork].sort());
  const refused = await protect(w.vault, ADA, w.project, [w.prod], false);
  assert.equal(!refused.ok && refused.refusal.code, 'not_allowed');
  assert.ok((await protect(w.vault, ROOT, w.project, [w.prod], false)).ok);
  assert.deepEqual((await w.vault.policy()).protected, [fork]);
  // A fork's alone, as the app protects it before writing its row: its entry names the project, and no environment yet.
  const next = randomUUID();
  assert.ok((await protect(w.vault, ADA, w.project, [next])).ok);
  const [entry] = (await db.owner.select().from(tablesOf(db.owner).auditLog)).filter((row) => row.action === 'policy.change' && row.metadata.includes(next));
  assert.deepEqual([entry?.projectId, entry?.environmentId], [w.project, null]);
  // Nor in a project that is not there.
  const nowhere = await protect(w.vault, ROOT, randomUUID(), [randomUUID()]);
  assert.equal(!nowhere.ok && nowhere.refusal.code, 'invalid');
  // A developer protects nothing: they do not manage the project's environments.
  await w.grant('user:bo@acme.example', null, 'developer');
  const bo = await protect(w.vault, 'user:bo@acme.example', w.project, [w.dev]);
  assert.equal(!bo.ok && bo.refusal.code, 'not_allowed');
});

test('an Owner of the whole instance edits a role, resets it, makes one, and deletes it once no grant names it; nobody edits Owner', async () => {
  const w = await world();
  await w.grant(ADA, null, 'developer');
  const reads: RoleDefinition = { ...ROLES.developer, protected: ['secret.read', 'secret.use', 'secret.write'] };
  const notOwner = await w.vault.changePolicy({ actor: ADA, change: { kind: 'role', role: 'developer', definition: reads } });
  assert.equal(!notOwner.ok && notOwner.refusal.code, 'not_allowed');
  assert.ok((await w.vault.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'developer', definition: reads } })).ok);
  assert.ok((await protect(w.vault, ROOT, w.project, [w.prod])).ok);
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: await w.stored(w.prod) })).ok, true, 'Developer as edited reads in prod');
  assert.ok((await w.vault.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'developer', definition: null } })).ok);
  assert.deepEqual((await w.vault.policy()).roles.developer, ROLES.developer, 'reset: as it ships');

  const owner = await w.vault.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'owner', definition: { ...ROLES.viewer } } });
  assert.equal(!owner.ok && owner.refusal.code, 'invalid');
  const member = await w.vault.changePolicy({ actor: ROOT, change: { kind: 'instance-role', role: 'member', definition: { ...ROLES.viewer } } });
  assert.equal(!member.ok && member.refusal.code, 'invalid');

  const releaser: RoleDefinition = { name: 'Release manager', description: 'Writes prod, reads nothing.', permissions: ['secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] };
  assert.ok((await w.vault.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'release-manager', definition: releaser } })).ok);
  await w.grant('user:bo@acme.example', w.prod, 'release-manager');
  const held = await w.vault.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'release-manager', definition: null } });
  assert.equal(!held.ok && held.refusal.code, 'invalid');
  assert.match(!held.ok ? held.refusal.message : '', /1 grant names release-manager/);
});

test('a role holds no more in a protected environment than elsewhere, reads only where it uses, and nothing project-wide in its protected column', async () => {
  const w = await world();
  const bad: RoleDefinition[] = [
    { ...ROLES.viewer, protected: ['secret.read', 'secret.use', 'secret.write'] },
    { ...ROLES.viewer, permissions: ['secret.read'], protected: [] },
    { ...ROLES.maintainer, protected: ['secret.use', 'environment.manage'] },
  ];
  for (const definition of bad) {
    const refused = await w.vault.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'viewer', definition } });
    assert.equal(!refused.ok && refused.refusal.code, 'invalid', JSON.stringify(definition));
  }
});

/** `count` entries in the vault's name that no key of its sealed: what an owner of the database inserts by hand. */
async function forge(metadata: unknown, count = 1): Promise<void> {
  const { auditLog, auditChainHead } = tablesOf(db.owner);
  const [head] = await db.owner.select().from(auditChainHead);
  const mac = Buffer.alloc(32, 7);
  let [seq, prevHash] = [head!.nextSeq, head!.headHash];
  const forged = [];
  for (let i = 0; i < count; i++, seq++) {
    const fields = {
      seq, author: 'vault' as const, keyId: 'forged', occurredAt: Date.now(), actor: ROOT, action: 'policy.change', decision: 'allow',
      code: null, subjectPrincipal: null, projectId: null, environmentId: null, secretId: null, secretVersionId: null,
      operationId: null, requestId: null, sourceIp: null, relatedSeq: null, metadata: JSON.stringify(metadata),
    };
    const hash = entryHash(prevHash, fields, mac);
    forged.push({ ...fields, prevHash, mac, hash });
    prevHash = hash;
  }
  for (let i = 0; i < forged.length; i += 200) await db.owner.insert(auditLog).values(forged.slice(i, i + 200));
  await db.owner.update(auditChainHead).set({ nextSeq: seq, headHash: prevHash });
}

test("a policy entry forged in the vault's name is passed over; with none of its own within reach, every environment is protected", async () => {
  const w = await world();
  await w.grant(ADA, null, 'developer');
  const prod = await w.stored(w.prod);
  const dev = await w.stored(w.dev);
  await w.grant(CI, w.dev, 'viewer');
  // Forged alone, it closes: no role holds anything, a service account's neither, but Owner, who writes it again.
  await forge({ policy: { roles: {}, instanceRoles: {}, protected: [] } });
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: dev })).ok, false);
  assert.equal((await w.vault.unwrap({ principal: CI, purpose: 'run', items: dev })).ok, false);
  assert.equal((await w.vault.unwrap({ principal: ROOT, purpose: 'reveal', items: dev })).ok, true);
  // The vault's own, after it, decides; a forged one after that, unprotecting prod, is passed over.
  assert.ok((await protect(w.vault, ROOT, w.project, [w.prod])).ok);
  await forge({ policy: { roles: {}, instanceRoles: {}, protected: [] } });
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: dev })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: CI, purpose: 'run', items: dev })).ok, true);
  assert.equal((await w.vault.unwrap({ principal: ADA, purpose: 'reveal', items: prod })).ok, false);
});

test('a role that holds nothing is given by whoever manages access alone: so a policy the vault cannot read leaves every service account to Owners', async () => {
  const w = await world();
  await w.grant(ADA, null, 'developer');
  assert.ok((await w.vault.changePolicy({ actor: ROOT, change: { kind: 'role', role: 'pending', definition: { name: 'Pending', description: '', permissions: [], protected: [] } } })).ok);
  // Ada, a Developer of market, gives a service account what she holds, never a role that holds nothing an Owner could fill in.
  assert.ok((await w.vault.admit({ actor: ADA, principal: 'token:ada-ci' })).ok);
  const given = (role: string) => w.vault.setAccess({ actor: ADA, principal: 'token:ada-ci', changes: [{ projectId: w.project, environmentId: null, role, expiresAt: null }] });
  const pending = await given('pending');
  assert.equal(!pending.ok && pending.refusal.code, 'not_allowed', JSON.stringify(pending));
  assert.ok((await given('viewer')).ok);
  await w.grant(CI, w.dev, 'viewer');
  // Unreadable, its own entry beyond reach, every role but Owner holds nothing: no member but an Owner gives, takes or
  // removes a service account.
  await forge({ policy: { roles: {}, instanceRoles: {}, protected: [] } }, 1024);
  assert.deepEqual((await w.vault.policy()).protected, ['*']);
  const revoked = await w.vault.setAccess({ actor: ADA, principal: CI, changes: [{ projectId: w.project, environmentId: w.dev, role: null, expiresAt: null }] });
  assert.equal(revoked.ok, false, JSON.stringify(revoked));
  assert.equal((await w.vault.admit({ actor: ADA, principal: 'token:another' })).ok, false);
  assert.equal((await w.vault.remove({ actor: ADA, principal: 'token:ada-ci' })).ok, false);
  assert.ok((await w.vault.setAccess({ actor: ROOT, principal: CI, changes: [{ projectId: w.project, environmentId: w.dev, role: null, expiresAt: null }] })).ok);
});

test("a policy the vault cannot read is written again by an Owner of the whole instance alone, from nothing: no change erases what the forged rows hide", async () => {
  const w = await world();
  await w.grant(ADA, null, 'owner');
  assert.ok((await protect(w.vault, ROOT, w.project, [w.prod])).ok);
  // The vault's own entry, beyond reach behind 1,024 forged ones: unreadable, so closed.
  await forge({ policy: { roles: {}, instanceRoles: {}, protected: [] } }, 1024);
  assert.deepEqual((await w.vault.policy()).protected, ['*']);
  // An Owner of market protecting dev would write a policy that protects dev alone, prod no longer: refused.
  const ada = await protect(w.vault, ADA, w.project, [w.dev]);
  assert.equal(!ada.ok && ada.refusal.code, 'not_allowed');
  assert.match(!ada.ok ? ada.refusal.message : '', /cannot read its own policy/);
  // An Owner of the whole instance writes it again, from the roles as they ship: what the forged rows hid is for them to restore.
  assert.ok((await protect(w.vault, ROOT, w.project, [w.dev])).ok);
  assert.deepEqual((await w.vault.policy()).protected, [w.dev]);
});

test('an id protected before its row exists protects it for ten minutes; one still with no row after is a fork never written, and protects nothing', async () => {
  const w = await world();
  const [refused, written] = [randomUUID(), randomUUID()];
  assert.ok((await protect(w.vault, ROOT, w.project, [refused, written])).ok);
  await db.owner.insert(tablesOf(db.owner).environments).values({ id: written, projectId: w.project, slug: 'staging', name: 'Staging' });
  w.clock.offset = UNWRITTEN_FORK_MS + 60_000;
  const young = randomUUID();
  assert.ok((await protect(w.vault, ROOT, w.project, [young])).ok);
  const policy = await w.vault.policy();
  assert.deepEqual([...policy.protected].sort(), [written, young].sort());
  // Each with its slug, which a scoped role's filters read; a fork's none until its row is written.
  assert.deepEqual(
    [...policy.protectedIn[w.project]!].sort((a, b) => (a.environmentId < b.environmentId ? -1 : 1)),
    [{ environmentId: written, slug: 'staging' }, { environmentId: young, slug: null }].sort((a, b) => (a.environmentId < b.environmentId ? -1 : 1)),
  );
  // The change after keeps no more of it: its entry holds the ids the policy does.
  const entries = (await db.owner.select().from(tablesOf(db.owner).auditLog)).filter((row) => row.action === 'policy.change' && row.decision === 'allow')
    .sort((a, b) => Number(a.seq) - Number(b.seq));
  const kept = (JSON.parse(entries.at(-1)!.metadata) as { policy: { protected: { environmentId: string }[] } }).policy.protected.map((place) => place.environmentId);
  assert.deepEqual(kept.sort(), [written, young].sort());
});

test('a protected environment keeps its slug: a person scoped to it by slug holds what their role holds there', async () => {
  const w = await world();
  // Ada, a Viewer of market, and a Developer of every prod, as an Owner edited Developer to read in protected environments.
  assert.ok((await w.vault.changePolicy({ actor: ROOT, change: { kind: 'instance-role', role: 'developer', definition: { ...INSTANCE_ROLES.developer, protected: ['secret.read', 'secret.use', 'secret.write'] } } })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, principal: ADA, role: 'developer', scope: { projects: 'all', environments: { only: ['prod'] } } })).ok);
  assert.ok((await w.vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  assert.ok((await protect(w.vault, ROOT, w.project, [w.prod])).ok);
  // She reads all of market, prod included: she gives CI a Viewer of market. Without prod's slug, her scope would not take it in.
  assert.ok((await w.vault.admit({ actor: ADA, principal: CI })).ok);
  const given = await w.vault.setAccess({ actor: ADA, principal: CI, changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }] });
  assert.ok(given.ok, JSON.stringify(given));
});

test('a read in flight when an environment is protected is decided as the policy is when it commits', { skip: process.env.COFFRE_TEST_ENGINE === 'sqlite' && 'SQLite runs one writer at a time' }, async () => {
  const inner = LocalKekProvider.generate('test-kek-1');
  let hold: Promise<void> | null = null;
  const kek = {
    provider: inner.provider, keyId: inner.keyId, keyVersion: inner.keyVersion,
    wrap: (dek: Buffer, ctx: Parameters<typeof inner.wrap>[1], operation?: Parameters<typeof inner.wrap>[2]) => inner.wrap(dek, ctx, operation),
    unwrap: async (wrapped: Parameters<typeof inner.unwrap>[0], ctx: Parameters<typeof inner.unwrap>[1], operation?: Parameters<typeof inner.unwrap>[2]) => {
      if (hold !== null) await hold;
      return inner.unwrap(wrapped, ctx, operation);
    },
  };
  const config = { ...configure(), keks: new KekRegistry(kek) };
  const vault = await openLocalVault(db.vault, config);
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const where = await places(db.owner);
  assert.ok((await vault.admit({ actor: ROOT, principal: ADA })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, principal: ADA, changes: [{ projectId: where.project, environmentId: null, role: 'developer', expiresAt: null }] })).ok);
  const secret = await where.secret(where.prod);
  const wrap = await vault.wrap({ principal: ROOT, items: [{ secret, key: randomBytes(32).toString('base64') }] });
  assert.ok(wrap.ok);
  const items = await storedVersions(db.owner, [{ secret, wrapped: wrap.wrapped[0]! }]);
  let release!: () => void;
  hold = new Promise<void>((resolve) => (release = resolve));
  const reading = vault.unwrap({ principal: ADA, purpose: 'reveal', items });
  await new Promise((resolve) => setTimeout(resolve, 100));
  // Another connection protects prod while the read waits on its key.
  const twin = await openLocalVault(await db.connect(), config);
  const protecting = protect(twin, ROOT, where.project, [where.prod]);
  await new Promise((resolve) => setTimeout(resolve, 100));
  release();
  const [read, protectedNow] = await Promise.all([reading, protecting]);
  assert.ok(protectedNow.ok);
  assert.equal(!read.ok && read.refusal.code, 'no_grant', 'refused as the policy is when it commits');
});

/**
 * Make `change` on a vault of its own connection, as another instance
 * would, and hold its transaction just before it commits, the log's head
 * with it; ask `decision` meanwhile, until it waits on that head; then let
 * the change commit. A decision in flight as the policy changes under it:
 * one that read the policy before the head would decide as it was.
 */
async function overtaken<T>(config: ResolvedVaultConfig, change: (vault: LocalVault) => Promise<{ ok: boolean }>, decision: () => Promise<T>): Promise<T> {
  let holding!: () => void;
  const held = new Promise<void>((resolve) => (holding = resolve));
  let release!: () => void;
  const released = new Promise<void>((resolve) => (release = resolve));
  let armed = false;
  const connection = await db.connect();
  const paused = new Proxy(connection, {
    get(target, key) {
      const value = Reflect.get(target, key, target) as unknown;
      if (typeof value !== 'function') return value;
      if (key !== 'transaction') return value.bind(target);
      return (work: (tx: unknown) => Promise<unknown>, ...rest: unknown[]) => value.call(target, async (tx: unknown) => {
        const done = await work(tx);
        if (armed) {
          armed = false;
          holding();
          await released;
        }
        return done;
      }, ...rest);
    },
  }) as Database;
  const twin = await openLocalVault(paused, config);
  await twin.policy();
  armed = true;
  const changing = change(twin);
  await Promise.race([held, changing.then((outcome) => assert.fail(`the change finished without committing: ${JSON.stringify(outcome)}`))]);
  const deciding = decision();
  // Until the vault's login queues on the head the change holds.
  for (let i = 0; ; i++) {
    const [waiting] = await rows<{ n: number }>(db.owner, sql`SELECT count(*)::int AS n FROM pg_stat_activity
      WHERE datname = current_database() AND usename = 'coffre_vault_runtime' AND wait_event_type = 'Lock'`);
    if (waiting!.n > 0) break;
    assert.ok(i < 200, 'the decision never waited on the head');
    await sleep(25);
  }
  release();
  assert.ok((await changing).ok, 'the change commits');
  return deciding;
}

test('a reference made as prod is protected is decided under the head, as the policy is when it commits: refused', postgresOnly('SQLite runs one writer at a time'), async () => {
  const w = await world();
  await w.grant(ADA, null, 'developer');
  const source = await w.secret(w.prod);
  const holder = { projectId: w.project, environmentId: w.dev, secretId: randomUUID(), path: 'p/dev/HOLDER' };
  // Ada reads prod and writes dev: a reference from one to the other, before prod is protected, is hers to make.
  const made = await overtaken(w.config,
    (twin) => protect(twin, ROOT, w.project, [w.prod]),
    () => w.vault.reference({ principal: ADA, items: [{ id: randomUUID(), holder, source: { secretId: source.secretId } }] }),
  );
  // Made as prod is protected, which she only uses now: it would let her read prod through dev.
  assert.equal(!made.ok && made.refusal.code, 'no_grant');
});

test('a service account removed by its manager as prod is protected is decided under the head: they manage it no more', postgresOnly('SQLite runs one writer at a time'), async () => {
  const w = await world();
  await w.grant(ADA, null, 'developer');
  // Ada sets up CI, a Viewer of all of market, while nothing is protected: it is hers to manage.
  assert.ok((await w.vault.admit({ actor: ADA, principal: CI })).ok);
  assert.ok((await w.vault.setAccess({ actor: ADA, principal: CI, changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  const removed = await overtaken(w.config,
    (twin) => protect(twin, ROOT, w.project, [w.prod]),
    () => w.vault.remove({ actor: ADA, principal: CI }),
  );
  // CI reads prod, which Ada only uses once it is protected: she no longer reaches all it holds.
  assert.equal(!removed.ok && removed.refusal.code, 'not_allowed');
  assert.equal((await w.vault.access(CI)).status, 'active');
});
