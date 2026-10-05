import { randomBytes } from 'node:crypto';
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { LocalKekProvider } from '@coffre/core/kek';
import type { Database } from '@coffre/db';
import { and, asc, eq } from 'drizzle-orm';

import { auditLog, environments, projects, secrets, secretVersions } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { postgresOnly } from './db/engine.ts';

const ROOT = 'admin@acme.example';
const LEAD = 'user:lead@acme.example';
const DEV = 'user:dev@acme.example';
const CI = 'token:ci-deploy';
const OWNER = 'user:instance-owner@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let lead: CoffreClient;
let owner: CoffreClient;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  lead = clientFor(deps, 'lead@acme.example');
  owner = clientFor(deps, 'instance-owner@acme.example');
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  await root.members.add(LEAD);
  await root.members.add(DEV);
  await root.members.add(CI);
  await root.members.add(OWNER, { owner: true });
});

const today = () => new Date().toISOString().slice(0, 10);

/** `market`, with values in prod and dev, a lead, a developer on prod, and CI only there. */
async function seedMarket(): Promise<void> {
  await root.projects.create('market', { name: 'Acme Market' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.environments.create('market/dev', { name: 'Development' });
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://prod', API_KEY: 'prod-key' });
  await root.secrets.set('market/prod', { API_KEY: 'prod-key-2' });
  await root.secrets.set('market/dev', { DATABASE_URL: 'postgres://dev' });
  await root.access.set(LEAD, { market: 'owner' });
  await root.access.set(DEV, { 'market/prod': 'developer' });
  await root.access.set(CI, { 'market/prod': 'viewer' });
  // The developer holds something elsewhere too, so is left with access.
  await root.projects.create('web', { name: 'Web' });
  await root.access.set(DEV, { web: 'viewer' });
}

/** Every version under a project, with whether its value is still there. */
async function versionsOf(projectId: string) {
  const rows = await db.owner
    .select({ key: secrets.key, version: secretVersions.version, ciphertext: secretVersions.ciphertext, wrappedDek: secretVersions.wrappedDek, environmentId: secrets.environmentId })
    .from(secretVersions)
    .innerJoin(secrets, eq(secrets.id, secretVersions.secretId))
    .where(eq(secrets.projectId, projectId))
    .orderBy(asc(secrets.key), asc(secretVersions.version));
  return rows.map((row) => ({ ...row, sealed: row.ciphertext.length > 0 || row.wrappedDek.length > 0 }));
}

async function projectRow(id: string) {
  const [row] = await db.owner.select().from(projects).where(eq(projects.id, id));
  return row;
}

async function projectId(slug: string): Promise<string> {
  const [row] = await db.owner.select({ id: projects.id }).from(projects).where(eq(projects.slug, slug));
  return row.id;
}

/** The app's entries of `action`, oldest first, with their metadata. */
async function entries(action: string) {
  const rows = await db.owner
    .select({ decision: auditLog.decision, metadata: auditLog.metadata, operationId: auditLog.operationId, projectId: auditLog.projectId })
    .from(auditLog)
    .where(eq(auditLog.action, action))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}

test('only instance owners delete, and only what is archived; each refusal is logged', async () => {
  await seedMarket();
  await assert.rejects(lead.projects.delete('market'), { status: 403 });
  await assert.rejects(lead.projects.previewDelete('market'), { status: 403 });
  await assert.rejects(root.projects.delete('market'), { status: 409, message: /not archived/ });
  await assert.rejects(root.environments.delete('market/prod'), { status: 409, message: /not archived/ });
  assert.deepEqual(
    [...(await entries('project.delete')), ...(await entries('environment.delete'))].map((entry) => [entry.decision, entry.metadata.reason]),
    [['deny', 'requires_instance_owner'], ['deny', 'requires_instance_owner'], ['deny', 'not_archived'], ['deny', 'not_archived']],
  );
  assert.equal((await versionsOf(await projectId('market'))).every((version) => version.sealed), true);
});

test('a preview says what deleting would take, and changes nothing', async () => {
  await seedMarket();
  await root.projects.update('market', { archived: true });
  const id = await projectId('market');
  const before = await versionsOf(id);
  const { dryRun, deletion } = await owner.projects.previewDelete('market');
  assert.equal(dryRun, true);
  assert.deepEqual(deletion, {
    path: 'market',
    tombstone: `market~deleted-${today()}`,
    environments: ['dev', 'prod'],
    keys: 3,
    versions: 4,
    grants: [
      { member: CI, place: 'market/prod', role: 'viewer' },
      { member: DEV, place: 'market/prod', role: 'developer' },
      { member: LEAD, place: 'market', role: 'owner' },
    ],
    stranded: [CI, LEAD],
  });
  assert.deepEqual(await versionsOf(id), before);
  assert.equal((await projectRow(id)).slug, 'market');
  assert.equal((await deps.vault.access(LEAD)).grants.length, 1);
});

test('deleting a project erases its values, revokes its grants, hides it and frees its slug; the log still verifies', async () => {
  await seedMarket();
  await root.projects.update('market', { archived: true });
  const id = await projectId('market');

  const { dryRun, deletion } = await owner.projects.delete('market');
  assert.equal(dryRun, false);
  assert.equal(deletion.tombstone, `market~deleted-${today()}`);
  assert.equal(deletion.versions, 4);

  // The values are gone for good; the names stay, for the log.
  const versions = await versionsOf(id);
  assert.equal(versions.length, 4);
  assert.deepEqual(versions.filter((version) => version.sealed), []);
  assert.deepEqual([...new Set(versions.map((version) => version.key))], ['API_KEY', 'DATABASE_URL']);
  const tombstone = await projectRow(id);
  assert.equal(tombstone.slug, `market~deleted-${today()}`);
  assert.equal(tombstone.name, 'Acme Market');

  // The vault revoked every grant there, in the deletion's operation.
  assert.deepEqual((await deps.vault.access(LEAD)).grants, []);
  assert.deepEqual((await deps.vault.access(CI)).grants, []);
  assert.deepEqual((await deps.vault.access(DEV)).grants.map((grant) => grant.role), ['viewer']);
  const [entry] = await entries('project.delete');
  assert.deepEqual(entry.metadata, { path: 'market', tombstone: `market~deleted-${today()}`, keys: 3, versions: 4, grants: 3 });
  assert.equal(entry.projectId, id);
  const revocations = await db.owner.select({ operationId: auditLog.operationId }).from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'access.revoke'), eq(auditLog.projectId, id)));
  assert.equal(revocations.length, 3);
  assert.equal(revocations.every((row) => row.operationId === entry.operationId), true);

  // Gone from every list, archived ones included.
  assert.deepEqual((await root.projects.list()).projects.map((project) => project.slug), ['web']);
  assert.deepEqual((await lead.projects.list()).projects, []);
  assert.equal((await root.members.list()).members.some((member) => member.grants.some((grant) => grant.project.includes('market'))), false);
  await assert.rejects(root.secrets.list('market/prod'), { status: 404 });
  await assert.rejects(root.secrets.reveal(`market~deleted-${today()}/prod`), { status: 404 });

  // Its slug is free, and what takes it is another project in the log.
  await root.projects.create('market', { name: 'New Market' });
  assert.notEqual(await projectId('market'), id);
  const { entries: history } = await root.audit.list({ path: `market~deleted-${today()}`, limit: 500 });
  assert.ok(history.some((row) => row.action === 'project.delete'));
  assert.ok(history.every((row) => row.project === `market~deleted-${today()}`));

  assert.equal((await root.audit.verify()).ok, true);
});

test('a second deletion of the same slug on the same day takes the next tombstone', async () => {
  for (const name of ['First', 'Second']) {
    await root.projects.create('market', { name });
    await root.projects.update('market', { archived: true });
    await root.projects.delete('market');
  }
  const slugs = (await db.owner.select({ slug: projects.slug }).from(projects).orderBy(asc(projects.slug))).map((row) => row.slug);
  assert.deepEqual(slugs, [`market~deleted-${today()}`, `market~deleted-${today()}-2`]);
  assert.equal((await root.audit.verify()).ok, true);
});

test('deleting an environment takes it alone, and frees its slug in the project', async () => {
  await seedMarket();
  await root.environments.update('market/prod', { archived: true });
  const id = await projectId('market');
  const [prod] = await db.owner.select({ id: environments.id }).from(environments).where(eq(environments.slug, 'prod'));

  const { deletion } = await root.environments.delete('market/prod');
  assert.deepEqual(
    { ...deletion, grants: deletion.grants.map((grant) => grant.member) },
    { path: 'market/prod', tombstone: `prod~deleted-${today()}`, environments: ['prod'], keys: 2, versions: 3, grants: [CI, DEV], stranded: [CI] },
  );
  const versions = await versionsOf(id);
  assert.deepEqual(versions.filter((version) => version.environmentId === prod.id && version.sealed), []);
  assert.deepEqual(versions.filter((version) => version.sealed).map((version) => version.key), ['DATABASE_URL']);
  assert.equal((await root.secrets.reveal('market/dev/DATABASE_URL')).values.DATABASE_URL, 'postgres://dev');
  // The lead's project grant stays; the environment's grants are gone.
  assert.deepEqual((await deps.vault.access(LEAD)).grants.map((grant) => grant.role), ['owner']);
  assert.deepEqual((await deps.vault.access(CI)).grants, []);

  const [project] = (await root.projects.list()).projects.filter((entry) => entry.slug === 'market');
  assert.deepEqual(project.environments.map((environment) => environment.slug), ['dev']);
  await root.environments.create('market/prod', { name: 'Production, again' });
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://new' });
  assert.equal((await root.secrets.reveal('market/prod/DATABASE_URL')).values.DATABASE_URL, 'postgres://new');
  assert.equal((await root.audit.verify()).ok, true);
});

test('a deletion cut off after the vault revoked its grants finishes when asked again', async () => {
  await seedMarket();
  await root.projects.update('market', { archived: true });
  const id = await projectId('market');

  // The app's transaction fails once, after the vault has committed its revocations.
  let interrupt = false;
  const flaky = new Proxy(db.runtime, {
    get(target, key) {
      if (key === 'transaction' && interrupt) {
        return async () => {
          interrupt = false;
          throw new Error('interrupted');
        };
      }
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as Database;
  const vault = { ...deps.vault, setAccess: async (input: Parameters<typeof deps.vault.setAccess>[0]) => {
    const outcome = await deps.vault.setAccess(input);
    interrupt = true;
    return outcome;
  } };
  const cutOff = clientFor({ ...deps, db: flaky, vault }, ROOT);
  await assert.rejects(cutOff.projects.delete('market'), { status: 500 });

  // Half done: the grants are gone, the values and the slug are not.
  assert.deepEqual((await deps.vault.access(LEAD)).grants, []);
  assert.equal((await projectRow(id)).slug, 'market');
  assert.ok((await versionsOf(id)).some((version) => version.sealed));
  assert.deepEqual(await entries('project.delete'), []);

  const { deletion } = await root.projects.delete('market');
  assert.equal(deletion.versions, 4);
  assert.equal((await projectRow(id)).slug, `market~deleted-${today()}`);
  assert.deepEqual((await versionsOf(id)).filter((version) => version.sealed), []);
  assert.equal((await entries('project.delete')).length, 1);
  assert.equal((await root.audit.verify()).ok, true);
});

/** The current version of `KEY` in `market/<environment>`, as the vault is asked for it. */
async function currentVersion(environment: string, key: string) {
  const [row] = await db.owner
    .select({ id: secretVersions.id, secretId: secrets.id, projectId: secrets.projectId, environmentId: secrets.environmentId, version: secretVersions.version })
    .from(secrets)
    .innerJoin(secretVersions, eq(secretVersions.id, secrets.currentVersionId))
    .innerJoin(environments, eq(environments.id, secrets.environmentId))
    .where(and(eq(environments.slug, environment), eq(secrets.key, key)));
  return row;
}

const unwrapAs = (principal: string, secretVersionId: string) =>
  deps.vault.unwrap({ principal, purpose: 'reveal', requestId: 'r', operationId: crypto.randomUUID(), items: [{ secretVersionId }] });

/**
 * The root admin's client, whose vault runs `meanwhile` once, after its first
 * revocation: something another owner does between a deletion's vault calls
 * and its transaction.
 */
function racedBy(meanwhile: () => Promise<unknown>): CoffreClient {
  let done = false;
  const vault = { ...deps.vault, setAccess: async (input: Parameters<typeof deps.vault.setAccess>[0]) => {
    const outcome = await deps.vault.setAccess(input);
    if (!done) {
      done = true;
      await meanwhile();
    }
    return outcome;
  } };
  return clientFor({ ...deps, vault }, ROOT);
}

test('a grant set while a deletion runs is refused with a 409, and revoked when it is asked again', async () => {
  await seedMarket();
  await root.projects.update('market', { archived: true });
  const id = await projectId('market');
  // The service's grant is revoked first, then given back before the app's transaction.
  const raced = racedBy(() => root.access.set(CI, { 'market/prod': 'viewer' }));
  await assert.rejects(raced.projects.delete('market'), { status: 409, message: /granted while it was being deleted/ });
  assert.equal((await projectRow(id)).slug, 'market');
  assert.ok((await versionsOf(id)).every((version) => version.sealed));
  assert.deepEqual((await deps.vault.access(CI)).grants.map((grant) => grant.role), ['viewer']);
  assert.deepEqual((await entries('project.delete')).map((entry) => [entry.decision, entry.metadata.reason]), [['deny', 'granted_meanwhile']]);

  const { deletion } = await root.projects.delete('market');
  assert.deepEqual(deletion.grants.map((grant) => grant.member), [CI]);
  assert.deepEqual((await deps.vault.access(CI)).grants, []);
  assert.equal((await projectRow(id)).slug, `market~deleted-${today()}`);
  assert.equal((await root.audit.verify()).ok, true);
});

test('a project restored while it is being deleted stays, unerased, and the deletion is refused', async () => {
  await seedMarket();
  await root.projects.update('market', { archived: true });
  const id = await projectId('market');
  const raced = racedBy(() => root.projects.update('market', { archived: false }));
  await assert.rejects(raced.projects.delete('market'), { status: 409, message: /restored while it was being deleted: nothing was erased/ });
  const row = await projectRow(id);
  assert.equal(row.slug, 'market');
  assert.equal(row.archivedAt, null);
  assert.ok((await versionsOf(id)).every((version) => version.sealed));
  assert.equal((await root.secrets.reveal('market/dev/DATABASE_URL')).values.DATABASE_URL, 'postgres://dev');
  assert.deepEqual((await entries('project.delete')).map((entry) => entry.metadata.reason), ['restored']);
});

/**
 * The root admin's client, whose first transaction begins only once
 * `meanwhile` has run: a request whose path the router resolved before
 * another owner's change committed.
 */
function lateBy(meanwhile: () => Promise<unknown>): CoffreClient {
  let pending: (() => Promise<unknown>) | null = meanwhile;
  const late = new Proxy(db.runtime, {
    get(target, key) {
      const value = Reflect.get(target, key, target);
      if (key === 'transaction' && pending !== null) {
        const run = pending;
        pending = null;
        return async (...args: unknown[]) => {
          await run();
          return Reflect.apply(value as (...args: unknown[]) => unknown, target, args);
        };
      }
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as Database;
  return clientFor({ ...deps, db: late }, ROOT);
}

test('a restore or a rename that resolved its place before the place was deleted is refused, and the tombstone stays', async () => {
  await seedMarket();
  await root.environments.update('market/dev', { archived: true });
  const restore = lateBy(() => root.environments.delete('market/dev'));
  await assert.rejects(restore.environments.update('market/dev', { archived: false }), { status: 404 });
  const [dev] = await db.owner.select().from(environments).where(eq(environments.slug, `dev~deleted-${today()}`));
  assert.notEqual(dev.archivedAt, null);

  await root.projects.update('market', { archived: true });
  const id = await projectId('market');
  // Renamed by its id, the tombstone would take a live slug again: listed, grantable, and no longer refused.
  const rename = lateBy(() => root.projects.delete('market'));
  await assert.rejects(rename.projects.update('market', { slug: 'bazaar' }), { status: 404, message: /no project "market"/ });
  assert.equal((await projectRow(id)).slug, `market~deleted-${today()}`);
  assert.equal((await root.audit.verify()).ok, true);
});

test('a key renamed in an environment deleted since its path was found is refused, and the tombstone keeps its names', async () => {
  await seedMarket();
  const { environmentId: devId } = await currentVersion('dev', 'DATABASE_URL');
  const rename = lateBy(async () => {
    await root.environments.update('market/dev', { archived: true });
    await root.environments.delete('market/dev');
  });
  await assert.rejects(rename.secrets.update('market/dev/DATABASE_URL', { key: 'DB_URL' }), { status: 404 });
  const keys = await db.owner.select({ key: secrets.key }).from(secrets).where(eq(secrets.environmentId, devId));
  assert.deepEqual(keys, [{ key: 'DATABASE_URL' }]);
  assert.equal((await root.audit.verify()).ok, true);
});

test('an environment added to a project deleted since its path was found is refused, and nothing is added', async () => {
  await seedMarket();
  const id = await projectId('market');
  const add = lateBy(async () => {
    await root.projects.update('market', { archived: true });
    await root.projects.delete('market');
  });
  await assert.rejects(add.environments.create('market/staging', { name: 'Staging' }), { status: 404, message: /no project "market"/ });
  const under = await db.owner.select({ slug: environments.slug }).from(environments).where(eq(environments.projectId, id));
  assert.deepEqual(under.filter(({ slug }) => slug === 'staging'), []);
  assert.deepEqual(await entries('environment.create').then((all) => all.filter((entry) => entry.metadata.slug === 'staging')), []);
  assert.equal((await root.audit.verify()).ok, true);
});

test('a key decided on before its place is deleted, and released after, is refused as deleted', postgresOnly('on SQLite a decision holds the whole file, so no deletion commits inside one'), async () => {
  await seedMarket();
  await root.environments.update('market/dev', { archived: true });
  const { id } = await currentVersion('dev', 'DATABASE_URL');
  // The lead's grant on the project still covers market/dev, which is deleted
  // alone, while the vault opens its key: after the check, before the release.
  let meanwhile: (() => Promise<unknown>) | null = null;
  class DeletedMeanwhile extends LocalKekProvider {
    override async unwrap(...args: Parameters<LocalKekProvider['unwrap']>): Promise<Buffer> {
      const run = meanwhile;
      meanwhile = null;
      await run?.();
      return super.unwrap(...args);
    }
  }
  const vault = testVault(
    [ROOT],
    { kek: new DeletedMeanwhile(deps.vault.kek, 'test-kek-1'), signingKey: deps.vault.signingKey.toString('base64') },
    { kek: deps.vault.kek },
  );
  const read = () => vault.unwrap({ principal: LEAD, purpose: 'reveal', requestId: 'r', operationId: crypto.randomUUID(), items: [{ secretVersionId: id }] });
  // A first read, which also proves the vault's key on stored keys before it decides anything.
  assert.equal((await read()).ok, true);
  // Chained out here, the deletion runs as its own request would, not inside the vault's transaction.
  let release!: () => void;
  const deleted = new Promise<void>((resolve) => (release = resolve)).then(() => root.environments.delete('market/dev'));
  meanwhile = async () => {
    release();
    await deleted;
  };
  const outcome = await read();
  assert.equal(meanwhile, null);
  assert.deepEqual(outcome.ok ? outcome.keys : outcome.refusal.code, 'deleted');
  const reads = await db.owner
    .select({ decision: auditLog.decision, code: auditLog.code })
    .from(auditLog)
    .where(and(eq(auditLog.action, 'secret.read'), eq(auditLog.secretVersionId, id)))
    .orderBy(asc(auditLog.seq));
  assert.deepEqual(reads, [{ decision: 'allow', code: null }, { decision: 'deny', code: 'deleted' }]);
  assert.equal((await root.audit.verify()).ok, true);
});

test('an environment is deleted only once it is archived itself, whatever its project is', async () => {
  await seedMarket();
  await root.projects.update('market', { archived: true });
  await assert.rejects(root.environments.delete('market/prod'), { status: 409, message: /market\/prod is not archived/ });
  await root.environments.update('market/prod', { archived: true });
  assert.equal((await root.environments.delete('market/prod')).deletion.tombstone, `prod~deleted-${today()}`);
});

test('the vault grants nothing on a deleted place, and still revokes there', async () => {
  await seedMarket();
  const version = await currentVersion('prod', 'API_KEY');
  await db.owner.update(projects).set({ slug: `market~deleted-${today()}` }).where(eq(projects.id, version.projectId));
  const change = (role: 'viewer' | null, environmentId: string | null) => deps.vault.setAccess({
    actor: `user:${ROOT}`, principal: CI, requestId: 'r', operationId: crypto.randomUUID(),
    changes: [{ projectId: version.projectId, environmentId, role, expiresAt: null }],
  });
  for (const environmentId of [null, version.environmentId]) {
    const outcome = await change('viewer', environmentId);
    assert.equal(outcome.ok ? null : outcome.refusal.code, 'deleted');
  }
  const revoked = await change(null, version.environmentId);
  assert.deepEqual(revoked.ok ? revoked.changes : revoked.refusal, ['revoked']);
});

test('the vault refuses a deleted place as deleted, its erased versions included', async () => {
  await seedMarket();
  const version = await currentVersion('prod', 'API_KEY');
  await root.projects.update('market', { archived: true });
  await root.projects.delete('market');
  const outcome = await unwrapAs(`user:${ROOT}`, version.id);
  assert.deepEqual(outcome.ok ? null : outcome.refusal.code, 'deleted');
});

test('a tombstone is refused by the rule, not by its emptied keys: values left in it, and a grant still on it, open nothing', async () => {
  await seedMarket();
  const version = await currentVersion('prod', 'API_KEY');
  // As if the erase had missed it: the slug says deleted, the value and the developer's grant are still there.
  await db.owner.update(projects).set({ slug: `market~deleted-${today()}` }).where(eq(projects.id, version.projectId));
  assert.equal((await deps.vault.access(DEV)).grants.length, 2);

  for (const principal of [DEV, `user:${ROOT}`]) {
    const outcome = await unwrapAs(principal, version.id);
    assert.equal(outcome.ok ? null : outcome.refusal.code, 'deleted', principal);
  }
  const wrapped = await deps.vault.wrap({
    principal: `user:${ROOT}`,
    requestId: 'r',
    operationId: crypto.randomUUID(),
    items: [{
      secret: { projectId: version.projectId, environmentId: version.environmentId, secretId: version.secretId, version: version.version + 1, path: 'market/prod/API_KEY' },
      key: randomBytes(32).toString('base64'),
    }],
  });
  assert.equal(wrapped.ok ? null : wrapped.refusal.code, 'deleted');
  const refusals = await db.owner.select({ action: auditLog.action }).from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.decision, 'deny'), eq(auditLog.code, 'deleted')))
    .orderBy(asc(auditLog.seq));
  assert.deepEqual(refusals.map((row) => row.action), ['secret.read', 'secret.read', 'key.wrap']);
});
