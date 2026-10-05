import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import { randomUUID } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import { createClient, CoffreError } from '@coffre/client';
import { defineSignin, github } from '@coffre/core/identity';
import { and, eq, ne } from 'drizzle-orm';

import { propertySettings } from '../../../scripts/property-settings.ts';
import { clientFor, openTestDatabase, resetDatabase, testVault, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { drainBackgroundTasks } from './background-tasks.ts';
import { auditLog, vaultMembers, vaultGrants, credentials as storedCredentials, identities, environments as storedEnvironments, projects as storedProjects, secrets as storedSecrets, secretReferences, secretVersions } from './db/tables.ts';
import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';

const ROOT = 'admin@acme.example';
const ADA = 'ada@acme.example';
const members = ['ada', 'ci'] as const;
/** Environment slugs: dev and prod exist first; qa, and any slug again once deleted, can be made. */
const slugs = ['dev', 'prod', 'qa'] as const;
type Member = typeof members[number];
type Slug = typeof slugs[number];
type Role = 'viewer' | 'developer';
/** Where a grant is: the project, one environment, every project, or one environment slug in every project. */
type Scope = 'project' | 'environment' | 'every' | 'every-env';
const kinds = [
  'invite', 'grant', 'revoke', 'set', 'read', 'remove', 'issue', 'revoke-token',
  'create-env', 'rename-env', 'archive-env', 'unarchive-env', 'delete-env',
  'archive-project', 'unarchive-project', 'delete-project', 'create-project', 'retire-env', 'retire-project',
  'refer', 'break', 'rotate', 'set-holder', 'forge',
] as const;
type Operation = {
  kind: typeof kinds[number];
  member: Member;
  environment: Slug;
  /** A rename's new slug. */
  to: Slug;
  scope: Scope;
  role: Role;
  value: string;
  credential: number;
};
const operation = gs.record({
  kind: gs.sampledFrom(kinds),
  member: gs.sampledFrom(members),
  environment: gs.sampledFrom(slugs),
  to: gs.sampledFrom(slugs),
  scope: gs.sampledFrom(['project', 'environment', 'every', 'every-env'] as const),
  role: gs.sampledFrom(['viewer', 'developer'] as const),
  value: gs.text({ codec: 'utf-8', maxSize: 12 }),
  credential: gs.integers({ minValue: 0, maxValue: 10 }),
});
const principal = (member: Member) => member === 'ada' ? `user:${ADA}` : 'token:ci';
const settings = propertySettings(4, 10);
/** A modeled environment: its identity (`n`), which grants on it follow through renames, and its slug and value. */
type Environment = { n: number; id: string; slug: Slug; archived: boolean; value: string };
/** A deleted place: its tombstone's path, and what the vault must refuse there for good. */
type Tombstone = { path: string; projectId: string; environmentId: string | null; versionIds: string[] };
let database: Awaited<ReturnType<typeof openTestDatabase>>;
before(async () => { database = await openTestDatabase(); });
after(async () => { await database.close(); });

async function scenario(operations: readonly Operation[]) {
  await resetDatabase(database.owner);
  // Fake deployment keys are fixed so randomness cannot change any verdict.
  const vault = testVault([ROOT], {}, { kek: Buffer.alloc(32, 17) });
  const deps: FixtureDeps = { db: database.runtime, vault, chainKey: Buffer.alloc(32, 23) };
  const signinConfig = defineSignin({ publicUrl: 'https://coffre.test', providers: [github({ clientId: 'property', clientSecret: 'property' })] });
  const signin = new SigninService({ ...deps, signin: signinConfig });
  deps.signin = signin;
  const runtime: CoffreRuntime = {
    ...deps, signin, workloads: null,

    auth: { mode: 'signin', signin: signinConfig },
    publicUrl: 'https://coffre.test', verifier: signin, waitUntil,
  };
  const root = clientFor(deps, ROOT);
  const model = {
    active: { ada: true, ci: true },
    // Each member's roles, by what the grant covers: `project:<generation>`, `env:<n>`, `*` or `*/<slug>`.
    grants: { ada: new Map<string, Role>(), ci: new Map<string, Role>() },
    project: null as { generation: number; id: string; archived: boolean } | null,
    environments: [] as Environment[],
    // billing/prod/VALUE, in a project of its own that stays: a value, or a reference to market/<slug>/VALUE by its source's `n`.
    billing: { projectId: '', value: 'initial billing', reference: null as { source: number; live: boolean } | null },
    /** billing/prod/FORGED: a reference row the database's owner wrote, which the vault never sealed. */
    forged: false,
  };
  let generation = 0;
  let made = 0;
  const tombstones: Tombstone[] = [];
  const environmentAt = (slug: Slug) => model.environments.find((environment) => environment.slug === slug);
  /** The key a grant at this scope is held under, or null when the place it names is not there. */
  function grantKey(op: Pick<Operation, 'scope' | 'environment'>): string | null {
    switch (op.scope) {
      case 'every': return '*';
      case 'every-env': return `*/${op.environment}`;
      case 'project': return model.project === null ? null : `project:${model.project.generation}`;
      case 'environment': {
        const environment = model.project === null ? undefined : environmentAt(op.environment);
        return environment === undefined ? null : `env:${environment.n}`;
      }
    }
  }
  const grantPath = (op: Pick<Operation, 'scope' | 'environment'>) =>
    ({ project: 'market', environment: `market/${op.environment}`, every: '*', 'every-env': `*/${op.environment}` })[op.scope];
  /** A deletion of these environments ends billing's live reference into one of them, and says so. */
  function ends(references: readonly { holder: string; source: string }[], deleted: readonly Environment[]) {
    const { reference } = model.billing;
    const into = reference?.live === true ? deleted.find((each) => each.n === reference.source) : undefined;
    assert.deepEqual(references, into === undefined ? [] : [{ holder: 'billing/prod/VALUE', source: `market/${into.slug}/VALUE` }], 'a deletion ends, and names, the references into what it deletes');
    if (into !== undefined) reference!.live = false;
  }
  function forget(keys: (key: string) => boolean) {
    for (const member of members) for (const key of [...model.grants[member].keys()]) if (keys(key)) model.grants[member].delete(key);
  }
  async function createProject() {
    await root.projects.create('market', { name: 'Market' });
    const [row] = await database.owner.select({ id: storedProjects.id }).from(storedProjects).where(eq(storedProjects.slug, 'market'));
    model.project = { generation: ++generation, id: row.id, archived: false };
    model.environments = [];
  }
  async function createEnvironment(slug: Slug, value: string) {
    await root.environments.create(`market/${slug}`, { name: slug });
    await root.secrets.set(`market/${slug}`, { VALUE: value });
    const [row] = await database.owner.select({ id: storedEnvironments.id }).from(storedEnvironments)
      .where(and(eq(storedEnvironments.projectId, model.project!.id), eq(storedEnvironments.slug, slug)));
    model.environments.push({ n: ++made, id: row.id, slug, archived: false, value });
  }
  async function versionsIn(environmentId: string): Promise<string[]> {
    const rows = await database.owner.select({ id: secretVersions.id }).from(secretVersions)
      .innerJoin(storedSecrets, eq(storedSecrets.id, secretVersions.secretId)).where(eq(storedSecrets.environmentId, environmentId));
    return rows.map((row) => row.id);
  }
  const credentials: { member: Member; id: string; token: string; live: boolean }[] = [];
  function may(member: Member, environment: Environment | undefined, write = false): boolean {
    if (!model.active[member] || model.project === null || model.project.archived || environment === undefined || environment.archived) return false;
    const covering = [`project:${model.project.generation}`, `env:${environment.n}`, '*', `*/${environment.slug}`];
    return covering.some((key) => {
      const role = model.grants[member].get(key);
      return write ? role === 'developer' : role !== undefined;
    });
  }
  /** Whether `member` reads billing/prod/VALUE: a grant on billing/prod, or on prod in every project, and a value or a live reference to a live source. */
  function mayBilling(member: Member | 'root'): boolean {
    if (member !== 'root' && (!model.active[member] || !['billing:prod', '*', '*/prod'].some((key) => model.grants[member].has(key)))) return false;
    const { reference } = model.billing;
    if (reference === null) return true;
    const source = model.environments.find((each) => each.n === reference.source);
    return reference.live && source !== undefined && !source.archived && model.project !== null && !model.project.archived;
  }
  const billingValue = () => {
    const { reference } = model.billing;
    return reference === null ? model.billing.value : model.environments.find((each) => each.n === reference.source)!.value;
  };
  async function session() {
    const signed = await signin.completeSignin({ provider: 'github', subject: 'ada-account', emails: [ADA], name: null }, { requestId: randomUUID(), sourceIp: null, label: 'property' });
    assert.ok(signed.ok);
    if (signed.ok) credentials.push({ member: 'ada', ...signed.credential, live: true });
  }
  async function issue() {
    const issued = await root.tokens.issue('token:ci', { label: 'property', expiresInDays: 30 });
    credentials.push({ member: 'ci', ...issued, live: true });
  }
  function client(member: Member) {
    const token = (credentials.findLast((credential) => credential.member === member && credential.live) ?? credentials.findLast((credential) => credential.member === member))?.token ?? 'coffre_svc_invalid';
    return createClient({ url: 'https://coffre.test', headers: () => ({ authorization: `Bearer ${token}` }), transport: (request) => fetchApi(request, runtime, { sourceIp: null }) });
  }
  async function state() {
    await drainBackgroundTasks();
    return {
      members: await database.owner.select().from(vaultMembers).orderBy(vaultMembers.principal),
      grants: await database.owner.select().from(vaultGrants).orderBy(vaultGrants.principal, vaultGrants.projectId, vaultGrants.environmentId),
      credentials: await database.owner.select().from(storedCredentials).orderBy(storedCredentials.id),
      identities: await database.owner.select().from(identities).orderBy(identities.id),
      allowed: await database.owner.select().from(auditLog).where(eq(auditLog.decision, 'allow')).orderBy(auditLog.seq),
    };
  }
  async function allowed<T>(work: () => Promise<T>, expected: boolean, unchanged = false, status?: number): Promise<T | undefined> {
    const previous = !expected && unchanged ? await state() : undefined;
    try {
      const result = await work();
      assert.equal(expected, true, 'the model refused an operation that the API allowed');
      return result;
    } catch (error) {
      if (!(error instanceof CoffreError)) throw error;
      assert.equal(expected, false, `the model allowed an operation that the API refused: ${error.status} ${error.message}`);
      assert.ok(error.status >= 400 && error.status < 500, 'an outage is not an access refusal');
      if (status !== undefined) assert.equal(error.status, status);
      if (previous) assert.deepEqual(await state(), previous, 'a refused operation changes no member, grant, credential or identity, and adds no allow audit entry');
      return undefined;
    }
  }
  async function read(member: Member, slug: Slug) {
    const previous = await reads();
    const environment = environmentAt(slug);
    const result = await allowed(() => client(member).secrets.reveal(`market/${slug}/VALUE`), may(member, environment) && credentials.some((credential) => credential.member === member && credential.live));
    const current = await reads();
    assert.equal(current.length - previous.length, result ? 1 : 0, 'exactly one allowed audit entry per value read, and none for a refused read');
    if (result) {
      assert.equal(result.values.VALUE, environment!.value, 'the current value remains readable by those granted');
      assert.equal(current.at(-1)!.author, 'vault');
    }
  }
  async function readBilling(member: Member | 'root', key: 'VALUE') {
    const previous = await reads();
    const live = member === 'root' || credentials.some((credential) => credential.member === member && credential.live);
    // The root reads whatever has a value, or a live reference to a live source; a member needs a grant there too.
    const expected = key === 'VALUE' && (member === 'root' ? mayBilling('root') : mayBilling(member) && live);
    const result = await allowed(() => (member === 'root' ? root : client(member)).secrets.reveal(`billing/prod/${key}`), expected);
    const current = await reads();
    assert.equal(current.length - previous.length, result ? 1 : 0, 'exactly one allowed audit entry per value read, and none for a refused read');
    if (!result) return;
    assert.equal(result.values[key], billingValue(), 'billing reads its value, or its live source\'s current one');
    if (model.billing.reference !== null) {
      // Through a reference, a read of the source, in the source's project and, by `also`, in the holder's.
      const entry = current.at(-1)!;
      assert.equal(entry.projectId, model.project!.id, 'a read through a reference is logged as a read of its source');
      assert.equal((JSON.parse(entry.metadata) as { also?: { projectId?: string } }).also?.projectId, model.billing.projectId, '…and in the holder\'s project');
      for (const path of ['market', 'billing']) {
        const { entries } = await root.audit.list({ path, limit: 5 });
        assert.ok(entries.some((listed) => listed.seq === Number(entry.seq)), `the read through the reference is in ${path}'s log`);
      }
    }
  }
  /**
   * A row the vault never sealed is no reference: a read of its key, allowed
   * or refused, releases no value, and the vault logs no read of a key (the
   * app may log an empty read, which names no secret).
   */
  async function readForged(member: Member | 'root') {
    const released = async () => (await reads()).filter((entry) => entry.author === 'vault');
    const previous = await released();
    const values = await (member === 'root' ? root : client(member)).secrets.reveal('billing/prod/FORGED')
      .then((result) => result.values, (error: unknown) => {
        if (!(error instanceof CoffreError) || error.status >= 500) throw error;
        return {};
      });
    assert.deepEqual(values, {}, 'an unsealed reference row releases nothing');
    assert.equal((await released()).length, previous.length, 'and the vault opens no key for it');
  }
  async function reads() {
    return database.owner.select().from(auditLog).where(and(eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'allow'))).orderBy(auditLog.seq);
  }
  async function invariants() {
    for (const credential of credentials) {
      if (credential.live && model.active[credential.member]) await signin.verify(credential.token);
      else await assert.rejects(signin.verify(credential.token), /unknown, expired or revoked/);
    }
    for (const member of members) {
      for (const slug of slugs) await read(member, slug);
    }
    // Every list shows the places the model has, archived included, and no tombstone.
    const listed = (await root.projects.list()).projects;
    assert.deepEqual(listed.map((project) => project.slug), model.project === null ? ['billing'] : ['billing', 'market'], 'the projects listed are the live ones');
    for (const member of members) await readBilling(member, 'VALUE');
    await readBilling('root', 'VALUE');
    if (model.forged) {
      for (const member of [...members, 'root'] as const) await readForged(member);
    }
    assert.deepEqual(
      (listed.find((project) => project.slug === 'market')?.environments ?? []).map((environment) => environment.slug).sort(),
      model.environments.map((environment) => environment.slug).sort(),
      'the environments listed are the live ones',
    );
    // A deleted place is never read or granted again, by its tombstone's path or by its ids at the vault.
    for (const tombstone of tombstones) {
      await allowed(() => root.access.set(principal('ada'), { [tombstone.path]: 'viewer' }), false, true, 404);
      if (tombstone.environmentId !== null) {
        await allowed(() => root.secrets.reveal(`${tombstone.path}/VALUE`), false, false, 404);
      }
      const granted = await vault.setAccess({
        actor: `user:${ROOT}`, principal: principal('ada'), requestId: randomUUID(), operationId: randomUUID(),
        changes: [{ projectId: tombstone.projectId, environmentId: tombstone.environmentId, role: 'viewer', expiresAt: null }],
      });
      assert.equal(granted.ok ? 'granted' : granted.refusal.code, 'deleted', `the vault grants nothing on ${tombstone.path}`);
      for (const secretVersionId of tombstone.versionIds) {
        const opened = await vault.unwrap({ principal: `user:${ROOT}`, purpose: 'reveal', requestId: randomUUID(), operationId: randomUUID(), items: [{ secretVersionId }] });
        assert.equal(opened.ok ? 'opened' : opened.refusal.code, 'deleted', `the vault opens nothing of ${tombstone.path}`);
      }
    }
    await drainBackgroundTasks();
    assert.equal((await root.audit.verify()).ok, true, 'the real app/vault log verification passes after every step');
  }
  await root.members.add(principal('ada'));
  await root.members.add(principal('ci'));
  await session();
  await issue();
  await createProject();
  await createEnvironment('dev', 'initial dev');
  await createEnvironment('prod', 'initial prod');
  await root.access.set(principal('ada'), { 'market/dev': 'viewer' });
  model.grants.ada.set(`env:${environmentAt('dev')!.n}`, 'viewer');
  await root.access.set(principal('ci'), { 'market/prod': 'developer' });
  model.grants.ci.set(`env:${environmentAt('prod')!.n}`, 'developer');
  await root.projects.create('billing', { name: 'Billing' });
  await root.environments.create('billing/prod', { name: 'prod' });
  await root.secrets.set('billing/prod', { VALUE: model.billing.value });
  model.billing.projectId = (await database.owner.select({ id: storedProjects.id }).from(storedProjects).where(eq(storedProjects.slug, 'billing')))[0]!.id;
  for (const member of members) {
    await root.access.set(principal(member), { 'billing/prod': 'viewer' });
    model.grants[member].set('billing:prod', 'viewer');
  }
  await allowed(() => root.members.remove('user:never-admitted@acme.example'), false, true, 404);
  await allowed(() => root.tokens.revoke('token:ci', '00000000-0000-4000-8000-000000000001'), false, true, 404);
  await invariants();
  async function apply(op: Operation): Promise<void> {
    const environment = model.project === null ? undefined : environmentAt(op.environment);
    switch (op.kind) {
      case 'invite': {
        await root.members.add(principal(op.member));
        if (!model.active[op.member]) model.grants[op.member].clear();
        model.active[op.member] = true;
        if (op.member === 'ada') await session();
        else await issue();
        break;
      }
      case 'grant':
      case 'revoke': {
        const where = grantPath(op);
        const key = grantKey(op);
        const previousRole = key === null ? undefined : model.grants[op.member].get(key);
        const permitted = model.active[op.member] && key !== null;
        const noOp = permitted && (op.kind === 'grant' ? previousRole === op.role : previousRole === undefined);
        const previous = noOp ? await state() : undefined;
        const result = await allowed(() => root.access.set(principal(op.member), { [where]: op.kind === 'grant' ? op.role : null }), permitted, true);
        if (result) {
          assert.equal(result.changes[where], noOp ? 'unchanged' : op.kind === 'revoke' ? 'revoked' : previousRole === undefined ? 'created' : 'updated');
          if (op.kind === 'grant') model.grants[op.member].set(key!, op.role);
          else model.grants[op.member].delete(key!);
        }
        if (previous) {
          const current = await state();
          const { allowed: oldEntries, ...oldState } = previous;
          const { allowed: newEntries, ...newState } = current;
          assert.deepEqual(newState, oldState, 'a declarative no-op changes no member, grant, credential or identity');
          const last = oldEntries.at(-1)?.seq ?? -1;
          assert.deepEqual(newEntries.filter((entry) => entry.seq > last && ['access.grant', 'access.revoke'].includes(entry.action)), [], 'a no-op must not claim a grant was changed in the audit log');
        }
        break;
      }
      case 'set': {
        const live = credentials.some((credential) => credential.member === op.member && credential.live);
        const result = await allowed(() => client(op.member).secrets.set(`market/${op.environment}`, { VALUE: op.value }), may(op.member, environment, true) && live);
        if (result) environment!.value = op.value;
        break;
      }
      case 'read': await read(op.member, op.environment); break;
      case 'remove': {
        const result = await allowed(() => root.members.remove(principal(op.member)), model.active[op.member], true, model.active[op.member] ? undefined : 404);
        if (result) {
          model.active[op.member] = false;
          model.grants[op.member].clear();
          for (const credential of credentials) if (credential.member === op.member) credential.live = false;
        }
        break;
      }
      case 'issue': await allowed(issue, model.active.ci, true); break;
      case 'revoke-token': {
        const tokens = credentials.filter((credential) => credential.member === 'ci');
        const selected = tokens[op.credential % tokens.length];
        const result = await allowed(() => root.tokens.revoke('token:ci', selected.id), selected.live, true, selected.live ? undefined : 404);
        if (result) selected.live = false;
        break;
      }
      case 'create-env': {
        // An environment that is there is left as it is; a new one needs a live project.
        if (model.project === null) await allowed(() => root.environments.create(`market/${op.environment}`, { name: op.environment }), false, true, 404);
        else if (environment !== undefined) assert.equal((await root.environments.create(`market/${op.environment}`, { name: op.environment })).created, false);
        else if (model.project.archived) await allowed(() => root.environments.create(`market/${op.environment}`, { name: op.environment }), false, true, 409);
        else await createEnvironment(op.environment, op.value);
        break;
      }
      case 'rename-env': {
        const taken = op.to !== op.environment && environmentAt(op.to) !== undefined;
        const result = await allowed(() => root.environments.update(`market/${op.environment}`, { slug: op.to }), environment !== undefined && !taken, true,
          environment === undefined ? 404 : taken ? 409 : undefined);
        if (result) environment!.slug = op.to;
        break;
      }
      case 'archive-env':
      case 'unarchive-env': {
        const result = await allowed(() => root.environments.update(`market/${op.environment}`, { archived: op.kind === 'archive-env' }), environment !== undefined, true, 404);
        if (result) environment!.archived = op.kind === 'archive-env';
        break;
      }
      case 'archive-project':
      case 'unarchive-project': {
        const result = await allowed(() => root.projects.update('market', { archived: op.kind === 'archive-project' }), model.project !== null, true, 404);
        if (result) model.project!.archived = op.kind === 'archive-project';
        break;
      }
      case 'delete-env': {
        // Only an environment archived itself goes; then its slug is free.
        const versionIds = environment === undefined ? [] : await versionsIn(environment.id);
        const result = await allowed(() => root.environments.delete(`market/${op.environment}`), environment?.archived === true, true,
          environment === undefined ? 404 : environment.archived ? undefined : 409);
        if (result) {
          tombstones.push({ path: `market/${result.deletion.tombstone}`, projectId: model.project!.id, environmentId: environment!.id, versionIds });
          ends(result.deletion.references, [environment!]);
          model.environments = model.environments.filter((each) => each !== environment);
          forget((key) => key === `env:${environment!.n}`);
        }
        break;
      }
      case 'delete-project': {
        const going = model.project === null ? [] : await Promise.all(model.environments.map(async (each) => ({ each, versionIds: await versionsIn(each.id) })));
        const result = await allowed(() => root.projects.delete('market'), model.project?.archived === true, true,
          model.project === null ? 404 : model.project.archived ? undefined : 409);
        if (result) {
          const { id, generation: gone } = model.project!;
          tombstones.push({ path: result.deletion.tombstone, projectId: id, environmentId: null, versionIds: [] });
          for (const { each, versionIds } of going) {
            tombstones.push({ path: `${result.deletion.tombstone}/${each.slug}`, projectId: id, environmentId: each.id, versionIds });
          }
          ends(result.deletion.references, going.map(({ each }) => each));
          forget((key) => key === `project:${gone}` || going.some(({ each }) => key === `env:${each.n}`));
          model.project = null;
          model.environments = [];
        }
        break;
      }
      case 'create-project': {
        if (model.project === null) await createProject();
        else assert.equal((await root.projects.create('market', { name: 'Market' })).created, false);
        break;
      }
      case 'refer': {
        // billing/prod/VALUE made a reference to market/<slug>/VALUE, by the root: a live source, or a refusal.
        const live = model.project !== null && !model.project.archived && environment !== undefined && !environment.archived;
        const result = await allowed(() => root.secrets.set('billing/prod', { VALUE: { ref: `market/${op.environment}/VALUE` } }), live, true, 404);
        if (result) model.billing.reference = { source: environment!.n, live: true };
        break;
      }
      case 'break': {
        const { reference } = model.billing;
        const result = await allowed(() => root.references.break('billing/prod/VALUE'), reference?.live === true, true, reference === null ? 404 : 409);
        if (result) reference!.live = false;
        break;
      }
      case 'rotate': {
        // The source's side writes a new value; a live reference reads it next.
        const writable = model.project !== null && !model.project.archived && environment !== undefined && !environment.archived;
        const result = await allowed(() => root.secrets.set(`market/${op.environment}`, { VALUE: op.value }), writable);
        if (result) environment!.value = op.value;
        break;
      }
      case 'set-holder': {
        // A value of billing's own: it ends the reference, replaced.
        await root.secrets.set('billing/prod', { VALUE: op.value });
        model.billing.reference = null;
        model.billing.value = op.value;
        break;
      }
      case 'forge': {
        // The database's owner writes a reference row the vault never sealed: its seq is an entry, but no reference.create.
        const source = model.environments.find((each) => each.slug === op.environment) ?? model.environments[0];
        if (model.forged || source === undefined) break;
        const [billing] = await database.owner.select({ environmentId: storedEnvironments.id }).from(storedEnvironments)
          .where(and(eq(storedEnvironments.projectId, model.billing.projectId), eq(storedEnvironments.slug, 'prod')));
        const [sourceSecret] = await database.owner.select({ id: storedSecrets.id }).from(storedSecrets)
          .where(and(eq(storedSecrets.environmentId, source.id), eq(storedSecrets.key, 'VALUE')));
        const [unsealed] = await database.owner.select({ seq: auditLog.seq }).from(auditLog).where(eq(auditLog.action, 'project.create')).limit(1);
        const holder = randomUUID();
        await database.owner.insert(storedSecrets).values({ id: holder, projectId: model.billing.projectId, environmentId: billing!.environmentId, key: 'FORGED' });
        await database.owner.insert(secretReferences).values({
          id: randomUUID(), projectId: model.billing.projectId, environmentId: billing!.environmentId, secretId: holder,
          sourceProjectId: model.project!.id, sourceEnvironmentId: source.id, sourceSecretId: sourceSecret!.id,
          createdSeq: unsealed!.seq, createdBy: 'user:mallory@acme.example',
        });
        model.forged = true;
        // And the genuine row, if billing follows one, edited to name another source: what it reads, and where it shows, stay the seal's.
        const { reference } = model.billing;
        const other = model.environments.find((each) => each.n !== reference?.source);
        if (reference?.live === true && other !== undefined) {
          const [otherSecret] = await database.owner.select({ id: storedSecrets.id }).from(storedSecrets)
            .where(and(eq(storedSecrets.environmentId, other.id), eq(storedSecrets.key, 'VALUE')));
          await database.owner.update(secretReferences)
            .set({ sourceEnvironmentId: other.id, sourceSecretId: otherSecret!.id })
            .where(and(eq(secretReferences.projectId, model.billing.projectId), eq(secretReferences.sourceProjectId, model.project!.id), ne(secretReferences.secretId, holder)));
        }
        break;
      }
      // Archived, then deleted, as one step: so random sequences reach deletions, which need both.
      case 'retire-env': {
        await apply({ ...op, kind: 'archive-env' });
        await apply({ ...op, kind: 'delete-env' });
        break;
      }
      case 'retire-project': {
        await apply({ ...op, kind: 'archive-project' });
        await apply({ ...op, kind: 'delete-project' });
        break;
      }
    }
  }
  for (const [index, op] of operations.entries()) {
    await apply(op);
    try { await invariants(); }
    catch (error) { throw new Error(`after operation ${index}: ${JSON.stringify(op)}`, { cause: error }); }
  }
}

test('API operation sequence covers invitation, grants, values, removal, re-admission and token revocation', () => {
  const base: Operation = { kind: 'read', member: 'ada', environment: 'prod', to: 'qa', scope: 'environment', role: 'viewer', value: 'changed', credential: 0 };
  return scenario([
    { ...base, kind: 'grant' },
    { ...base, kind: 'grant' },
    { ...base, kind: 'set', member: 'ci' },
    base,
    { ...base, kind: 'revoke' },
    { ...base, kind: 'revoke' },
    { ...base, kind: 'issue' },
    { ...base, kind: 'revoke-token' },
    { ...base, kind: 'revoke-token' },
    { ...base, kind: 'remove' },
    { ...base, kind: 'remove' },
    { ...base, kind: 'invite' },
    { ...base, kind: 'remove', member: 'ci' },
    { ...base, kind: 'invite', member: 'ci' },
  ]);
});

test('API operation sequence covers every project, renames, archiving, deletion and a slug used again', () => {
  const base: Operation = { kind: 'read', member: 'ada', environment: 'qa', to: 'qa', scope: 'every-env', role: 'viewer', value: 'qa one', credential: 0 };
  return scenario([
    // qa in every project, before any qa exists; then a qa, which it reads.
    { ...base, kind: 'grant' },
    { ...base, kind: 'create-env' },
    { ...base, kind: 'grant', member: 'ci', scope: 'environment', role: 'developer' },
    { ...base, kind: 'set', member: 'ci', value: 'qa two' },
    // prod renamed qa is refused, the slug taken; qa renamed dev, too; dev's grant follows dev.
    { ...base, kind: 'rename-env', environment: 'prod' },
    { ...base, kind: 'rename-env', to: 'dev' },
    // Archived, deleted, and made again: ci's grant was on the old qa, ada's is on the slug.
    { ...base, kind: 'delete-env' },
    { ...base, kind: 'archive-env' },
    { ...base, kind: 'unarchive-env' },
    { ...base, kind: 'archive-env' },
    { ...base, kind: 'delete-env' },
    { ...base, kind: 'create-env', value: 'qa again' },
    { ...base, kind: 'set', member: 'ci', value: 'refused' },
    // Every project, as a developer, then the project's whole life.
    { ...base, kind: 'grant', member: 'ci', scope: 'every', role: 'developer' },
    { ...base, kind: 'set', member: 'ci', environment: 'dev', value: 'dev by every project' },
    { ...base, kind: 'delete-project' },
    { ...base, kind: 'archive-project' },
    { ...base, kind: 'create-env', environment: 'prod' },
    { ...base, kind: 'unarchive-project' },
    { ...base, kind: 'archive-project' },
    { ...base, kind: 'delete-project' },
    { ...base, kind: 'create-env' },
    { ...base, kind: 'create-project' },
    { ...base, kind: 'create-env', value: 'qa in the new market' },
    { ...base, kind: 'revoke', scope: 'every-env' },
    { ...base, kind: 'revoke', member: 'ci', scope: 'every' },
    { ...base, kind: 'remove', member: 'ci' },
  ]);
});

test('API operation sequence covers references: made, read in both projects, rotated, broken, replaced, deleted with their source, and forged', () => {
  const base: Operation = { kind: 'refer', member: 'ada', environment: 'prod', to: 'qa', scope: 'every-env', role: 'viewer', value: 'rotated', credential: 0 };
  return scenario([
    base,
    { ...base, kind: 'rotate' },
    { ...base, kind: 'refer' },
    // The source archived, then back: the reference with it.
    { ...base, kind: 'archive-env' },
    { ...base, kind: 'unarchive-env' },
    { ...base, kind: 'rename-env', to: 'qa' },
    { ...base, kind: 'rotate', environment: 'qa', value: 'after the rename' },
    { ...base, kind: 'break' },
    { ...base, kind: 'break' },
    { ...base, kind: 'refer', environment: 'dev' },
    { ...base, kind: 'set-holder', value: 'billing of its own' },
    { ...base, kind: 'break' },
    { ...base, kind: 'refer', environment: 'dev' },
    // prod in every project reaches billing/prod, and so its reference.
    { ...base, kind: 'revoke', scope: 'environment' },
    { ...base, kind: 'grant', member: 'ci', scope: 'every-env', environment: 'prod' },
    { ...base, kind: 'forge', environment: 'dev' },
    // Its source deleted: the reference ends, and the deletion says so.
    { ...base, kind: 'retire-env', environment: 'dev' },
    { ...base, kind: 'refer', environment: 'qa' },
    { ...base, kind: 'retire-project' },
    { ...base, kind: 'create-project' },
    { ...base, kind: 'create-env', environment: 'prod', value: 'a new market' },
    { ...base, kind: 'refer' },
  ]);
});

test(`random API operations preserve the model after every step, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const operations = tc.draw(gs.arrays(operation, { minSize: 4, maxSize: 14 }));
  tc.note(`operations: ${JSON.stringify(operations)}`);
  await scenario(operations);
}, settings));
