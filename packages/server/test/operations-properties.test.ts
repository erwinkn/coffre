import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import { randomUUID } from 'node:crypto';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import { createClient, CoffreError } from '@coffre/client';
import { defineSignin, github } from '@coffre/core/identity';
import { and, eq } from 'drizzle-orm';

import { propertySettings } from '../../../scripts/property-settings.ts';
import { clientFor, openTestDatabase, resetDatabase, testVault, waitUntil, type FixtureDeps } from './api-fixture.ts';
import { drainBackgroundTasks } from './background-tasks.ts';
import { auditLog, vaultMembers, vaultGrants, credentials as storedCredentials, identities } from './db/tables.ts';
import { SigninService } from '../src/api/signin.ts';
import { fetchApi } from '../src/fetch-api.ts';
import type { CoffreRuntime } from '../src/runtime.ts';

const ROOT = 'admin@acme.example';
const ADA = 'ada@acme.example';
const members = ['ada', 'ci'] as const;
const places = ['dev', 'prod'] as const;
type Member = typeof members[number];
type Environment = typeof places[number];
type Role = 'viewer' | 'developer';
type Operation = {
  kind: 'invite' | 'grant' | 'revoke' | 'set' | 'read' | 'remove' | 'issue' | 'revoke-token';
  member: Member;
  environment: Environment;
  project: boolean;
  role: Role;
  value: string;
  credential: number;
};
const operation = gs.record({
  kind: gs.sampledFrom(['invite', 'grant', 'revoke', 'set', 'read', 'remove', 'issue', 'revoke-token'] as const),
  member: gs.sampledFrom(members),
  environment: gs.sampledFrom(places),
  project: gs.booleans(),
  role: gs.sampledFrom(['viewer', 'developer'] as const),
  value: gs.text({ codec: 'utf-8', maxSize: 12 }),
  credential: gs.integers({ minValue: 0, maxValue: 10 }),
});
const principal = (member: Member) => member === 'ada' ? `user:${ADA}` : 'token:ci';
const settings = propertySettings(4, 10);
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
    ...deps, signin, workloads: null, mcp: null,

    auth: { mode: 'signin', signin: signinConfig },
    publicUrl: 'https://coffre.test', verifier: signin, waitUntil,
  };
  const root = clientFor(deps, ROOT);
  const model = {
    active: { ada: true, ci: true },
    grants: { ada: new Map<string, Role>(), ci: new Map<string, Role>() },
    values: { dev: 'initial dev', prod: 'initial prod' },
  };
  const credentials: { member: Member; id: string; token: string; live: boolean }[] = [];
  function may(member: Member, environment: Environment, write = false): boolean {
    if (!model.active[member]) return false;
    const roles = [model.grants[member].get('market'), model.grants[member].get(`market/${environment}`)];
    return roles.some((role) => write ? role === 'developer' : role === 'viewer' || role === 'developer');
  }
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
  async function read(member: Member, environment: Environment) {
    const previous = await reads();
    const result = await allowed(() => client(member).secrets.reveal(`market/${environment}/VALUE`), may(member, environment) && credentials.some((credential) => credential.member === member && credential.live));
    const current = await reads();
    assert.equal(current.length - previous.length, result ? 1 : 0, 'exactly one allowed audit entry per value read, and none for a refused read');
    if (result) {
      assert.equal(result.values.VALUE, model.values[environment], 'the current value remains readable by those granted');
      assert.equal(current.at(-1)!.author, 'vault');
    }
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
      for (const environment of places) await read(member, environment);
    }
    await drainBackgroundTasks();
    assert.equal((await root.audit.verify()).ok, true, 'the real app/vault log verification passes after every step');
  }
  await root.members.add(principal('ada'));
  await root.members.add(principal('ci'));
  await session();
  await issue();
  await root.projects.create('market', { name: 'Market' });
  for (const environment of places) {
    await root.environments.create(`market/${environment}`, { name: environment });
    await root.secrets.set(`market/${environment}`, { VALUE: model.values[environment] });
  }
  await root.access.set(principal('ada'), { 'market/dev': 'viewer' });
  model.grants.ada.set('market/dev', 'viewer');
  await root.access.set(principal('ci'), { 'market/prod': 'developer' });
  model.grants.ci.set('market/prod', 'developer');
  await allowed(() => root.members.remove('user:never-admitted@acme.example'), false, true, 404);
  await allowed(() => root.tokens.revoke('token:ci', '00000000-0000-4000-8000-000000000001'), false, true, 404);
  await invariants();
  for (const [index, op] of operations.entries()) {
    const where = op.project ? 'market' : `market/${op.environment}`;
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
        const previousRole = model.grants[op.member].get(where);
        const noOp = model.active[op.member] && (op.kind === 'grant' ? previousRole === op.role : previousRole === undefined);
        const previous = noOp ? await state() : undefined;
        const result = await allowed(() => root.access.set(principal(op.member), { [where]: op.kind === 'grant' ? op.role : null }), model.active[op.member], true);
        if (result) {
          assert.equal(result.changes[where], noOp ? 'unchanged' : op.kind === 'revoke' ? 'revoked' : previousRole === undefined ? 'created' : 'updated');
          if (op.kind === 'grant') model.grants[op.member].set(where, op.role);
          else model.grants[op.member].delete(where);
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
        const result = await allowed(() => client(op.member).secrets.set(`market/${op.environment}`, { VALUE: op.value }), may(op.member, op.environment, true) && !!live);
        if (result) model.values[op.environment] = op.value;
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
    }
    try { await invariants(); }
    catch (error) { throw new Error(`after operation ${index}: ${JSON.stringify(op)}`, { cause: error }); }
  }
}

test('API operation sequence covers invitation, grants, values, removal, re-admission and token revocation', () => {
  const base: Operation = { kind: 'read', member: 'ada', environment: 'prod', project: false, role: 'viewer', value: 'changed', credential: 0 };
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

test(`random API operations preserve the model after every step, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const operations = tc.draw(gs.arrays(operation, { minSize: 1, maxSize: 8 }));
  tc.note(`operations: ${JSON.stringify(operations)}`);
  await scenario(operations);
}, settings));
