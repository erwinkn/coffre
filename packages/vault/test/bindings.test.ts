// A service's trust bindings are the vault's to make and end (T149, PR 3a; credentials.ts; migration 0037): a binding a
// person makes is weighed as a service token's issue is and sealed, a change of the log; one ended takes every live
// credential it issued with it, in one statement; and a sign-in takes only a binding the vault sealed (formal/Lifecycle.tla's
// BindingSealed, its bind and unbind). Both engines unless a case says otherwise.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { issuedGrant, storedScope } from '@coffre/core/access';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { ChangeBindingsInput, CredentialColumns, MadeBinding, SignInInput } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { postgresSession } from '@coffre/db/connect';
import { asc, eq } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { objectKey } from '../src/inputs.ts';
import { emptyDatabase, newProject, openLocalVault, openTestDatabase, OWNER_URL, postgresOnly, sealed, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADMIN = 'user:admin@acme.example';
const CI = 'token:ci';
const ISSUER = 'https://token.actions.githubusercontent.com';
const APP_KEY = 'app:0123456789abcdef';

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

/** A vault keeping 0.15's log; an Owner, an Admin who is no Owner, and a service account that views a project. */
async function world() {
  const vault = await openLocalVault(db.vault, configure(), { log: '0.15', sealThrough: sealed });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'admin' })).ok);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  return { vault, project };
}

type World = Awaited<ReturnType<typeof world>>;

/** A binding of CI's, as the app asks the vault to make it: by the Owner, viewing the project, reading sensitive values when `sensitive`. */
function binding(w: World, sensitive = false, by = ROOT): MadeBinding {
  return {
    id: randomUUID(), principal: CI, generation: 0, profile: 'github', issuer: ISSUER, jwksUri: `${ISSUER}/.well-known/jwks`, claims: JSON.stringify({ repository_id: '1' }),
    scope: storedScope([{ ...issuedGrant({ projectId: w.project, environmentId: null, role: 'viewer' }), sensitive }]), policy: null, revoked: false,
    jwks: null, label: 'deploys', createdBy: by.slice('user:'.length), createdAt: Date.now(), authMac: randomBytes(32).toString('base64'),
  };
}

function change(input: Partial<ChangeBindingsInput>): ChangeBindingsInput {
  return {
    actor: ROOT, via: null, actorAccess: null, make: null, ends: [], reason: 'unbound', revokedAt: Date.now(), revokedBy: 'root@acme.example',
    policy: { seq: null, protected: [] }, appKey: APP_KEY, ...input,
  };
}

/** A binding as its row is now, with its seal: what a sign-in names, and what ending it names. */
async function read(id: string): Promise<{ columns: SignInInput['binding']['columns']; seal: string | null; authMac: string }> {
  const { serviceBindings } = tablesOf(db.owner);
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, id));
  return {
    columns: {
      id, principal: row!.principal, generation: row!.generation, profile: row!.profile, issuer: row!.issuer, jwksUri: row!.jwksUri, claims: row!.claims,
      scope: row!.scope, policy: row!.policy, revoked: row!.revokedAt !== null,
    },
    seal: row!.seal === null ? null : Buffer.from(row!.seal).toString('base64'),
    authMac: Buffer.from(row!.authMac).toString('base64'),
  };
}

/** A CI run's sign-in through binding `id`, as the app asks it. */
async function signIn(w: World, id: string): Promise<{ outcome: Awaited<ReturnType<NonNullable<World['vault']['signIn']>>>; credential: string }> {
  const { columns, seal } = await read(id);
  const credential = randomUUID();
  const now = Date.now();
  const outcome = await w.vault.signIn!({
    principal: CI, binding: { columns, seal },
    credential: {
      id: credential, kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'coffre_svc_x', label: 'deploys', scope: columns.scope,
      places: null, expiresAt: now + 5 * 60_000, notAfter: null, jkt: null, authMac: randomBytes(32).toString('base64'),
    },
    appKey: APP_KEY, spent: randomBytes(32).toString('base64'), validUntil: now + 60_000, record: { proof: 'oidc', issuer: ISSUER, run: { run_id: '7001' } },
  });
  return { outcome, credential };
}

/** Binding `id` ended, with the live credentials named (all it issued, unless `credentials` says otherwise). */
async function ending(id: string, credentials?: string[]): Promise<ChangeBindingsInput['ends'][number]> {
  const { credentials: table } = tablesOf(db.owner);
  const { columns, seal, authMac } = await read(id);
  const rows = (await db.owner.select().from(table).where(eq(table.createdBy, `binding:${id}`))).filter((row) => row.revokedAt === null && (credentials === undefined || credentials.includes(row.id)));
  return {
    before: { columns, seal: seal! }, authMacFrom: authMac, authMac: randomBytes(32).toString('base64'),
    credentials: rows.map((row) => ({
      before: {
        columns: { id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: false, generation: row.generation, expiresAt: row.expiresAt.getTime() } satisfies CredentialColumns,
        seal: Buffer.from(row.seal!).toString('base64'),
      },
      authMacFrom: Buffer.from(row.authMac).toString('base64'), authMac: randomBytes(32).toString('base64'),
    })),
  };
}

async function ops(object: { kind: 'binding' | 'credential'; id: string }): Promise<string[]> {
  const { logChanges } = tablesOf(db.owner);
  return (await db.owner.select({ payload: logChanges.payload }).from(logChanges).where(eq(logChanges.object, objectKey(object))).orderBy(asc(logChanges.number)))
    .map(({ payload }) => (JSON.parse(payload) as { op: string }).op);
}

test("a binding the Owner makes is a change of the log, its row the object it seals, its record who made it (D147); a run signs in through it", async () => {
  const w = await world();
  const made = binding(w, true);
  const outcome = await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const { logChanges } = tablesOf(db.owner);
  const [row] = await db.owner.select().from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'binding', id: made.id })));
  assert.deepEqual((JSON.parse(row!.payload) as { bind: unknown }).bind, { by: ROOT, via: null, label: 'deploys', replaces: [] });
  assert.equal((await read(made.id)).seal, Buffer.from(row!.seal!).toString('base64'), "the row carries its object's seal");
  assert.ok((await signIn(w, made.id)).outcome.ok);
});

test("only an Owner of its project gives a binding's runs sensitive reads (R32); a service account gives none; nothing written", async () => {
  const w = await world();
  const byAdmin = await w.vault.changeBindings!(change({ actor: ADMIN, make: binding(w, true, ADMIN), reason: 'replaced' }));
  assert.equal(!byAdmin.ok && byAdmin.refused, 'refused');
  assert.ok((await w.vault.changeBindings!(change({ actor: ADMIN, make: binding(w, false, ADMIN), reason: 'replaced' }))).ok, 'no sensitive read, the Admin may');
  const bySelf = await w.vault.changeBindings!(change({ actor: CI, make: { ...binding(w), createdBy: 'ci' }, reason: 'replaced' }));
  assert.equal(!bySelf.ok && bySelf.refused, 'refused');
  const { serviceBindings } = tablesOf(db.owner);
  assert.equal((await db.owner.select().from(serviceBindings)).length, 1);
});

test('a binding 0.14 made, which the log never held, or one whose row was edited around the vault, signs nobody in (BindingSealed)', async () => {
  const w = await world();
  const { serviceBindings } = tablesOf(db.owner);
  // As 0.14 wrote one: no seal, no change.
  const old = binding(w);
  await db.owner.insert(serviceBindings).values({ ...old, authMac: Buffer.from(old.authMac, 'base64'), createdAt: new Date(old.createdAt), revoked: undefined } as never);
  assert.deepEqual((await signIn(w, old.id)).outcome, { ok: false, refused: 'unsealed' });
  // One the vault sealed, its keys moved to the app's own around it: the row is not the object its seal covers.
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const sealedAs = await read(made.id);
  await db.owner.update(serviceBindings).set({ jwksUri: 'https://evil.example/jwks' }).where(eq(serviceBindings.id, made.id));
  assert.deepEqual((await signIn(w, made.id)).outcome, { ok: false, refused: 'unsealed' }, 'named as the row is now');
  // Named as it was sealed, the statement holds the row to it.
  const now = Date.now();
  const asSealed = await w.vault.signIn!({
    principal: CI, binding: { columns: sealedAs.columns, seal: sealedAs.seal },
    credential: {
      id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'x', label: null, scope: sealedAs.columns.scope,
      places: null, expiresAt: now + 60_000, notAfter: null, jkt: null, authMac: randomBytes(32).toString('base64'),
    },
    appKey: APP_KEY, spent: randomBytes(32).toString('base64'), validUntil: now + 60_000, record: { proof: 'oidc', issuer: ISSUER, run: {} },
  });
  assert.deepEqual(asSealed, { ok: false, refused: 'unbound' });
});

test("an unbind ends the binding and every live credential it issued, each a change, in one statement; a sign-in after is none", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const first = await signIn(w, made.id);
  const second = await signIn(w, made.id);
  assert.ok(first.outcome.ok && second.outcome.ok);
  const outcome = await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.deepEqual(await ops({ kind: 'binding', id: made.id }), ['binding.make', 'binding.revoke']);
  for (const { credential } of [first, second]) assert.deepEqual(await ops({ kind: 'credential', id: credential }), ['credential.issue', 'credential.revoke']);
  const { credentials } = tablesOf(db.owner);
  assert.ok((await db.owner.select().from(credentials)).every((row) => row.revokedAt !== null));
  assert.equal((await read(made.id)).columns.revoked, true);
  // Through it again, as it was sealed before its end: the statement sees the end.
  assert.deepEqual((await signIn(w, made.id)).outcome, { ok: false, refused: 'unsealed' });
});

test("an unbind that names not every live credential its binding issued (one signed in meanwhile) is read again: nothing written", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const first = await signIn(w, made.id);
  const named = await ending(made.id);
  const meanwhile = await signIn(w, made.id);
  assert.ok(first.outcome.ok && meanwhile.outcome.ok);
  assert.deepEqual(await w.vault.changeBindings!(change({ ends: [named] })), { ok: false, refused: 'moved' });
  assert.deepEqual(await ops({ kind: 'binding', id: made.id }), ['binding.make']);
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok, 'read again, it goes');
});

test("a binding that replaces another ends it, and what it issued, in the same statement: the new one's runs sign in, the old one's do not", async () => {
  const w = await world();
  const old = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: old, reason: 'replaced' }))).ok);
  const run = await signIn(w, old.id);
  assert.ok(run.outcome.ok);
  const next = binding(w);
  const outcome = await w.vault.changeBindings!(change({ make: next, ends: [await ending(old.id)], reason: 'keys_moved' }));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.deepEqual(await ops({ kind: 'binding', id: old.id }), ['binding.make', 'binding.revoke']);
  assert.deepEqual(await ops({ kind: 'credential', id: run.credential }), ['credential.issue', 'credential.revoke']);
  assert.ok((await signIn(w, next.id)).outcome.ok);
  // Ending what is not the log's: a binding sealed under no key of the vault's.
  const forged = await ending(next.id);
  assert.deepEqual(await w.vault.changeBindings!(change({ ends: [{ ...forged, before: { ...forged.before, seal: randomBytes(16).toString('base64') } }] })), { ok: false, refused: 'tampered' });
});

test("an unbind takes the fence for its statement; a bind that ends nothing takes none (RevokeTakesFence, IssueOffFence, R58)", postgresOnly('the fence is an advisory lock'), async () => {
  const w = await world();
  const holder = postgresSession(OWNER_URL);
  try {
    // A change holds the fence exclusive: a bind goes ahead, an unbind waits for it.
    await holder.unsafe('BEGIN');
    await holder.unsafe('SELECT pg_advisory_xact_lock(1668244070, 0)');
    const made = binding(w);
    assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok, 'made while the fence is held');
    let ended = false;
    const unbinding = w.vault.changeBindings!(change({ ends: [await ending(made.id)] })).then((outcome) => ((ended = true), outcome));
    await sleep(200);
    assert.equal(ended, false, 'the unbind waits for the fence');
    await holder.unsafe('COMMIT');
    assert.ok((await unbinding).ok);
  } finally {
    await holder.end();
  }
});

test("a binding's maker whose access moved since the app weighed it is refused, for the app to weigh again", async () => {
  const w = await world();
  const { vaultMembers } = tablesOf(db.owner);
  const [{ accessSeq }] = (await db.owner.select({ accessSeq: vaultMembers.accessSeq }).from(vaultMembers).where(eq(vaultMembers.principal, ROOT))) as [{ accessSeq: bigint }];
  const stale = await w.vault.changeBindings!(change({ make: binding(w), reason: 'replaced', actorAccess: String(BigInt(accessSeq) + 1n) }));
  assert.equal(!stale.ok && stale.refused, 'access');
  const { serviceBindings } = tablesOf(db.owner);
  assert.equal((await db.owner.select().from(serviceBindings)).length, 0);
});
