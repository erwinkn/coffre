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
import { loggedChange, type ChangeKeys } from '../src/changes.ts';
import { objectKey, sealKey } from '../src/inputs.ts';
import { authentic, changeEntry, logMacKey } from '../src/log-entry.ts';
import { replay } from '../src/log-replay.ts';
import { emptyDatabase, newEnvironment, newProject, openLocalVault, openTestDatabase, OWNER_URL, postgresOnly, sealed, type TestDatabase } from './database.ts';

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
  const config = configure();
  const vault = await openLocalVault(db.vault, config, { log: '0.15', sealThrough: sealed });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'admin' })).ok);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  const keys: ChangeKeys = { seals: config.signingKeys.map((seed) => sealKey(seed)), mac: logMacKey(config.signingKeys[0]!) };
  return { vault, project, keys };
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

/** A change as the app asks it; with a binding made, beside the account's live bindings `live` (none unless named). */
function change(input: Partial<ChangeBindingsInput>): ChangeBindingsInput {
  return {
    actor: ROOT, via: null, actorAccess: null, connection: null, make: null, ends: [], reason: 'unbound', revokedAt: Date.now(), revokedBy: 'root@acme.example',
    policy: { seq: null, protected: [] }, appKey: APP_KEY, reads: [], ...input,
    live: input.live ?? (input.make == null ? null : []),
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
        seal: row.seal === null ? null : Buffer.from(row.seal).toString('base64'),
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
  assert.ok((await w.vault.changeBindings!(change({ make: made, live: [old.id], reason: 'replaced' }))).ok);
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
  const outcome = await w.vault.changeBindings!(change({ make: next, live: [old.id], ends: [await ending(old.id)], reason: 'keys_moved' }));
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

test("a credential with no seal its sealed binding issued (one planted around the vault) is ended with it; the binding's object ends all the same (review r1)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const run = await signIn(w, made.id);
  assert.ok(run.outcome.ok);
  const { credentials } = tablesOf(db.owner);
  const planted = randomUUID();
  await db.owner.insert(credentials).values({
    id: planted, kind: 'service', authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, principal: CI,
    createdBy: `binding:${made.id}`, expiresAt: new Date(Date.now() + 300_000),
  });
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
  assert.deepEqual(await ops({ kind: 'binding', id: made.id }), ['binding.make', 'binding.revoke']);
  assert.deepEqual(await ops({ kind: 'credential', id: planted }), [], 'none of the log\'s: no change of it');
  assert.ok((await db.owner.select().from(credentials)).every((row) => row.revokedAt !== null), 'both ended');
});

test("a bind weighed beside the account's bindings as they were is read again when another was made meanwhile, or a key it reads renamed (review r1)", async () => {
  const w = await world();
  assert.ok((await w.vault.changeBindings!(change({ make: binding(w), reason: 'replaced' }))).ok);
  // Beside none, as it read them before the first was made.
  assert.deepEqual(await w.vault.changeBindings!(change({ make: binding(w), live: [], reason: 'replaced' })), { ok: false, refused: 'moved' });
  // A key its policy reads, asked by a name it no longer has.
  const { secrets, serviceBindings } = tablesOf(db.owner);
  const environment = await newEnvironment(db.owner, w.project);
  const key = randomUUID();
  await db.owner.insert(secrets).values({ id: key, projectId: w.project, environmentId: environment, key: 'RENAMED' });
  const live = (await db.owner.select({ id: serviceBindings.id }).from(serviceBindings)).map(({ id }) => id);
  assert.deepEqual(await w.vault.changeBindings!(change({ make: binding(w), live, reads: [{ id: key, key: 'API_KEY' }], reason: 'replaced' })), { ok: false, refused: 'moved' });
  assert.ok((await w.vault.changeBindings!(change({ make: binding(w), live, reads: [{ id: key, key: 'RENAMED' }], reason: 'replaced' }))).ok, 'by its name now');
});

test("a change names each binding and credential once: one named twice is no change the replay could take (review r1)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const end = await ending(made.id);
  await assert.rejects(w.vault.changeBindings!(change({ ends: [end, end] })), /each binding and credential once/);
});

test("the log of a bind, a sign-in through it and its unbind replays to the rows: each entry the vault's, no fault (review r1)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  assert.ok((await signIn(w, made.id)).outcome.ok);
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
  const { logChanges } = tablesOf(db.owner);
  const holds = authentic(w.keys.mac);
  const changes = (await db.owner.select().from(logChanges).orderBy(asc(logChanges.number))).map((raw) => {
    const row = { ...raw, number: BigInt(raw.number), seal: raw.seal ?? null };
    assert.ok(holds(changeEntry(row)), `entry ${row.number}'s MAC is the vault's`);
    return loggedChange(row)!;
  });
  const replayed = replay(w.keys.seals, changes);
  assert.deepEqual(replayed.faults, []);
  const binding_ = replayed.rows.get(objectKey({ kind: 'binding', id: made.id }));
  assert.equal((binding_?.row as { revoked?: boolean } | undefined)?.revoked, true, 'the replay ends it too');
});

test("a binding 0.14 made is ended by the vault with no change; one of the log's whose seal a writer cleared is stale, never ended with no change (review r2)", async () => {
  const w = await world();
  const { serviceBindings } = tablesOf(db.owner);
  const old = binding(w);
  await db.owner.insert(serviceBindings).values({ ...old, authMac: Buffer.from(old.authMac, 'base64'), createdAt: new Date(old.createdAt), revoked: undefined } as never);
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(old.id)] }))).ok);
  assert.deepEqual(await ops({ kind: 'binding', id: old.id }), [], 'the log holds no object of it');
  assert.equal((await read(old.id)).columns.revoked, true);
  // The log's binding, its seal cleared around the vault: no end of it with no change.
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, live: [], reason: 'replaced' }))).ok);
  await db.owner.update(serviceBindings).set({ seal: null }).where(eq(serviceBindings.id, made.id));
  assert.deepEqual(await w.vault.changeBindings!(change({ ends: [await ending(made.id)] })), { ok: false, refused: 'stale' });
  assert.deepEqual(await ops({ kind: 'binding', id: made.id }), ['binding.make']);
});

test("a bind through an MCP connection goes ahead only while it is connected; an id the log holds already is no binding to make, its row deleted or not (review r3)", async () => {
  const w = await world();
  const { mcpConnections, oauthClients, serviceBindings } = tablesOf(db.owner);
  const client = randomUUID();
  await db.owner.insert(oauthClients).values({ id: client, name: 'agent', redirectUris: '[]', authMac: randomBytes(32) } as never);
  const connection = randomUUID();
  await db.owner.insert(mcpConnections).values({
    id: connection, authMac: randomBytes(32), principal: ROOT, generation: 0, clientId: client, clientName: 'agent', registration: 'dcr', scopes: '[]',
    redirectUri: 'https://agent.example/cb', expiresAt: new Date(Date.now() + 3_600_000), revokedAt: new Date(),
  } as never);
  assert.deepEqual(await w.vault.changeBindings!(change({ make: binding(w), connection: { id: connection, generation: 0 }, reason: 'replaced' })), { ok: false, refused: 'ended' });
  await db.owner.update(mcpConnections).set({ revokedAt: null }).where(eq(mcpConnections.id, connection));
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, connection: { id: connection, generation: 0 }, reason: 'replaced' }))).ok, 'connected, it goes');
  // Made, ended, its row deleted around the vault: made again under the same id, it would be a second make the replay refuses.
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
  await db.owner.delete(serviceBindings).where(eq(serviceBindings.id, made.id));
  assert.deepEqual(await w.vault.changeBindings!(change({ make: { ...binding(w), id: made.id }, reason: 'replaced' })), { ok: false, refused: 'stale' });
  // The database's reset empties neither table.
  await db.owner.delete(mcpConnections);
  await db.owner.delete(oauthClients);
});

test("a key a replacing bind reads, renamed while it waits for the fence, has it read again: the names compared once the fence is had (review r4)", postgresOnly('the fence is an advisory lock'), async () => {
  const w = await world();
  const { secrets } = tablesOf(db.owner);
  const environment = await newEnvironment(db.owner, w.project);
  const key = randomUUID();
  await db.owner.insert(secrets).values({ id: key, projectId: w.project, environmentId: environment, key: 'API_KEY' });
  const old = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: old, reason: 'replaced' }))).ok);
  const holder = postgresSession(OWNER_URL);
  try {
    // A rename under way: the fence held, as its append takes it, the name changed, not yet committed.
    await holder.unsafe('BEGIN');
    await holder.unsafe('SELECT pg_advisory_xact_lock(1668244070, 0)');
    await holder.unsafe(`UPDATE secrets SET key = 'RENAMED' WHERE id = '${key}'`);
    const replacing = w.vault.changeBindings!(change({ make: binding(w), live: [old.id], ends: [await ending(old.id)], reads: [{ id: key, key: 'API_KEY' }], reason: 'replaced' }));
    await sleep(200);
    await holder.unsafe('COMMIT');
    assert.deepEqual(await replacing, { ok: false, refused: 'moved' });
  } finally {
    await holder.end();
  }
});

test("one new binding id asked for two accounts at once, the first's row deleted once it committed: the second is no second make of it (review r4)", postgresOnly('row locks'), async () => {
  const w = await world();
  const OTHER = 'token:other';
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: OTHER })).ok);
  assert.ok((await w.vault.setAccess({ actor: ROOT, caller: 'person', principal: OTHER, changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  // OTHER's binding, which the second call ends: held, so the second waits there once past its first look at the id.
  const others = { ...binding(w), principal: OTHER };
  assert.ok((await w.vault.changeBindings!(change({ make: others, reason: 'replaced' }))).ok);
  const id = randomUUID();
  const holder = postgresSession(OWNER_URL);
  try {
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM service_bindings WHERE id = '${others.id}' FOR UPDATE`);
    const second = w.vault.changeBindings!(change({ make: { ...binding(w), id, principal: OTHER }, live: [others.id], ends: [await ending(others.id)], reason: 'replaced' }));
    await sleep(200);
    assert.ok((await w.vault.changeBindings!(change({ make: { ...binding(w), id }, reason: 'replaced' }))).ok, "CI's, first");
    const { serviceBindings } = tablesOf(db.owner);
    await db.owner.delete(serviceBindings).where(eq(serviceBindings.id, id));
    await holder.unsafe('COMMIT');
    assert.deepEqual(await second, { ok: false, refused: 'stale' });
  } finally {
    await holder.end();
  }
});

test("a binding's row put back after its end, its old seal and all, signs nobody in: the statement holds the seal to its object's newest change (review r5)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const { serviceBindings } = tablesOf(db.owner);
  const [saved] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made.id));
  const before = await read(made.id);
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
  await db.owner.update(serviceBindings).set({ revokedAt: null, revokedBy: null, authMac: saved!.authMac, seal: saved!.seal }).where(eq(serviceBindings.id, made.id));
  const { credentials } = tablesOf(db.owner);
  const none = (await db.owner.select().from(credentials)).length;
  const now = Date.now();
  const outcome = await w.vault.signIn!({
    principal: CI, binding: { columns: before.columns, seal: before.seal },
    credential: {
      id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'x', label: null, scope: before.columns.scope,
      places: null, expiresAt: now + 60_000, notAfter: null, jkt: null, authMac: randomBytes(32).toString('base64'),
    },
    appKey: APP_KEY, spent: randomBytes(32).toString('base64'), validUntil: now + 60_000, record: { proof: 'oidc', issuer: ISSUER, run: {} },
  });
  assert.deepEqual(outcome, { ok: false, refused: 'unbound' });
  assert.equal((await db.owner.select().from(credentials)).length, none, 'nothing written');
});
