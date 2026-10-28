// The vault makes and ends credentials itself (T149; credentials.ts; migration 0034): a sign-in through a trust binding
// (`sign_in`) and a revoke (`revoke_credential`), each one statement. Each case names the part of formal/Lifecycle.tla
// it holds, and runs on both engines unless it says otherwise: SQLite runs each function's twin, under its one writer.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { CredentialColumns, SignInInput } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { postgresSession } from '@coffre/db/connect';
import { asc, count, eq } from 'drizzle-orm';

import { loggedChange, type ChangeKeys } from '../src/changes.ts';
import type { ResolvedVaultConfig } from '../src/config.ts';
import { objectKey, sealKey, sealOf } from '../src/inputs.ts';
import { authentic, changeEntry, logMacKey } from '../src/log-entry.ts';
import { replay } from '../src/log-replay.ts';
import { credentialObject } from '../src/objects.ts';
import { emptyDatabase, openLocalVault, openTestDatabase, OWNER_URL, postgresOnly, sealed, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const CI = 'token:ci';
const ISSUER = 'https://token.actions.githubusercontent.com';

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

const SCOPE = JSON.stringify([{ projectId: randomUUID(), environmentId: null, role: 'viewer', permissions: { normal: ['secret.read'], protected: [] }, sensitive: false }]);

/** A vault keeping 0.15's log, the service account CI admitted, and a binding of CI's: what a CI run signs in through. */
async function world() {
  const config = configure();
  const vault = await openLocalVault(db.vault, config, { log: '0.15', sealThrough: sealed });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  assert.ok((await vault.admit({ actor: ROOT, principal: CI })).ok);
  const keys: ChangeKeys = { seals: config.signingKeys.map((seed) => sealKey(seed)), mac: logMacKey(config.signingKeys[0]!) };
  const binding = randomUUID();
  await db.owner.insert(tablesOf(db.owner).serviceBindings).values({
    id: binding, authMac: randomBytes(32), principal: CI, generation: 0, profile: 'github', issuer: ISSUER, jwksUri: `${ISSUER}/.well-known/jwks`,
    claims: JSON.stringify({ repository_id: '1' }), scope: SCOPE, policy: null, label: 'deploys', createdBy: 'root@acme.example',
  });
  return { vault, keys, binding };
}

type World = Awaited<ReturnType<typeof world>>;

/** A CI run's sign-in through the world's binding, as the app asks it, with `change` over it. */
function asked(w: World, change: (input: SignInInput) => SignInInput = (input) => input): SignInInput {
  const now = Date.now();
  return change({
    principal: CI,
    binding: { id: w.binding, generation: 0, profile: 'github', scope: SCOPE, policy: null },
    credential: {
      id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'coffre_svc_x', label: 'deploys', scope: SCOPE,
      places: null, expiresAt: now + 5 * 60_000, notAfter: null, jkt: null, authMac: randomBytes(32).toString('base64'),
    },
    spent: randomBytes(32).toString('base64'),
    validUntil: now + 60_000,
    record: { proof: 'oidc', issuer: ISSUER, run: { run_id: '7001' } },
  });
}

/** How many of each row a sign-in or a revoke writes there are, a credential's changes for its: none written by a refusal. */
async function written() {
  const { consumedTokens, credentials, logChanges } = tablesOf(db.owner);
  const n = async (table: typeof credentials | typeof consumedTokens) => (await db.owner.select({ n: count() }).from(table))[0]!.n;
  const changes = (await db.owner.select({ payload: logChanges.payload }).from(logChanges)).filter(({ payload }) => (JSON.parse(payload) as { ref?: { kind?: string } }).ref?.kind === 'credential').length;
  return { credentials: await n(credentials), spent: await n(consumedTokens), changes };
}

/** The log replayed: each entry's MAC the vault's, and the credential's row the replay's object, under its newest change's seal. */
async function holdsReplay(keys: ChangeKeys, id: string): Promise<void> {
  const { credentials, logChanges } = tablesOf(db.owner);
  const holds = authentic(keys.mac);
  const changes = (await db.owner.select().from(logChanges).orderBy(asc(logChanges.number))).map((raw) => {
    const row = { ...raw, number: BigInt(raw.number), seal: raw.seal ?? null };
    assert.ok(holds(changeEntry(row)), `entry ${row.number}'s MAC is the vault's`);
    return loggedChange(row)!;
  });
  const replayed = replay(keys.seals, changes);
  assert.deepEqual(replayed.faults, []);
  const [live] = await db.owner.select().from(credentials).where(eq(credentials.id, id));
  const log = replayed.rows.get(objectKey({ kind: 'credential', id }));
  assert.ok(live !== undefined && log !== undefined, 'the credential is in the rows and the log');
  assert.deepEqual(credentialObject(columnsOf(live)), log.row, "the row is the replay's object");
  assert.deepEqual(live.seal, log.seal, "the row carries its newest change's seal");
}

function columnsOf(row: { id: string; principal: string; kind: string; scope: string | null; revokedAt: Date | null; expiresAt: Date; notAfter: Date | null; generation: number }): CredentialColumns {
  return {
    id: row.id, principal: row.principal, kind: row.kind, scope: row.scope, revoked: row.revokedAt !== null, generation: row.generation,
    expiresAt: Math.min(row.expiresAt.getTime(), row.notAfter?.getTime() ?? Infinity),
  };
}

test('a sign-in through a binding is one change of the log, its row the object it seals, its record the run (D147); no 0.14 entry', async () => {
  const w = await world();
  const { auditLog, credentials, serviceBindings, logChanges } = tablesOf(db.owner);
  const entries = (await db.owner.select({ n: count() }).from(auditLog))[0]!.n;
  const input = asked(w);
  const outcome = await w.vault.signIn!(input);
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, input.credential.id));
  assert.equal(row!.principal, CI);
  assert.equal(row!.createdBy, `binding:${w.binding}`);
  assert.equal(row!.expiresAt.getTime(), input.credential.expiresAt);
  assert.equal(Buffer.from(row!.authMac).toString('base64'), input.credential.authMac, "the app's MAC, as it made it");
  await holdsReplay(w.keys, input.credential.id);
  const [change] = await db.owner.select().from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'credential', id: input.credential.id })));
  assert.equal(change!.actor, CI);
  assert.equal(String(change!.number), outcome.number);
  const payload = JSON.parse(change!.payload) as { op: string; signIn: unknown };
  assert.equal(payload.op, 'credential.issue');
  assert.deepEqual(payload.signIn, { binding: w.binding, proof: 'oidc', issuer: ISSUER, run: { run_id: '7001' } });
  assert.equal((await db.owner.select({ n: count() }).from(auditLog))[0]!.n, entries, 'no 0.14 entry');
  const [binding] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, w.binding));
  assert.notEqual(binding!.lastUsedAt, null, "the binding's last use stamped");
});

test('a sign-in goes ahead only while the binding is as named and stands, and its account active at its generation (BindingLocked, MemberLocked): else nothing written', async () => {
  const w = await world();
  const { serviceBindings, vaultMembers } = tablesOf(db.owner);
  const none = await written();
  const refused = async (input: SignInInput) => {
    assert.deepEqual(await w.vault.signIn!(input), { ok: false, refused: 'unbound' });
    assert.deepEqual(await written(), none);
  };
  // Named with another scope, another generation, another policy, or another binding: none is its row.
  await refused(asked(w, (input) => ({ ...input, binding: { ...input.binding, scope: '[]' }, credential: { ...input.credential, scope: '[]' } })));
  await refused(asked(w, (input) => ({ ...input, binding: { ...input.binding, id: randomUUID() } })));
  await refused(asked(w, (input) => ({ ...input, binding: { ...input.binding, generation: 1 } })));
  // Revoked.
  await db.owner.update(serviceBindings).set({ revokedAt: new Date() }).where(eq(serviceBindings.id, w.binding));
  await refused(asked(w));
  await db.owner.update(serviceBindings).set({ revokedAt: null }).where(eq(serviceBindings.id, w.binding));
  // The account removed; then admitted again, at a generation the binding is not of.
  assert.ok((await w.vault.remove({ actor: ROOT, principal: CI })).ok);
  await refused(asked(w));
  assert.ok((await w.vault.admit({ actor: ROOT, principal: CI })).ok);
  assert.equal((await db.owner.select({ generation: vaultMembers.generation }).from(vaultMembers).where(eq(vaultMembers.principal, CI)))[0]!.generation, 1);
  await refused(asked(w));
});

test("an ID token is spent once (SpentChecked): presented again, it buys nothing, and writes nothing", async () => {
  const w = await world();
  const first = asked(w);
  assert.ok((await w.vault.signIn!(first)).ok);
  const after = await written();
  assert.deepEqual(await w.vault.signIn!(asked(w, (input) => ({ ...input, spent: first.spent }))), { ok: false, refused: 'replayed' });
  assert.deepEqual(await written(), after);
});

test("a binding makes at most 60 credentials a minute, counted under its row (BindingLocked): the 61st is busy", async () => {
  const w = await world();
  const { credentials } = tablesOf(db.owner);
  await db.owner.insert(credentials).values(Array.from({ length: 60 }, () => ({
    id: randomUUID(), kind: 'service', authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, principal: CI,
    createdBy: `binding:${w.binding}`, expiresAt: new Date(Date.now() + 300_000),
  })));
  const none = await written();
  assert.deepEqual(await w.vault.signIn!(asked(w)), { ok: false, refused: 'busy' });
  assert.deepEqual(await written(), none);
  // Those of another binding, or a minute old, count for nothing.
  await db.owner.update(credentials).set({ createdAt: new Date(Date.now() - 61_000) }).where(eq(credentials.principal, CI));
  assert.ok((await w.vault.signIn!(asked(w))).ok);
});

test("the proof's times and the credential's end are held to by the database's clock, in the statement: past, or too far, nothing written", async () => {
  const w = await world();
  const none = await written();
  const expired = async (input: SignInInput) => {
    assert.deepEqual(await w.vault.signIn!(input), { ok: false, refused: 'expired' });
    assert.deepEqual(await written(), none);
  };
  await expired(asked(w, (input) => ({ ...input, validUntil: Date.now() - 1 })));
  await expired(asked(w, (input) => ({ ...input, credential: { ...input.credential, expiresAt: Date.now() - 1 } })));
  // A CI run's credential lives five minutes, a minute's slack for the Worker's clock.
  await expired(asked(w, (input) => ({ ...input, credential: { ...input.credential, expiresAt: Date.now() + 7 * 60_000 } })));
});

test('what the vault decides is the binding\'s: a scope the app names otherwise, or a CI run\'s credential bound to a key, is no sign-in', async () => {
  const w = await world();
  await assert.rejects(w.vault.signIn!(asked(w, (input) => ({ ...input, credential: { ...input.credential, scope: '[]' } }))), /reaches what its binding does/);
  await assert.rejects(w.vault.signIn!(asked(w, (input) => ({ ...input, credential: { ...input.credential, jkt: 'thumbprint' } }))), /bound to no key/);
  await assert.rejects(w.vault.signIn!(asked(w, (input) => ({ ...input, principal: ROOT }))), /service account/);
  assert.deepEqual((await written()).credentials, 0);
});

test('a sign-in takes the issue lock, never the fence: it commits while a change holds the fence exclusive (IssueOffFence, R58)', postgresOnly('the fence is an advisory lock'), async () => {
  const w = await world();
  const holder = postgresSession(OWNER_URL);
  try {
    await holder.unsafe('BEGIN');
    await holder.unsafe('SELECT pg_advisory_xact_lock(1668244070, 0)');
    const outcome = await w.vault.signIn!(asked(w));
    assert.ok(outcome.ok, 'made while the fence is held');
    await holder.unsafe('COMMIT');
  } finally {
    await holder.end();
  }
});

test("a sign-in that waits over a second for its binding's row is refused busy at once, nothing written (R44)", postgresOnly('lock_timeout'), async () => {
  const w = await world();
  const holder = postgresSession(OWNER_URL);
  try {
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM service_bindings WHERE id = '${w.binding}' FOR UPDATE`);
    const none = await written();
    const started = Date.now();
    assert.deepEqual(await w.vault.signIn!(asked(w)), { ok: false, refused: 'busy' });
    assert.ok(Date.now() - started < 1900, `refused within its lock_timeout, not after ${Date.now() - started} ms`);
    await holder.unsafe('ROLLBACK');
    assert.deepEqual(await written(), none);
  } finally {
    await holder.end();
  }
});

// --- revokes ---------------------------------------------------------------------------

/** A credential the world's binding signed in, as the app reads it back: its row and its object's columns, with their seal. */
async function signedIn(w: World) {
  const input = asked(w);
  assert.ok((await w.vault.signIn!(input)).ok);
  return read(input.credential.id);
}

async function read(id: string) {
  const { credentials } = tablesOf(db.owner);
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, id));
  return { row: row!, before: { columns: columnsOf(row!), seal: row!.seal === null ? null : Buffer.from(row!.seal).toString('base64') } };
}

function revoking(made: Awaited<ReturnType<typeof read>>, by = ROOT) {
  return {
    actor: by, before: made.before, authMacFrom: Buffer.from(made.row.authMac).toString('base64'), authMac: randomBytes(32).toString('base64'),
    revokedAt: Date.now(), revokedBy: 'root@acme.example', reason: 'revoke' as const, via: null,
  };
}

test("a revoke is one change of the log, from the row's seal, the app's MAC written over the revoked row; the log replays to it", async () => {
  const w = await world();
  const made = await signedIn(w);
  const input = revoking(made);
  const outcome = await w.vault.revokeCredential!(input);
  assert.ok(outcome.ok && outcome.number !== null, JSON.stringify(outcome));
  const { row } = await read(made.row.id);
  assert.equal(row.revokedAt!.getTime(), input.revokedAt);
  assert.equal(row.revokedBy, 'root@acme.example');
  assert.equal(Buffer.from(row.authMac).toString('base64'), input.authMac);
  await holdsReplay(w.keys, made.row.id);
  const { logChanges } = tablesOf(db.owner);
  const [, revoke] = await db.owner.select().from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'credential', id: made.row.id }))).orderBy(asc(logChanges.number));
  assert.deepEqual((JSON.parse(revoke!.payload) as { revoke: unknown }).revoke, { reason: 'revoke', via: null, kind: 'service', principal: CI });
  // Revoked already, or as read before it: moved, nothing written.
  assert.deepEqual(await w.vault.revokeCredential!(input), { ok: false, refused: 'moved' });
});

test('a revoke goes ahead only from the row as the app read it and signed it: another MAC, or another seal, is moved', async () => {
  const w = await world();
  const made = await signedIn(w);
  const none = await written();
  assert.deepEqual(await w.vault.revokeCredential!({ ...revoking(made), authMacFrom: randomBytes(32).toString('base64') }), { ok: false, refused: 'moved' });
  assert.deepEqual(await written(), none);
  assert.equal((await read(made.row.id)).row.revokedAt, null);
});

test('a revoked row put back with the seal it had (ChangeChecksSeal) is stale, and reported: nothing written', async () => {
  const w = await world();
  const made = await signedIn(w);
  assert.ok((await w.vault.revokeCredential!(revoking(made))).ok);
  // The writer puts back the live row, its MAC and the seal the vault made over it once: the vault's, but not the newest change's.
  const { auditLog, credentials } = tablesOf(db.owner);
  await db.owner.update(credentials).set({ revokedAt: null, revokedBy: null, authMac: made.row.authMac, seal: made.row.seal }).where(eq(credentials.id, made.row.id));
  const reports = (await db.owner.select({ n: count() }).from(auditLog))[0]!.n;
  const none = await written();
  assert.deepEqual(await w.vault.revokeCredential!(revoking(await read(made.row.id))), { ok: false, refused: 'stale' });
  assert.deepEqual(await written(), none);
  assert.ok((await db.owner.select({ n: count() }).from(auditLog))[0]!.n > reports, 'reported, as a finding');
});

test("a seal the vault never made is tampered, refused before any statement; a 0.14 row the log never held is revoked with no change", async () => {
  const w = await world();
  const made = await signedIn(w);
  const forged = { ...made, before: { ...made.before, seal: randomBytes(16).toString('base64') } };
  assert.deepEqual(await w.vault.revokeCredential!(revoking(forged)), { ok: false, refused: 'tampered' });
  // 0.14's: no seal, no change.
  const { credentials } = tablesOf(db.owner);
  const old = randomUUID();
  await db.owner.insert(credentials).values({
    id: old, kind: 'service', authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, principal: CI, createdBy: ROOT,
    expiresAt: new Date(Date.now() + 300_000),
  });
  const before = await written();
  assert.deepEqual(await w.vault.revokeCredential!(revoking(await read(old))), { ok: true, number: null, witnessed: null });
  assert.notEqual((await read(old)).row.revokedAt, null);
  assert.equal((await written()).changes, before.changes);
});

test('a revoke takes the fence exclusive, for its own work alone: it waits for a use holding it shared, then commits (RevokeTakesFence)', postgresOnly('the fence is an advisory lock'), async () => {
  const w = await world();
  const made = await signedIn(w);
  const holder = postgresSession(OWNER_URL);
  try {
    await holder.unsafe('BEGIN');
    await holder.unsafe('SELECT pg_advisory_xact_lock_shared(1668244070, 0)');
    let done = false;
    const revoking_ = w.vault.revokeCredential!(revoking(made)).then((outcome) => ((done = true), outcome));
    await sleep(300);
    assert.equal(done, false, 'waits while the use holds the fence');
    await holder.unsafe('COMMIT');
    assert.ok((await revoking_).ok);
  } finally {
    await holder.end();
  }
});

test("the seal a sign-in writes is the vault's over the object its columns make", async () => {
  const w = await world();
  const made = await signedIn(w);
  const ref = { kind: 'credential' as const, id: made.row.id };
  assert.deepEqual(Buffer.from(made.row.seal!), sealOf(w.keys.seals[0]!, ref, credentialObject(made.before.columns)));
});
