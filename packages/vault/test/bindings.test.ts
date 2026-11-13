// A service's trust bindings are the vault's to make and end (credentials.ts; migration 0037): a binding a
// person makes is weighed as a service token's issue is and sealed, a change of the log; one ended takes every live
// credential it issued with it, in one statement; and a sign-in takes only a binding the vault sealed (formal/Lifecycle.tla's
// BindingSealed, its bind and unbind).
import { defineDeployment } from '@coffre/core/deployment';
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { issuedGrant, storedScope } from '@coffre/core/access';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { ChangeBindingsInput, CredentialColumns, LoggedChange, MadeBinding, SignInInput } from '@coffre/core/vault';
import { postgresSession } from '@coffre/db/connect';
import { and, asc, desc, eq, inArray, sql } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { loggedChange, type ChangeKeys } from '../src/changes.ts';
import { objectKey, sealKey } from '../src/inputs.ts';
import { authentic, changeEntry, logMacKey } from '../src/log-entry.ts';
import { replay } from '../src/log-replay.ts';
import { emptyDatabase, newEnvironment, newProject, openLocalVault, openTestDatabase, OWNER_URL, rows, sealed, nothingHeld, type TestDatabase } from './database.ts';
import { auditLog, credentials as credentialsTable, logChanges, mcpConnections, oauthClients, principals, secrets, serviceBindings } from '@coffre/db/schema';

const ROOT = 'user:root@acme.example';
const ADMIN = 'user:admin@acme.example';
const CI = 'token:ci';
const ISSUER = 'https://token.actions.githubusercontent.com';
/** The instance's public URL its bindings are made on, which their seals cover. */
const ORIGIN = 'https://secrets.acme.example';
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
    deployment: defineDeployment(),
  };
}

/** A vault keeping 0.15's log; an Owner, an Admin who is no Owner, and a service account that views a project. */
async function world() {
  const config = configure();
  const vault = await openLocalVault(db.vault, config, { sealThrough: sealed, heldOutside: nothingHeld });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'admin' })).ok);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  const keys: ChangeKeys = { seals: config.signingKeys.map((seed) => sealKey(seed)), mac: logMacKey(config.signingKeys[0]!) };
  return { vault, project, keys, config };
}

type World = Awaited<ReturnType<typeof world>>;

/** A binding of CI's, as the app asks the vault to make it: by the Owner, viewing the project, reading sensitive values when `sensitive`. */
function binding(w: World, sensitive = false, by = ROOT): MadeBinding {
  return {
    id: randomUUID(), principal: CI, generation: 0, profile: 'github', issuer: ISSUER, origin: ORIGIN, jwksUri: `${ISSUER}/.well-known/jwks`, claims: JSON.stringify({ repository_id: '1' }),
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
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, id));
  return {
    columns: {
      id, principal: row!.principal, generation: row!.generation, profile: row!.profile, issuer: row!.issuer, origin: ORIGIN, jwksUri: row!.jwksUri, claims: row!.claims,
      scope: row!.scope, policy: row!.policy, revoked: row!.revokedAt !== null,
    },
    seal: row!.seal === null ? null : Buffer.from(row!.seal).toString('base64'),
    authMac: Buffer.from(row!.authMac).toString('base64'),
  };
}

/** An object's newest change as the app reads it beside the bindings (`SignInInput.newest`), or none. */
async function newestOf(object: { kind: 'principal' | 'binding'; id: string }): Promise<LoggedChange | null> {
  const [row] = await db.owner.select().from(logChanges).where(eq(logChanges.object, objectKey(object))).orderBy(desc(logChanges.number)).limit(1);
  if (row === undefined) return null;
  return {
    number: String(row.number), at: Number(row.at), requestId: row.requestId, actor: row.actor, payload: row.payload,
    seal: row.seal === null ? null : Buffer.from(row.seal).toString('base64'), mac: Buffer.from(row.mac).toString('base64'),
  };
}

/** The account's and binding `id`'s newest changes, as the app reads them. */
async function newestAsRead(id: string): Promise<NonNullable<SignInInput['newest']>> {
  return { member: await newestOf({ kind: 'principal', id: CI }), binding: await newestOf({ kind: 'binding', id }) };
}

/**
 * `w`'s vault on a connection that counts the vault's own reads of newest changes (`loggedChanges`) and runs
 * `before` as `sign_in`'s statement goes out.
 */
async function watchedVault(w: World, before: () => Promise<void> = async () => {}): Promise<{ vault: World['vault']; reads: () => number }> {
  const raw = db.vault as unknown as { dialect: { sqlToQuery(query: unknown): { sql: string } } } & Record<string | symbol, unknown>;
  let reads = 0;
  const late = new Proxy(raw, {
    get(target, key) {
      const value = Reflect.get(target, key);
      if (typeof value !== 'function') return value;
      if (key === 'execute') {
        return async (query: unknown) => {
          const text = target.dialect.sqlToQuery(query).sql;
          if (text.includes('FROM log_changes c WHERE c.number IN')) reads += 1;
          if (text.includes('sign_in(')) await before();
          return value.call(target, query);
        };
      }
      return value.bind(target);
    },
  });
  const vault = await openLocalVault(late as never, w.config, { sealThrough: sealed, heldOutside: nothingHeld });
  return { vault, reads: () => reads };
}

/** A CI run's sign-in through binding `id`, as the app asks it; with the newest changes it read beside the binding, when given. */
async function signIn(w: World, id: string, newest?: SignInInput['newest']): Promise<{ outcome: Awaited<ReturnType<NonNullable<World['vault']['signIn']>>>; credential: string }> {
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
    // Keys its issuer publishes: the app verified the token, as the vault fetches nothing.
    idToken: null, dpop: null,
    ...(newest === undefined ? {} : { newest }),
  });
  return { outcome, credential };
}

/** Binding `id` ended, with the live credentials named (all it issued, unless `credentials` says otherwise). */
async function ending(id: string, credentials?: string[]): Promise<ChangeBindingsInput['ends'][number]> {
  const { columns, seal, authMac } = await read(id);
  const rows = (await db.owner.select().from(credentialsTable).where(eq(credentialsTable.createdBy, `binding:${id}`))).filter((row) => row.revokedAt === null && (credentials === undefined || credentials.includes(row.id)));
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
  return (await db.owner.select({ payload: logChanges.payload }).from(logChanges).where(eq(logChanges.object, objectKey(object))).orderBy(asc(logChanges.number)))
    .map(({ payload }) => (JSON.parse(payload) as { op: string }).op);
}

test("a binding the Owner makes is a change of the log, its row the object it seals, its record who made it (D147); a run signs in through it", async () => {
  const w = await world();
  const made = binding(w, true);
  const outcome = await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const [row] = await db.owner.select().from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'binding', id: made.id })));
  assert.deepEqual((JSON.parse(row!.payload) as { bind: unknown }).bind, { by: ROOT, via: null, label: 'deploys', replaces: [] });
  assert.equal((await read(made.id)).seal, Buffer.from(row!.seal!).toString('base64'), "the row carries its object's seal");
  assert.ok((await signIn(w, made.id)).outcome.ok);
});

test("a binding ended, put back, its end's seal column written to match only once the vault has read that change, MAC and all: signs nobody in (review r3)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made.id));
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
  // The writer: the row as it was before its end, its old seal valid. The end's log row untouched, so far: its MAC holds.
  await db.owner.update(serviceBindings).set({ revokedAt: null, seal: row!.seal, authMac: row!.authMac }).where(eq(serviceBindings.id, made.id));
  const [newest] = await db.owner.select({ number: logChanges.number }).from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'binding', id: made.id }))).orderBy(desc(logChanges.number)).limit(1);
  // Then, as `sign_in`'s statement goes out: the end's seal column made the row's, after the vault checked that change's MAC, before the statement compares that column with the row.
  const forge = async () => { await db.owner.update(logChanges).set({ seal: row!.seal }).where(eq(logChanges.number, newest!.number)); };
  const raw = db.vault as unknown as { dialect: { sqlToQuery(query: unknown): { sql: string } } } & Record<string | symbol, unknown>;
  const late = new Proxy(raw, {
    get(target, key) {
      const value = Reflect.get(target, key);
      if (typeof value !== 'function') return value;
      if (key === 'execute') {
        return async (query: unknown) => {
          if (target.dialect.sqlToQuery(query).sql.includes('sign_in(')) await forge();
          return value.call(target, query);
        };
      }
      return value.bind(target);
    },
  });
  const vault = await openLocalVault(late as never, w.config, { sealThrough: sealed, heldOutside: nothingHeld });
  const signedIn = (await db.owner.select().from(credentialsTable)).length;
  // Held by the end's MAC alone, the sign-in went on to `sign_in`, whose comparison the forged column then passed: a
  // credential through an ended binding. The binding's seal, as the vault proved it, is held to the checked change's.
  assert.deepEqual((await signIn({ ...w, vault }, made.id)).outcome, { ok: false, refused: 'unbound' });
  assert.equal((await db.owner.select().from(credentialsTable)).length, signedIn, 'no credential made');
});

test("a binding ended, put back by a writer with its end's seal column written to match, signs nobody in: that change's MAC does not hold (T190)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const [row] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made.id));
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
  // The writer: the row as it was before its end, and the end's seal column made that row's seal (not its MAC).
  await db.owner.update(serviceBindings).set({ revokedAt: null, seal: row!.seal, authMac: row!.authMac }).where(eq(serviceBindings.id, made.id));
  const [newest] = await db.owner.select({ number: logChanges.number }).from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'binding', id: made.id }))).orderBy(desc(logChanges.number)).limit(1);
  await db.owner.update(logChanges).set({ seal: row!.seal }).where(eq(logChanges.number, newest!.number));
  const signedIn = (await db.owner.select().from(credentialsTable)).length;
  assert.deepEqual((await signIn(w, made.id)).outcome, { ok: false, refused: 'unbound' });
  assert.equal((await db.owner.select().from(credentialsTable)).length, signedIn, 'no credential made');
});

test("a sign-in handed the account's and the binding's newest changes, as the app reads them beside the binding, reads none itself: one statement (T192)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const watched = await watchedVault(w);
  const { outcome, credential } = await signIn({ ...w, vault: watched.vault }, made.id, await newestAsRead(made.id));
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.equal(watched.reads(), 0, 'the vault read no change itself');
  assert.deepEqual(await ops({ kind: 'credential', id: credential }), ['credential.issue']);
  // Handed none (an app of an earlier release), it reads them itself.
  const asBefore = await signIn({ ...w, vault: watched.vault }, made.id);
  assert.ok(asBefore.outcome.ok, JSON.stringify(asBefore.outcome));
  assert.equal(watched.reads(), 1);
});

test("the app's word refuses nothing: a newest change handed with its seal or MAC edited, of another object, or older than the newest, has the vault read them itself and decide on what it reads (T192)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const watched = await watchedVault(w);
  const honest = await newestAsRead(made.id);
  const other = randomBytes(16).toString('base64');
  const handed: NonNullable<SignInInput['newest']>[] = [
    { ...honest, member: { ...honest.member!, seal: other } },
    { ...honest, binding: { ...honest.binding!, mac: randomBytes(16).toString('base64') } },
    // The binding's change handed as the account's: its MAC is over the binding's object, not the account's.
    { ...honest, member: honest.binding },
    { member: null, binding: honest.binding },
    // A number past Postgres's bigint, which no MAC covers: none, never an error at its cast.
    { ...honest, member: { ...honest.member!, number: '9999999999999999999' } },
  ];
  for (const [i, newest] of handed.entries()) {
    const { outcome } = await signIn({ ...w, vault: watched.vault }, made.id, newest);
    assert.ok(outcome.ok, `${i}: ${JSON.stringify(outcome)}`);
    assert.equal(watched.reads(), i + 1, `${i}: read by the vault`);
  }
  // An authentic change of the account's, no longer its newest: a grant moved since the app read it. `sign_in` holds the
  // newest to the one checked, answers `moved`, and the vault reads the account's newest itself, and signs the run in.
  const stale = await newestAsRead(made.id);
  const regranted = await w.vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: new Date(Date.now() + 86_400_000).toISOString() }] });
  assert.ok(regranted.ok, JSON.stringify(regranted));
  const { outcome } = await signIn({ ...w, vault: watched.vault }, made.id, stale);
  assert.ok(outcome.ok, JSON.stringify(outcome));
  assert.equal(watched.reads(), handed.length + 1);
});

test("an account removed, its row put back, its removal's seal column written to match only once the vault has checked that change's MAC, signs nobody in: `sign_in` holds the account's newest change to the one checked (T192)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const [row] = await db.owner.select().from(principals).where(eq(principals.principal, CI));
  assert.ok((await w.vault.remove({ actor: ROOT, principal: CI })).ok);
  // The writer: the account's row as it was before its removal, its old seal valid; the removal's log row untouched, so
  // far: its MAC holds, as the app reads it and as the vault checks it.
  await db.owner.update(principals).set({ status: row!.status, generation: row!.generation, seal: row!.seal }).where(eq(principals.principal, CI));
  const removal = (await newestOf({ kind: 'principal', id: CI }))!;
  const forge = async () => { await db.owner.update(logChanges).set({ seal: row!.seal }).where(eq(logChanges.number, BigInt(removal.number))); };
  const signedIn = (await db.owner.select().from(credentialsTable)).length;
  for (const newest of [await newestAsRead(made.id), undefined]) {
    // Then, as `sign_in`'s statement goes out, the removal's seal column made the row's: a `sign_in` that compared the row
    // with that column would make a credential for the removed account.
    const watched = await watchedVault(w, forge);
    assert.deepEqual((await signIn({ ...w, vault: watched.vault }, made.id, newest)).outcome, { ok: false, refused: 'unbound' });
    assert.equal((await db.owner.select().from(credentialsTable)).length, signedIn, 'no credential made');
    await db.owner.update(logChanges).set({ seal: Buffer.from(removal.seal!, 'base64') }).where(eq(logChanges.number, BigInt(removal.number)));
  }
});

test("an account removed, its row put back with its removal's own seal, still gets a credential made, which nothing honours: `sign_in` holds the row to its newest change's seal, not to what that change sealed (open, R64; review r4)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const [row] = await db.owner.select().from(principals).where(eq(principals.principal, CI));
  assert.ok((await w.vault.remove({ actor: ROOT, principal: CI })).ok);
  // The writer, with no log tamper at all: the row active again at its old generation, its seal the removal's. The
  // removal ended no binding, so the binding's own seal and newest change are still authentic.
  const removal = (await newestOf({ kind: 'principal', id: CI }))!;
  await db.owner.update(principals).set({ status: row!.status, generation: row!.generation, seal: Buffer.from(removal.seal!, 'base64') })
    .where(eq(principals.principal, CI));
  const signedIn = (await db.owner.select().from(credentialsTable)).length;
  // The gap: the vault does not check the row's columns (and grants) against that seal at sign-in, so a credential is
  // made. Closing it means the app reads the row and its grants too; it stays open, as the row fails closed below.
  assert.equal((await signIn(w, made.id, await newestAsRead(made.id))).outcome.ok, true);
  assert.equal((await db.owner.select().from(credentialsTable)).length, signedIn + 1);
  // Every decision that reads the account checks its row against its seal (`use.ts`'s `viewOf`), and refuses it.
  assert.equal((await w.vault.access(CI)).status, 'tampered');
});

test("an account's old, authentic change handed back under the number of its removal, whose seal column a writer made the old one's, signs nobody in: `sign_in` holds the newest change to the one checked whole, not by number and seal (T192, review r2)", async () => {
  // Its change before its removal, whose MAC holds, and the removal's number. No MAC covers a number.
  {
    const w = await world();
    const made = binding(w);
    assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
    const [row] = await db.owner.select().from(principals).where(eq(principals.principal, CI));
    const old = (await newestOf({ kind: 'principal', id: CI }))!;
    assert.ok((await w.vault.remove({ actor: ROOT, principal: CI })).ok);
    const removal = (await newestOf({ kind: 'principal', id: CI }))!;
    // The writer: the row put back, the removal's seal column the old change's; nothing deleted, renumbered or replayed.
    await db.owner.update(principals).set({ status: row!.status, generation: row!.generation, seal: row!.seal }).where(eq(principals.principal, CI));
    await db.owner.update(logChanges).set({ seal: Buffer.from(old.seal!, 'base64') }).where(eq(logChanges.number, BigInt(removal.number)));
    const signedIn = (await db.owner.select().from(credentialsTable)).length;
    const handed = { ...(await newestAsRead(made.id)), member: { ...old, number: removal.number } };
    assert.deepEqual((await signIn(w, made.id, handed)).outcome, { ok: false, refused: 'unbound' });
    assert.equal((await db.owner.select().from(credentialsTable)).length, signedIn, 'no credential made');
  }
});

test("a binding's making handed back under the number of its end, whose seal column a writer made the making's, signs nobody in (T192, review r2)", async () => {
  {
    const w = await world();
    const made = binding(w);
    assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
    const [saved] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made.id));
    const making = (await newestOf({ kind: 'binding', id: made.id }))!;
    assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
    const end = (await newestOf({ kind: 'binding', id: made.id }))!;
    await db.owner.update(serviceBindings).set({ revokedAt: null, revokedBy: null, authMac: saved!.authMac, seal: saved!.seal }).where(eq(serviceBindings.id, made.id));
    await db.owner.update(logChanges).set({ seal: Buffer.from(making.seal!, 'base64') }).where(eq(logChanges.number, BigInt(end.number)));
    const signedIn = (await db.owner.select().from(credentialsTable)).length;
    const handed = { ...(await newestAsRead(made.id)), binding: { ...making, number: end.number } };
    assert.deepEqual((await signIn(w, made.id, handed)).outcome, { ok: false, refused: 'unbound' });
    assert.equal((await db.owner.select().from(credentialsTable)).length, signedIn, 'no credential made');
  }
});

test("only an Owner of its project gives a binding's runs sensitive reads (R32); a service account gives none; nothing written", async () => {
  const w = await world();
  const byAdmin = await w.vault.changeBindings!(change({ actor: ADMIN, make: binding(w, true, ADMIN), reason: 'replaced' }));
  assert.equal(!byAdmin.ok && byAdmin.refused, 'refused');
  assert.ok((await w.vault.changeBindings!(change({ actor: ADMIN, make: binding(w, false, ADMIN), reason: 'replaced' }))).ok, 'no sensitive read, the Admin may');
  const bySelf = await w.vault.changeBindings!(change({ actor: CI, make: { ...binding(w), createdBy: 'ci' }, reason: 'replaced' }));
  assert.equal(!bySelf.ok && bySelf.refused, 'refused');
  assert.equal((await db.owner.select().from(serviceBindings)).length, 1);
});

test('a binding 0.14 made, which the log never held, or one whose row was edited around the vault, signs nobody in (BindingSealed)', async () => {
  const w = await world();
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
    appKey: APP_KEY, spent: randomBytes(32).toString('base64'), validUntil: now + 60_000, record: { proof: 'oidc', issuer: ISSUER, run: {} }, idToken: null, dpop: null,
  });
  assert.deepEqual(asSealed, { ok: false, refused: 'unbound' });
});

test("a sign-in through the binding of an account whose newest change was edited around the vault is refused, its finding naming that change (T179 PR 4a)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  // The account's newest change, its actor edited: its MAC no longer holds.
  const object = objectKey({ kind: 'principal', id: CI });
  const [newest] = await rows<{ n: string; mac: Uint8Array }>(db.owner, sql`SELECT CAST(number AS text) AS n, mac FROM log_changes WHERE object = ${object} ORDER BY number DESC LIMIT 1`);
  await rows(db.owner, sql`UPDATE log_changes SET actor = 'user:mallory@acme.example' WHERE number = ${newest!.n}`);
  assert.deepEqual((await signIn(w, made.id)).outcome, { ok: false, refused: 'unbound' });
  // Found where the sign-in holds the account to the log (`#notLogged`), which names no change: the finding is given
  // the account's newest as it appends (`#weigh`), by its MAC (`changeName`).
  const findings = await db.owner.select({ metadata: auditLog.metadata }).from(auditLog)
    .where(and(eq(auditLog.action, 'vault.tampered'), eq(auditLog.subjectPrincipal, CI), inArray(auditLog.code, ['mac', 'stale'])));
  assert.deepEqual(findings.map((finding) => (JSON.parse(finding.metadata) as { change?: string }).change), [Buffer.from(newest!.mac).toString('hex')]);
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
  assert.ok((await db.owner.select().from(credentialsTable)).every((row) => row.revokedAt !== null));
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

test("an unbind takes the fence for its statement; a bind that ends nothing takes none (RevokeTakesFence, IssueOffFence, R58)", async () => {
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

test("an unbind takes 0.14's head first, which 0.14's use of a credential it ends holds from its check to its commit; a bind that ends nothing takes none (EntryLessHead, PR 9b)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  assert.ok((await signIn(w, made.id)).outcome.ok);
  const holder = postgresSession(OWNER_URL);
  try {
    // 0.14's use of the run's credential, on an isolate still serving: under the head, checked, not yet committed.
    await holder.unsafe('BEGIN');
    await holder.unsafe('SELECT 1 FROM audit_chain_head WHERE only_row FOR UPDATE');
    const another = await w.vault.changeBindings!(change({ make: binding(w), reason: 'replaced', live: [made.id] }));
    assert.ok(another.ok, `made while the head is held: ${JSON.stringify(another)}`);
    let ended = false;
    const unbinding = w.vault.changeBindings!(change({ ends: [await ending(made.id)] })).then((outcome) => ((ended = true), outcome));
    await sleep(200);
    assert.equal(ended, false, "the unbind waits for 0.14's head");
    await holder.unsafe('COMMIT');
    assert.ok((await unbinding).ok);
  } finally {
    await holder.end();
  }
});

test("a binding's maker whose access moved since the app weighed it is refused, for the app to weigh again", async () => {
  const w = await world();
  const [{ accessSeq }] = (await db.owner.select({ accessSeq: principals.accessSeq }).from(principals).where(eq(principals.principal, ROOT))) as [{ accessSeq: bigint }];
  const stale = await w.vault.changeBindings!(change({ make: binding(w), reason: 'replaced', actorAccess: String(BigInt(accessSeq) + 1n) }));
  assert.equal(!stale.ok && stale.refused, 'access');
  assert.equal((await db.owner.select().from(serviceBindings)).length, 0);
});

test("a credential with no seal its sealed binding issued (one planted around the vault) is ended with it; the binding's object ends all the same (review r1)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const run = await signIn(w, made.id);
  assert.ok(run.outcome.ok);
  const planted = randomUUID();
  await db.owner.insert(credentialsTable).values({
    id: planted, kind: 'service', authMac: randomBytes(32), tokenHash: randomBytes(32), tokenHint: 'x', generation: 0, principal: CI,
    createdBy: `binding:${made.id}`, expiresAt: new Date(Date.now() + 300_000),
  });
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
  assert.deepEqual(await ops({ kind: 'binding', id: made.id }), ['binding.make', 'binding.revoke']);
  assert.deepEqual(await ops({ kind: 'credential', id: planted }), [], 'none of the log\'s: no change of it');
  assert.ok((await db.owner.select().from(credentialsTable)).every((row) => row.revokedAt !== null), 'both ended');
});

test("a bind weighed beside the account's bindings as they were is read again when another was made meanwhile, or a key it reads renamed (review r1)", async () => {
  const w = await world();
  assert.ok((await w.vault.changeBindings!(change({ make: binding(w), reason: 'replaced' }))).ok);
  // Beside none, as it read them before the first was made.
  assert.deepEqual(await w.vault.changeBindings!(change({ make: binding(w), live: [], reason: 'replaced' })), { ok: false, refused: 'moved' });
  // A key its policy reads, asked by a name it no longer has.
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
  const client = randomUUID();
  await db.owner.insert(oauthClients).values({ id: client, name: 'agent', redirectUris: [], authMac: randomBytes(32) } as never);
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

test("a key a replacing bind reads, renamed while it waits for the fence, has it read again: the names compared once the fence is had (review r4)", async () => {
  const w = await world();
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

test("one new binding id asked for two accounts at once, the first's row deleted once it committed: the second is no second make of it (review r4)", async () => {
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
  const [saved] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, made.id));
  const before = await read(made.id);
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }))).ok);
  await db.owner.update(serviceBindings).set({ revokedAt: null, revokedBy: null, authMac: saved!.authMac, seal: saved!.seal }).where(eq(serviceBindings.id, made.id));
  const none = (await db.owner.select().from(credentialsTable)).length;
  const now = Date.now();
  const outcome = await w.vault.signIn!({
    principal: CI, binding: { columns: before.columns, seal: before.seal },
    credential: {
      id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'x', label: null, scope: before.columns.scope,
      places: null, expiresAt: now + 60_000, notAfter: null, jkt: null, authMac: randomBytes(32).toString('base64'),
    },
    appKey: APP_KEY, spent: randomBytes(32).toString('base64'), validUntil: now + 60_000, record: { proof: 'oidc', issuer: ISSUER, run: {} }, idToken: null, dpop: null,
  });
  assert.deepEqual(outcome, { ok: false, refused: 'unbound' });
  assert.equal((await db.owner.select().from(credentialsTable)).length, none, 'nothing written');
});

test("a sweep closes the binding, revoking only the credentials it names, each a change, waiting for no seal; a closed binding signs nobody in, and the end ends it (W331, Unbinding.tla)", async () => {
  const w = await world();
  const made = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: made, reason: 'replaced' }))).ok);
  const first = await signIn(w, made.id);
  const second = await signIn(w, made.id);
  assert.ok(first.outcome.ok && second.outcome.ok);
  assert.equal((await w.vault.about()).sweeps, true);
  const swept = await w.vault.changeBindings!(change({ ends: [await ending(made.id, [first.credential])], sweep: true }));
  assert.ok(swept.ok, JSON.stringify(swept));
  assert.equal(swept.witnessed, null, 'no seal waited for');
  // Closed, not ended: no change of the binding's; the one named revoked, the other still live.
  assert.deepEqual(await ops({ kind: 'binding', id: made.id }), ['binding.make']);
  assert.deepEqual(await ops({ kind: 'credential', id: first.credential }), ['credential.issue', 'credential.revoke']);
  assert.deepEqual(await ops({ kind: 'credential', id: second.credential }), ['credential.issue']);
  const [row] = await db.owner.select({ closedAt: serviceBindings.closedAt, revokedAt: serviceBindings.revokedAt }).from(serviceBindings).where(eq(serviceBindings.id, made.id));
  assert.deepEqual([row!.closedAt !== null, row!.revokedAt], [true, null]);
  assert.deepEqual((await signIn(w, made.id)).outcome, { ok: false, refused: 'unbound' });
  // A sweep of none closes again, changing nothing; then the end, the rest named.
  assert.ok((await w.vault.changeBindings!(change({ ends: [await ending(made.id, [])], sweep: true }))).ok);
  const ended = await w.vault.changeBindings!(change({ ends: [await ending(made.id)] }));
  assert.ok(ended.ok, JSON.stringify(ended));
  assert.deepEqual(await ops({ kind: 'binding', id: made.id }), ['binding.make', 'binding.revoke']);
  assert.deepEqual(await ops({ kind: 'credential', id: second.credential }), ['credential.issue', 'credential.revoke']);
});

test('a sweep closes and revokes, and ends nothing: one with none to close is no sweep (W331)', async () => {
  const w = await world();
  await assert.rejects(w.vault.changeBindings!(change({ make: binding(w), reason: 'replaced', sweep: true })), /a change of bindings names/);
  await assert.rejects(w.vault.changeBindings!(change({ ends: [], sweep: true })), /a change of bindings names/);
});

test("a replacement's sweep makes its binding as it closes the one it replaces, weighed on its maker's standing: a demoted maker's sweep closes, revokes and makes nothing (reviews r4, r9)", async () => {
  const w = await world();
  const old = binding(w);
  assert.ok((await w.vault.changeBindings!(change({ make: old, reason: 'replaced' }))).ok);
  const run = await signIn(w, old.id);
  assert.ok(run.outcome.ok);
  // As the Owner, weighed: the old one closed and its batch revoked, the new one made in the same statement, so that no
  // request that stops after it leaves the old closed and nothing in its place (Unbinding.tla's MakesAtClose).
  const next = binding(w);
  const swept = await w.vault.changeBindings!(change({ make: next, live: [old.id], ends: [await ending(old.id)], reason: 'replaced', sweep: true }));
  assert.ok(swept.ok, JSON.stringify(swept));
  assert.deepEqual(await ops({ kind: 'binding', id: next.id }), ['binding.make']);
  assert.deepEqual(await ops({ kind: 'credential', id: run.credential }), ['credential.issue', 'credential.revoke']);
  const [made] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, next.id));
  assert.ok(made !== undefined && made.revokedAt === null && made.closedAt === null);
  const [closed] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, old.id));
  assert.ok(closed!.closedAt !== null && closed!.revokedAt === null, 'the old one closed, not ended');
  // A maker whose access moved since the app weighed it (a demotion, say): the sweep refused, nothing closed or revoked.
  const other = binding(w);
  // Beside every binding not ended: the old one, closed, and the one its sweep made.
  assert.ok((await w.vault.changeBindings!(change({ make: other, live: [old.id, next.id], reason: 'replaced' }))).ok);
  const second = await signIn(w, other.id);
  assert.ok(second.outcome.ok);
  const [{ accessSeq }] = (await db.owner.select({ accessSeq: principals.accessSeq }).from(principals).where(eq(principals.principal, ROOT))) as [{ accessSeq: bigint }];
  const refusedMake = binding(w);
  const stale = await w.vault.changeBindings!(change({
    make: refusedMake, live: [old.id, next.id, other.id], ends: [await ending(other.id)], reason: 'replaced', sweep: true, actorAccess: String(BigInt(accessSeq) + 1n),
  }));
  assert.equal(!stale.ok && stale.refused, 'access');
  const [row] = await db.owner.select({ closedAt: serviceBindings.closedAt }).from(serviceBindings).where(eq(serviceBindings.id, other.id));
  assert.equal(row!.closedAt, null);
  assert.deepEqual(await ops({ kind: 'credential', id: second.credential }), ['credential.issue']);
  assert.deepEqual(await ops({ kind: 'binding', id: refusedMake.id }), []);
});
