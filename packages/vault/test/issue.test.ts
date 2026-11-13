// The vault issues tokens itself (credentials.ts; migration 0036): a service account's token, a person's
// personal token, a handle, each weighed by the vault on what it reads (formal/Lifecycle.tla's IssueRead), then written
// in one statement that holds those rows as read (IssuerLocked, IssuerCAS).
import { defineDeployment } from '@coffre/core/deployment';
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { EVERYWHERE, HANDLE_POLICY, issuedGrant, type Holdings, MAX_PERSONAL_TOKEN_MINUTES, MAX_SERVICE_TOKEN_DAYS, storedScope } from '@coffre/core/access';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import { CLOCK_SKEW_MS, type IssueTokenInput } from '@coffre/core/vault';
import { postgresSession } from '@coffre/db/connect';
import { asc, count, desc, eq, sql } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { weighIssue } from '../src/credentials.ts';
import { objectKey } from '../src/inputs.ts';
import { emptyDatabase, newEnvironment, newProject, openLocalVault, openTestDatabase, OWNER_URL, sealed, nothingHeld, withLogUnlocked, type TestDatabase } from './database.ts';
import { auditLog, credentials, logChanges, passkeys, principals } from '@coffre/db/schema';

const ROOT = 'user:root@acme.example';
const ADMIN = 'user:admin@acme.example';
const CI = 'token:ci';
const APP_KEY = 'app:0123456789abcdef';
/** `issue_token` as 0.16's vault calls it, with the passkey it carries (0064); the previous release's signature lacks the last `uuid`. */
const OLD_ISSUE_TOKEN = 'issue_token(text, bigint, text, text, bytea, bytea, text, integer, bigint, integer, bigint, uuid, bytea, bigint, bigint, uuid[], text[], text, uuid, text, bytea, bytea, text, text, text, text, text, bigint)';
const ISSUE_TOKEN = `${OLD_ISSUE_TOKEN.slice(0, -1)}, uuid)`;
/** The person's factor lock, as `issue_token` takes it and a change to their passkeys will (docs/design/passkeys.md, section 6.1). */
const factorLock = (principal: string) => `SELECT pg_advisory_xact_lock(1717658484, hashtext('${principal}'))`;

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

/** A vault keeping 0.15's log; an Owner, an Admin who is no Owner, and a service account that views a project, which has an environment. */
async function world() {
  const vault = await openLocalVault(db.vault, configure(), { sealThrough: sealed, heldOutside: nothingHeld });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  const environment = await newEnvironment(db.owner, project);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'admin' })).ok);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  return { vault, project, environment };
}

type World = Awaited<ReturnType<typeof world>>;

/** A token as the app asks the vault to issue it: a service token from the Owner, unless `change` says otherwise. */
function asked(w: World, change: (input: IssueTokenInput) => IssueTokenInput = (input) => input, sensitive = false): IssueTokenInput {
  return change({
    actor: ROOT,
    via: null,
    principal: CI,
    generation: 0,
    actorSeal: null,
    credential: {
      id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'coffre_svc_x', label: 'deploys',
      scope: storedScope([{ ...issuedGrant({ projectId: w.project, environmentId: null, role: 'viewer' }), sensitive }]),
      places: null, expiresAt: Date.now() + 86_400_000, createdBy: 'root@acme.example', passkeyId: null, authMac: randomBytes(32).toString('base64'),
    },
    policy: { seq: null, protected: [] },
    appKey: APP_KEY,
  });
}

/** A personal token of `actor`'s, as the app asks for one, on `via`. */
function personal(w: World, actor = ROOT, via: string | null = null, expiresAt = Date.now() + 3_600_000): IssueTokenInput {
  return asked(w, (input) => ({
    ...input, actor, via, principal: actor,
    credential: { ...input.credential, kind: 'personal', tokenHint: 'coffre_pat_x', expiresAt, createdBy: actor.slice('user:'.length) },
  }));
}

/** A handle of `actor`'s on `via`, as the app makes one: a viewer of the world's environment, made for it; `grant` changes its grant. */
function handleOf(w: World, via: string | null, expiresAt = Date.now() + 1_800_000, grant: (made: ReturnType<typeof issuedGrant>) => ReturnType<typeof issuedGrant> = (made) => made): IssueTokenInput {
  const input = personal(w, ROOT, via, expiresAt);
  input.credential.kind = 'handle';
  input.credential.tokenHint = 'coffre_use_x';
  input.credential.scope = storedScope([grant(issuedGrant({ projectId: w.project, environmentId: w.environment, role: 'viewer' }, HANDLE_POLICY))]);
  input.credential.places = JSON.stringify([{ environmentId: w.environment, personal: false }]);
  return input;
}

/** A handle's grant made on a viewer's personal token: what the token holds there, as the app caps it (`heldColumns`), reading only where nothing is protected. */
const onViewerToken = (grant: ReturnType<typeof issuedGrant>) => ({ ...grant, permissions: { normal: grant.permissions!.normal, protected: ['secret.use'] } }) as ReturnType<typeof issuedGrant>;

async function credentialRows(): Promise<number> {
  return (await db.owner.select({ n: count() }).from(credentials))[0]!.n;
}

test("an Owner's service token is one change of the log, its row the object it seals, its record who issued it on what (D147)", async () => {
  const w = await world();
  const input = asked(w, (x) => x, true);
  const outcome = await w.vault.issueToken!(input);
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, input.credential.id));
  assert.equal(row!.principal, CI);
  assert.equal(row!.scope, input.credential.scope);
  assert.notEqual(row!.seal, null);
  const [change] = await db.owner.select().from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'credential', id: input.credential.id }))).orderBy(asc(logChanges.number));
  assert.equal(change!.actor, ROOT);
  assert.deepEqual((JSON.parse(change!.payload) as { issue: unknown }).issue, { by: ROOT, via: null, kind: 'service', label: 'deploys' });
});

test('only an Owner of its project gives a service account sensitive reads (R32): an Admin is refused, nothing written', async () => {
  const w = await world();
  const none = await credentialRows();
  const byAdmin = (sensitive: boolean) => asked(w, (input) => ({ ...input, actor: ADMIN, credential: { ...input.credential, createdBy: 'admin@acme.example' } }), sensitive);
  const refused = await w.vault.issueToken!(byAdmin(true));
  assert.equal(refused.ok, false);
  assert.equal(!refused.ok && refused.refused, 'refused');
  assert.equal(await credentialRows(), none);
  // The same Admin gives it what is no sensitive read.
  assert.ok((await w.vault.issueToken!(byAdmin(false))).ok);
});

test('a token reaches at most what its account holds and its issuer could give it: a project the account holds nothing of is refused', async () => {
  const w = await world();
  const elsewhere = await newProject(db.owner);
  const outcome = await w.vault.issueToken!(asked(w, (input) => ({ ...input, credential: { ...input.credential, scope: storedScope([issuedGrant({ projectId: elsewhere, environmentId: null, role: 'viewer' })]) } })));
  assert.equal(!outcome.ok && outcome.refused, 'refused');
});

test("a personal token is its person's own, a role that manages no access, made on a session, never on a token", async () => {
  const w = await world();
  assert.ok((await w.vault.issueToken!(personal(w))).ok);
  // One that manages access.
  const managing = personal(w);
  managing.credential.scope = storedScope([issuedGrant({ projectId: w.project, environmentId: null, role: 'owner' })]);
  assert.equal((await w.vault.issueToken!(managing)) .ok, false);
  // One made on a personal token.
  const first = personal(w);
  assert.ok((await w.vault.issueToken!(first)).ok);
  const outcome = await w.vault.issueToken!(personal(w, ROOT, first.credential.id));
  assert.equal(!outcome.ok && outcome.refused, 'refused');
});

test("a grant's columns are what a use decides on, so they are held to its role: a viewer's that manages access, or a handle's that writes, is refused (review r1)", async () => {
  const w = await world();
  const columns = (normal: string[], protectedColumn: string[] = []) => storedScope([{
    ...issuedGrant({ projectId: w.project, environmentId: null, role: 'viewer' }),
    permissions: { normal, protected: protectedColumn },
  } as ReturnType<typeof issuedGrant>]);
  // The Owner holds `grant.manage`: as the viewer's columns, it would make a personal token that manages access.
  const forged = personal(w);
  forged.credential.scope = columns(['secret.read', 'grant.manage']);
  assert.equal(((await w.vault.issueToken!(forged)) as { refused?: string }).refused, 'refused');
  // A handle reads and uses: nothing it writes, whatever its person holds.
  const writes = handleOf(w, null, undefined, (grant) => ({ ...grant, permissions: { normal: ['secret.read', 'secret.use', 'secret.write'], protected: [] } }));
  assert.equal(((await w.vault.issueToken!(writes)) as { refused?: string }).refused, 'refused');
  const developer = handleOf(w, null, undefined, (grant) => ({ ...grant, role: 'developer' }));
  assert.equal(((await w.vault.issueToken!(developer)) as { refused?: string }).refused, 'refused', 'a handle is a viewer or a contributor');
  assert.equal(await credentialRows(), 0);
  // As the app makes them, each within its role.
  const fair = personal(w);
  fair.credential.scope = columns(['secret.read']);
  assert.ok((await w.vault.issueToken!(fair)).ok);
  assert.ok((await w.vault.issueToken!(handleOf(w, null))).ok);
});

test("a service token keeps at most its roles' columns, and only a person gives one: a service account managing access gives none (review r2)", async () => {
  const w = await world();
  const OTHER = 'token:other';
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: OTHER })).ok);
  for (const principal of [CI, OTHER]) {
    assert.ok((await w.vault.setAccess({ actor: ROOT, caller: 'person', principal, changes: [{ projectId: w.project, environmentId: null, role: principal === CI ? 'owner' : 'developer', expiresAt: null }] })).ok);
  }
  // A Developer account's token named `viewer` that writes: its scope says one thing, its columns another.
  const forged = asked(w, (input) => ({ ...input, principal: OTHER, credential: { ...input.credential, scope: storedScope([{
    ...issuedGrant({ projectId: w.project, environmentId: null, role: 'viewer' }),
    permissions: { normal: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.use'] },
  } as ReturnType<typeof issuedGrant>]) } }));
  assert.equal(((await w.vault.issueToken!(forged)) as { refused?: string }).refused, 'refused');
  assert.ok((await w.vault.issueToken!(asked(w, (input) => ({ ...input, principal: OTHER })))).ok, 'a viewer as the role is');
  // An account that is an Owner of the project, on a credential of its own, gives another account nothing.
  const bySelf = asked(w, (input) => ({ ...input, actor: CI, principal: OTHER, credential: { ...input.credential, createdBy: 'ci' } }));
  assert.equal(((await w.vault.issueToken!(bySelf)) as { refused?: string }).refused, 'refused');
});

test("a handle's end is held to the scoped credential it was made on, by what the credential's object seals: a row whose kind was edited bounds it as before (R53, review r2)", async () => {
  const w = await world();
  const token = personal(w, ROOT, null, Date.now() + 120_000);
  assert.ok((await w.vault.issueToken!(token)).ok);
  // A writer makes the personal token a CLI session, in its row alone: its object, scope and seal unchanged.
  await db.owner.update(credentials).set({ kind: 'cli' }).where(eq(credentials.id, token.credential.id));
  const outcome = await w.vault.issueToken!(handleOf(w, token.credential.id, Date.now() + 3_600_000, onViewerToken));
  assert.equal(!outcome.ok && outcome.why, 'a handle lasts at most a week, and never past the token that made it');
});

test("a token's end may run past its longest by CLOCK_SKEW_MS, the app's clock against the vault's, and not a millisecond further (#501 D3, review r1 of #534)", async () => {
  const w = await world();
  // Weighed at a fixed time, as the vault weighs what it read at its own clock's `at`: neither clock nor a pause moves the bound.
  const at = Date.UTC(2026, 10, 6);
  const holder: Holdings = { role: 'member', scope: EVERYWHERE, grants: [] };
  const ending = (input: IssueTokenInput, expiresAt: number): IssueTokenInput => ({ ...input, credential: { ...input.credential, expiresAt } });
  const longest = [
    { make: () => asked(w), ms: MAX_SERVICE_TOKEN_DAYS * 86_400_000, why: `a service token lasts at most ${MAX_SERVICE_TOKEN_DAYS} days here` },
    { make: () => personal(w), ms: MAX_PERSONAL_TOKEN_MINUTES * 60_000, why: 'a personal token lasts at most a week' },
    { make: () => handleOf(w, null), ms: MAX_PERSONAL_TOKEN_MINUTES * 60_000, why: 'a handle lasts at most a week, and never past the token that made it' },
  ];
  for (const { make, ms, why } of longest) {
    const weigh = (expiresAt: number) => weighIssue(ending(make(), expiresAt), [], holder, [], null, at, null);
    assert.notEqual(weigh(at + ms + CLOCK_SKEW_MS), why, `${why}: its longest and a minute is kept`);
    assert.equal(weigh(at + ms + CLOCK_SKEW_MS + 1), why, `${why}: a millisecond past is refused`);
  }
  // The deployment's own longest service token (`services.tokenMaxDays`), which the vault holds as the app does.
  const month = (expiresAt: number) => weighIssue(ending(asked(w), expiresAt), [], holder, [], null, at, null, 30);
  assert.notEqual(month(at + 30 * 86_400_000 + CLOCK_SKEW_MS), 'a service token lasts at most 30 days here');
  assert.equal(month(at + 30 * 86_400_000 + CLOCK_SKEW_MS + 1), 'a service token lasts at most 30 days here');
});

test("a handle names each environment it reaches, and stands in for those alone: no project's grant, no place it does not reach, no mapping it cannot read (review r3)", async () => {
  const w = await world();
  const wide = handleOf(w, null, undefined, (grant) => ({ ...grant, environmentId: null }));
  assert.equal(((await w.vault.issueToken!(wide)) as { refused?: string }).refused, 'refused', "a project's grant reaches its environments to come");
  const elsewhere = handleOf(w, null);
  elsewhere.credential.places = JSON.stringify([{ environmentId: randomUUID(), personal: false }]);
  assert.equal(((await w.vault.issueToken!(elsewhere)) as { refused?: string }).refused, 'refused');
  const garbled = handleOf(w, null);
  garbled.credential.places = 'not JSON';
  assert.equal(((await w.vault.issueToken!(garbled)) as { refused?: string }).refused, 'refused');
  assert.equal(await credentialRows(), 0);
});

test("a credential 0.14 made, which the log never held, authorizes no issue of the vault's: it answers `unlogged`, and the app issues as before (review r3)", async () => {
  const w = await world();
  const token = personal(w);
  assert.ok((await w.vault.issueToken!(token)).ok);
  // As 0.14 left it: no seal, no change.
  await db.owner.update(credentials).set({ seal: null }).where(eq(credentials.id, token.credential.id));
  await db.owner.delete(logChanges).where(eq(logChanges.object, objectKey({ kind: 'credential', id: token.credential.id })));
  assert.equal(((await w.vault.issueToken!(handleOf(w, token.credential.id, undefined, onViewerToken))) as { refused?: string }).refused, 'unlogged');
});

test("an issue's write holds the credential it came in on to the end the vault authenticated: one extended while it waits, its seal unchanged, ends it (review r3)", async () => {
  const w = await world();
  const token = personal(w, ROOT, null, Date.now() + 3_600_000);
  assert.ok((await w.vault.issueToken!(token)).ok);
  const holder = postgresSession(OWNER_URL);
  try {
    // A writer holds the token's row and pushes its end out a day, its seal as it was; the issue reads it before that commits.
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM credentials WHERE id = '${token.credential.id}' FOR UPDATE`);
    await holder.unsafe(`UPDATE credentials SET expires_at = expires_at + interval '1 day' WHERE id = '${token.credential.id}'`);
    const issuing = w.vault.issueToken!(handleOf(w, token.credential.id, undefined, onViewerToken));
    const waits = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%issue_token(%'`))[0]!.n;
    for (let tries = 0; (await waits()) === 0; tries += 1) {
      assert.ok(tries < 200, 'the write waits on the row');
      await sleep(10);
    }
    await holder.unsafe('COMMIT');
    const outcome = await issuing;
    assert.equal(!outcome.ok && outcome.refused, 'ended', JSON.stringify(outcome));
  } finally {
    await holder.end();
  }
});

test('a handle is made on a personal token only within its end, and not once it is revoked (IssuedByLiveCredential)', async () => {
  const w = await world();
  const token = personal(w, ROOT, null, Date.now() + 3_600_000);
  assert.ok((await w.vault.issueToken!(token)).ok);
  const handle = (expiresAt: number) => handleOf(w, token.credential.id, expiresAt, onViewerToken);
  assert.equal((await w.vault.issueToken!(handle(Date.now() + 2 * 3_600_000))).ok, false, 'past the token that made it');
  // Past the token's columns: reading a protected place, which a viewer's token only uses (`heldColumns`, through it).
  const reads = await w.vault.issueToken!(handleOf(w, token.credential.id));
  assert.equal(!reads.ok && reads.why, 'a handle reads and uses at most what its person holds, through what it was made on');
  assert.ok((await w.vault.issueToken!(handle(Date.now() + 1_800_000))).ok);
  // Revoked, it makes nothing more.
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, token.credential.id));
  const revoked = await w.vault.revokeCredential!({
    actor: ROOT, before: { columns: { id: row!.id, principal: row!.principal, kind: row!.kind, scope: row!.scope, revoked: false, expiresAt: row!.expiresAt.getTime(), generation: row!.generation }, seal: Buffer.from(row!.seal!).toString('base64') },
    authMacFrom: Buffer.from(row!.authMac).toString('base64'), authMac: randomBytes(32).toString('base64'), revokedAt: Date.now(), revokedBy: 'root@acme.example', reason: 'revoke', via: null, policy: null,
  });
  assert.ok(revoked.ok);
  const outcome = await w.vault.issueToken!(handle(Date.now() + 1_800_000));
  assert.equal(!outcome.ok && outcome.refused, 'ended');
});

test("a revoked token a writer put back, its revoke's seal column written to match, makes no handle: that change's MAC does not hold (T190)", async () => {
  const w = await world();
  const token = personal(w, ROOT, null, Date.now() + 3_600_000);
  assert.ok((await w.vault.issueToken!(token)).ok);
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, token.credential.id));
  const revoked = await w.vault.revokeCredential!({
    actor: ROOT, before: { columns: { id: row!.id, principal: row!.principal, kind: row!.kind, scope: row!.scope, revoked: false, expiresAt: row!.expiresAt.getTime(), generation: row!.generation }, seal: Buffer.from(row!.seal!).toString('base64') },
    authMacFrom: Buffer.from(row!.authMac).toString('base64'), authMac: randomBytes(32).toString('base64'), revokedAt: Date.now(), revokedBy: 'root@acme.example', reason: 'revoke', via: null, policy: null,
  });
  assert.ok(revoked.ok);
  // The writer: the row as it was before its revoke, and the revoke's seal column made that row's seal (not its MAC).
  await db.owner.update(credentials).set({ revokedAt: null, seal: row!.seal, authMac: row!.authMac }).where(eq(credentials.id, row!.id));
  const [newest] = await db.owner.select({ number: logChanges.number }).from(logChanges).where(eq(logChanges.object, objectKey({ kind: 'credential', id: row!.id }))).orderBy(desc(logChanges.number)).limit(1);
  await db.owner.update(logChanges).set({ seal: row!.seal }).where(eq(logChanges.number, newest!.number));
  const issued = await credentialRows();
  const outcome = await w.vault.issueToken!(handleOf(w, token.credential.id, Date.now() + 1_800_000, onViewerToken));
  assert.equal(!outcome.ok && outcome.refused, 'ended', JSON.stringify(outcome));
  assert.equal(await credentialRows(), issued, 'nothing issued');
});

test('an account not at the generation named, or removed, gets no token; a policy moved since, or a retired app key, refuses it', async () => {
  const w = await world();
  assert.equal(((await w.vault.issueToken!(asked(w, (input) => ({ ...input, generation: 1 })))) as { refused?: string }).refused, 'gone');
  assert.equal(((await w.vault.issueToken!(asked(w, (input) => ({ ...input, policy: { seq: '999999', protected: [] } })))) as { refused?: string }).refused, 'policy');
  assert.ok((await w.vault.remove({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.equal(((await w.vault.issueToken!(asked(w))) as { refused?: string }).refused, 'gone');
  // The app rotated from its key (its `key.rotate`, last: the vault's own entries chain on none after it here).
  await withLogUnlocked(db.owner, (owner) => owner.insert(auditLog).values({
    seq: 1_000_000n, author: 'app', keyId: 'app:fedcba9876543210', occurredAt: Date.now(), actor: 'system:coffre', action: 'key.rotate', decision: 'allow',
    subjectPrincipal: APP_KEY, metadata: '{}', prevHash: Buffer.alloc(32), mac: Buffer.alloc(32), hash: Buffer.alloc(32),
  }));
  assert.equal(((await w.vault.issueToken!(personal(w))) as { refused?: string }).refused, 'retired');
});

test("an issue weighed before its issuer's demotion commits is weighed again, on what they hold now: refused, nothing written (IssuerLocked, IssuerCAS)", async () => {
  const w = await world();
  const byAdmin = () => asked(w, (input) => ({ ...input, actor: ADMIN, credential: { ...input.credential, createdBy: 'admin@acme.example' } }));
  const holder = postgresSession(OWNER_URL);
  try {
    // The account's row held, which the issue's write locks first (by principal): its read done, the write waits there.
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM principals WHERE principal = '${CI}' FOR NO KEY UPDATE`);
    const issuing = w.vault.issueToken!(byAdmin());
    // Asked on a connection of its own: in the holder's transaction, `pg_stat_activity` stays as it first read it.
    const waits = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%issue_token(%'`))[0]!.n;
    for (let tries = 0; (await waits()) === 0; tries += 1) {
      assert.ok(tries < 200, 'the write waits on the row');
      await sleep(10);
    }
    // Meanwhile the Admin is demoted, and that commits: the issue was weighed on a right they no longer hold.
    assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'member' })).ok);
    await holder.unsafe('COMMIT');
    const outcome = await issuing;
    assert.equal(!outcome.ok && outcome.refused, 'refused', JSON.stringify(outcome));
    assert.equal(await credentialRows(), 0);
  } finally {
    await holder.end();
  }
});

/** A member's seal as their row holds it (`memberSeal`): base64, null for no row. */
async function sealOf(principal: string): Promise<string | null> {
  const [row] = await db.owner.select({ seal: principals.seal }).from(principals).where(eq(principals.principal, principal));
  return row?.seal?.toString('base64') ?? null;
}

test("the vault's answer carries the seal of the row it checked: the Owner it names, at the first answer that makes their row; none without a row", async () => {
  const vault = await openLocalVault(db.vault, configure(), { sealThrough: sealed, heldOutside: nothingHeld });
  const first = await vault.access(ROOT);
  assert.equal(first.role, 'owner');
  assert.notEqual(first.seal, null);
  assert.equal(first.seal, await sealOf(ROOT));
  assert.equal((await vault.access('user:nobody@acme.example')).seal, null);
  // A change reseals the row, and the next answer carries it.
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'admin' })).ok);
  const before = await sealOf(ADMIN);
  assert.equal((await vault.access(ADMIN)).seal, before);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'developer' })).ok);
  assert.notEqual(await sealOf(ADMIN), before);
  assert.equal((await vault.access(ADMIN)).seal, await sealOf(ADMIN));
});

/** The Admin's service token, weighed on `seal`. */
const byAdmin = (w: World, seal: string | null) => asked(w, (input) => ({ ...input, actor: ADMIN, actorSeal: seal, credential: { ...input.credential, createdBy: 'admin@acme.example' } }));

test("an issue the app weighed on its issuer's access as it was is refused, for the app to weigh again; at the access as it is, issued", async () => {
  const w = await world();
  const weighed = await sealOf(ADMIN);
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'developer' })).ok);
  assert.equal(((await w.vault.issueToken!(byAdmin(w, weighed))) as { refused?: string }).refused, 'access');
  assert.ok((await w.vault.issueToken!(byAdmin(w, await sealOf(ADMIN)))).ok);
});

test("each change of a member's access moves their seal: an issue weighed before it is refused", async () => {
  const w = await world();
  const changes: [string, () => Promise<{ ok: boolean }>][] = [
    ['role', () => w.vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'developer' })],
    ['owner', () => w.vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'owner' })],
    ['grant', () => w.vault.setAccess({ actor: ROOT, caller: 'person', principal: ADMIN, changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }] })],
    ['revoke', () => w.vault.setAccess({ actor: ROOT, caller: 'person', principal: ADMIN, changes: [{ projectId: w.project, environmentId: null, role: null, expiresAt: null }] })],
    ['remove', () => w.vault.remove({ actor: ROOT, caller: 'person', principal: ADMIN })],
    ['restore', () => w.vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'admin' })],
  ];
  for (const [change, make] of changes) {
    const weighed = await sealOf(ADMIN);
    assert.ok((await make()).ok, change);
    assert.notEqual(await sealOf(ADMIN), weighed, change);
    // Removed, they are refused before their seal is weighed.
    assert.equal(((await w.vault.issueToken!(byAdmin(w, weighed))) as { refused?: string }).refused, change === 'remove' ? 'ended' : 'access', change);
  }
  // An add: no row, no seal, then one.
  assert.equal(await sealOf('user:new@acme.example'), null);
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: 'user:new@acme.example' })).ok);
  assert.match(String(await sealOf('user:new@acme.example')), /^[A-Za-z0-9+/]{22}==$/);
  assert.equal(await credentialRows(), 0);
});

test('an issuer whose row holds no seal is refused, whatever seal the app weighed', async () => {
  const w = await world();
  const weighed = await sealOf(ADMIN);
  await db.owner.update(principals).set({ seal: null }).where(eq(principals.principal, ADMIN));
  // Its answer is `tampered`, and carries none.
  assert.deepEqual(await w.vault.access(ADMIN).then(({ status, seal }) => ({ status, seal })), { status: 'tampered', seal: null });
  for (const seal of [weighed, null]) assert.equal(((await w.vault.issueToken!(byAdmin(w, seal))) as { refused?: string }).refused, 'ended');
  assert.equal(await credentialRows(), 0);
});

test('an issue weighed before a demotion and its undoing is issued: their seal is back where it was', async () => {
  const w = await world();
  const weighed = await sealOf(ADMIN);
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'developer' })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: ADMIN, role: 'admin' })).ok);
  // The seal is over their access alone: the same seal is the same access, so the issue weighed on it holds.
  assert.equal(await sealOf(ADMIN), weighed);
  assert.ok((await w.vault.issueToken!(byAdmin(w, weighed))).ok);
});

test("a policy change waits for the issues in flight, which hold the issue lock shared, before the fence: ordered, and no use waits on them (IssuePolicyHeld, PolicyIssueFirst; review r3)", async () => {
  const w = await world();
  const holder = postgresSession(OWNER_URL);
  try {
    // An issue in flight: the issue lock shared, as `issue_token` holds it from its policy check to its commit.
    await holder.unsafe('BEGIN');
    await holder.unsafe('SELECT pg_advisory_xact_lock_shared(1668244070, 1)');
    let changed = false;
    const changing = w.vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'protect', projectId: w.project, environmentIds: [w.environment], protected: true } })
      .then((outcome) => ((changed = true), outcome));
    await sleep(300);
    assert.equal(changed, false, 'the change waits for the issue');
    // Not on the fence meanwhile: a use's shared fence is free.
    const [fence] = await db.owner.execute<{ free: boolean }>(sql`SELECT NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND classid = 1668244070 AND objid = 0 AND granted) AS free`);
    assert.equal(fence!.free, true, 'it holds no fence while it waits');
    await holder.unsafe('COMMIT');
    assert.ok((await changing).ok);
  } finally {
    await holder.end();
  }
});

test("an environment the scope names, renamed while the issue's write waits, refuses it: the slugs it was weighed on are held under the issue lock (Fable on PR 2)", async () => {
  const w = await world();
  const scoped = asked(w, (input) => ({ ...input, credential: { ...input.credential, scope: storedScope([issuedGrant({ projectId: w.project, environmentId: w.environment, role: 'viewer' })]) } }));
  const holder = postgresSession(OWNER_URL);
  try {
    // The account's row held: the issue's read is done, its write waits; meanwhile the environment is renamed.
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM principals WHERE principal = '${CI}' FOR NO KEY UPDATE`);
    const issuing = w.vault.issueToken!(scoped);
    const waits = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%issue_token(%'`))[0]!.n;
    for (let tries = 0; (await waits()) === 0; tries += 1) {
      assert.ok(tries < 200, 'the write waits on the row');
      await sleep(10);
    }
    await db.owner.execute(sql`UPDATE environments SET slug = 'renamed' WHERE id = ${w.environment}`);
    await holder.unsafe('COMMIT');
    const outcome = await issuing;
    assert.equal(!outcome.ok && outcome.refused, 'policy', JSON.stringify(outcome));
    assert.equal(await credentialRows(), 0);
  } finally {
    await holder.end();
  }
});

test("`issue_token` compares the policy only once it holds the issue lock shared (IssuePolicyHeld)", async () => {
  const [{ body }] = await db.owner.execute<{ body: string }>(sql`SELECT pg_get_functiondef(${ISSUE_TOKEN}::regprocedure) AS body`);
  const lock = body.indexOf('pg_advisory_xact_lock_shared(1668244070, 1)');
  assert.ok(lock > 0 && lock < body.indexOf("'policy.change'") && body.indexOf("'policy.change'") < body.indexOf('INSERT INTO public.log_changes'));
});

test('an issue takes the issue lock, never the fence: it commits while a change holds the fence exclusive (IssueOffFence, R58)', async () => {
  const w = await world();
  const holder = postgresSession(OWNER_URL);
  try {
    await holder.unsafe('BEGIN');
    await holder.unsafe('SELECT pg_advisory_xact_lock(1668244070, 0)');
    assert.ok((await w.vault.issueToken!(asked(w))).ok, 'issued while the fence is held');
    await holder.unsafe('COMMIT');
  } finally {
    await holder.end();
  }
});

// --- the person's factor lock and the passkey an issue carries (docs/design/passkeys.md, sections 6.1 and 6.3;
// migration 0064; formal/Factor.tla) -------------------------------------------------------------------------------------

/** A passkey of `principal`'s, as the app writes one at enrollment; its MAC is the app's, which the vault never reads. */
async function passkeyOf(principal: string, generationsAgo = 0): Promise<string> {
  const [member] = await db.owner.select({ generation: principals.generation }).from(principals).where(eq(principals.principal, principal));
  const id = randomUUID();
  await db.owner.insert(passkeys).values({
    id, authMac: randomBytes(32), principal, generation: member!.generation - generationsAgo, userHandle: randomBytes(16), credentialId: randomBytes(32), publicKey: randomBytes(77),
    algorithm: -7, transports: [], synced: true, name: 'iCloud Keychain', createdBy: principal.slice('user:'.length),
  });
  return id;
}

/** A personal token of the Owner's, issued by the vault, that `passkey` confirmed: the source a handle comes in on. */
async function confirmedToken(w: World, passkey: string | null): Promise<IssueTokenInput> {
  const token = personal(w, ROOT, null, Date.now() + 3_600_000);
  assert.ok((await w.vault.issueToken!(token)).ok);
  // Written as the app's sign-in will; the vault reads the column, which its seal does not cover.
  await db.owner.update(credentials).set({ passkeyId: passkey }).where(eq(credentials.id, token.credential.id));
  return token;
}

const carrying = (input: IssueTokenInput, passkeyId: string | null): IssueTokenInput => ({ ...input, credential: { ...input.credential, passkeyId } });

test("a token carries the passkey of the credential it came in on, and only that one, while it is its issuer's and live (section 6.3)", async () => {
  const w = await world();
  const passkey = await passkeyOf(ROOT);
  const other = await passkeyOf(ROOT);
  const token = await confirmedToken(w, passkey);
  const handle = (passkeyId: string | null) => carrying(handleOf(w, token.credential.id, undefined, onViewerToken), passkeyId);
  // None, or another of the same person's: the row's MAC would name a passkey that is not `via`'s.
  for (const named of [null, other]) {
    const outcome = await w.vault.issueToken!(handle(named));
    assert.equal(!outcome.ok && outcome.refused, 'ended', String(named));
  }
  assert.equal(await credentialRows(), 1, 'nothing written');
  // `via`'s own: issued, and the row names it.
  const made = handle(passkey);
  assert.ok((await w.vault.issueToken!(made)).ok);
  const [row] = await db.owner.select({ passkeyId: credentials.passkeyId }).from(credentials).where(eq(credentials.id, made.credential.id));
  assert.equal(row!.passkeyId, passkey);
  // One of an earlier generation of theirs, which a removal from the vault ended (`passkeys_live_idx`), though its
  // session somehow named it: not live, nothing comes of it.
  const stale = await passkeyOf(ROOT, 1);
  await db.owner.update(credentials).set({ passkeyId: stale }).where(eq(credentials.id, token.credential.id));
  const old = await w.vault.issueToken!(handle(stale));
  assert.equal(!old.ok && old.refused, 'ended');
  assert.equal(await credentialRows(), 2, 'nothing written');
  await db.owner.update(credentials).set({ passkeyId: passkey }).where(eq(credentials.id, token.credential.id));
  // Removed (its session not revoked, which a removal does too): nothing more comes of it.
  await db.owner.update(passkeys).set({ removedAt: new Date(), removedBy: 'root@acme.example' }).where(eq(passkeys.id, passkey));
  const outcome = await w.vault.issueToken!(handle(passkey));
  assert.equal(!outcome.ok && outcome.refused, 'ended');
  assert.equal(await credentialRows(), 2);
});

test('a token on no credential carries no passkey, and one on a credential no passkey confirmed issues as before', async () => {
  const w = await world();
  const passkey = await passkeyOf(ROOT);
  await assert.rejects(w.vault.issueToken!(carrying(asked(w), passkey)), /carries the passkey of the credential it came in on/);
  const token = await confirmedToken(w, null);
  assert.ok((await w.vault.issueToken!(handleOf(w, token.credential.id, undefined, onViewerToken))).ok);
});

test("a change to a person's passkeys that holds their factor lock: an issue on their session waits for it, then finds the session it revoked ended (review r12, IssueTakesFactor)", async () => {
  const w = await world();
  const passkey = await passkeyOf(ROOT);
  const token = await confirmedToken(w, passkey);
  const change = postgresSession(OWNER_URL);
  try {
    // A removal: the factor lock, then the person's credentials read, then each revoked; the commit.
    await change.unsafe('BEGIN');
    await change.unsafe(factorLock(ROOT));
    const issuing = w.vault.issueToken!(carrying(handleOf(w, token.credential.id, undefined, onViewerToken), passkey));
    const waits = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'advisory' AND query LIKE '%issue_token(%'`))[0]!.n;
    for (let tries = 0; (await waits()) === 0; tries += 1) {
      assert.ok(tries < 200, 'the issue waits on the factor lock');
      await sleep(10);
    }
    const live = await change.unsafe(`SELECT id FROM credentials WHERE principal = '${ROOT}' AND revoked_at IS NULL`);
    assert.deepEqual(live.map(({ id }) => id), [token.credential.id], 'the handle is not there to miss');
    await change.unsafe(`UPDATE credentials SET revoked_at = now(), revoked_by = 'root@acme.example' WHERE principal = '${ROOT}' AND revoked_at IS NULL`);
    await change.unsafe(`UPDATE passkeys SET removed_at = now(), removed_by = 'root@acme.example' WHERE id = '${passkey}'`);
    await change.unsafe('COMMIT');
    const outcome = await issuing;
    assert.equal(!outcome.ok && outcome.refused, 'ended', JSON.stringify(outcome));
    assert.equal(await credentialRows(), 1, 'no handle');
  } finally {
    await change.end();
  }
});

test("an issue takes the factor lock first, and holds it while it waits on a member's row: a change that comes after waits for it, and then reads the token it made (FactorFirst)", async () => {
  const w = await world();
  const token = await confirmedToken(w, null);
  const holder = postgresSession(OWNER_URL);
  const change = postgresSession(OWNER_URL);
  try {
    // The Owner's member row held: the issue has the factor lock and waits there.
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM principals WHERE principal = '${ROOT}' FOR NO KEY UPDATE`);
    const made = handleOf(w, token.credential.id, undefined, onViewerToken);
    const issuing = w.vault.issueToken!(made);
    const waits = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND wait_event <> 'advisory' AND query LIKE '%issue_token(%'`))[0]!.n;
    for (let tries = 0; (await waits()) === 0; tries += 1) {
      assert.ok(tries < 200, 'the issue waits on the member row');
      await sleep(10);
    }
    // A change to the Owner's passkeys starts now: its factor lock waits for the issue.
    await change.unsafe('BEGIN');
    let locked = false;
    const locking = change.unsafe(factorLock(ROOT)).then(() => (locked = true));
    await sleep(200);
    assert.equal(locked, false, 'the change waits for the issue');
    await holder.unsafe('COMMIT');
    assert.ok((await issuing).ok);
    await locking;
    // Its read comes after the issue's commit: the handle is there to revoke.
    const live = await change.unsafe(`SELECT id FROM credentials WHERE principal = '${ROOT}' AND revoked_at IS NULL ORDER BY id`);
    assert.deepEqual(live.map(({ id }) => id).sort(), [token.credential.id, made.credential.id].sort());
    await change.unsafe('COMMIT');
  } finally {
    await holder.end();
    await change.end();
  }
});

test('`issue_token` takes the factor lock before any row, and the previous release\'s signature is the same statement carrying no passkey (0064)', async () => {
  const [{ body }] = await db.owner.execute<{ body: string }>(sql`SELECT pg_get_functiondef(${ISSUE_TOKEN}::regprocedure) AS body`);
  const lock = body.indexOf('pg_advisory_xact_lock(1717658484, hashtext(p_actor))');
  assert.ok(lock > 0 && lock < body.indexOf('FROM public.principals') && lock < body.indexOf('FROM public.credentials'));
  assert.doesNotMatch(body, /jit/i, 'no planner setting (R69)');
  const [{ old }] = await db.owner.execute<{ old: string }>(sql`SELECT pg_get_functiondef(${OLD_ISSUE_TOKEN}::regprocedure) AS old`);
  assert.match(old, /SELECT public\.issue_token\([^;]*p_expires, NULL::uuid\)/);
  assert.doesNotMatch(old, /jit/i);
  // Both the vault's to call, and no one else's.
  for (const signature of [ISSUE_TOKEN, OLD_ISSUE_TOKEN]) {
    const [grant] = await db.owner.execute<{ vault: boolean; app: boolean }>(sql`SELECT has_function_privilege('coffre_vault', ${signature}, 'EXECUTE') AS vault, has_function_privilege('coffre_app', ${signature}, 'EXECUTE') AS app`);
    assert.deepEqual({ ...grant }, { vault: true, app: false }, signature);
  }
});
