// The vault issues tokens itself (T149, PR 2; credentials.ts; migration 0036): a service account's token, a person's
// personal token, a handle, each weighed by the vault on what it reads (formal/Lifecycle.tla's IssueRead), then written
// in one statement that holds those rows as read (IssuerLocked, IssuerCAS). Both engines unless a case says otherwise.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import { issuedGrant, storedScope } from '@coffre/core/access';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { IssueTokenInput } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { postgresSession } from '@coffre/db/connect';
import { asc, count, eq, sql } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { objectKey } from '../src/inputs.ts';
import { emptyDatabase, newProject, openLocalVault, openTestDatabase, OWNER_URL, postgresOnly, sealed, withLogUnlocked, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADMIN = 'user:admin@acme.example';
const CI = 'token:ci';
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

/** A token as the app asks the vault to issue it: a service token from the Owner, unless `change` says otherwise. */
function asked(w: World, change: (input: IssueTokenInput) => IssueTokenInput = (input) => input, sensitive = false): IssueTokenInput {
  return change({
    actor: ROOT,
    via: null,
    principal: CI,
    generation: 0,
    actorAccess: null,
    credential: {
      id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'coffre_svc_x', label: 'deploys',
      scope: storedScope([{ ...issuedGrant({ projectId: w.project, environmentId: null, role: 'viewer' }), sensitive }]),
      places: null, expiresAt: Date.now() + 86_400_000, createdBy: 'root@acme.example', authMac: randomBytes(32).toString('base64'),
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

async function credentialRows(): Promise<number> {
  const { credentials } = tablesOf(db.owner);
  return (await db.owner.select({ n: count() }).from(credentials))[0]!.n;
}

test("an Owner's service token is one change of the log, its row the object it seals, its record who issued it on what (D147)", async () => {
  const w = await world();
  const input = asked(w, (x) => x, true);
  const outcome = await w.vault.issueToken!(input);
  assert.ok(outcome.ok, JSON.stringify(outcome));
  const { credentials, logChanges } = tablesOf(db.owner);
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
  const handle = personal(w);
  handle.credential.kind = 'handle';
  handle.credential.scope = columns(['secret.read', 'secret.use', 'secret.write']);
  assert.equal(((await w.vault.issueToken!(handle)) as { refused?: string }).refused, 'refused');
  handle.credential.scope = storedScope([issuedGrant({ projectId: w.project, environmentId: null, role: 'developer' })]);
  assert.equal(((await w.vault.issueToken!(handle)) as { refused?: string }).refused, 'refused', 'a handle is a viewer or a contributor');
  assert.equal(await credentialRows(), 0);
  // As the app makes them, each within its role.
  const fair = personal(w);
  fair.credential.scope = columns(['secret.read']);
  assert.ok((await w.vault.issueToken!(fair)).ok);
  handle.credential.id = randomUUID();
  handle.credential.scope = columns(['secret.read', 'secret.use'], ['secret.read', 'secret.use']);
  assert.ok((await w.vault.issueToken!(handle)).ok);
});

test('a handle is made on a personal token only within its end, and not once it is revoked (IssuedByLiveCredential)', async () => {
  const w = await world();
  const token = personal(w, ROOT, null, Date.now() + 3_600_000);
  assert.ok((await w.vault.issueToken!(token)).ok);
  const handle = (expiresAt: number) => {
    const input = personal(w, ROOT, token.credential.id, expiresAt);
    input.credential.kind = 'handle';
    input.credential.scope = storedScope([issuedGrant({ projectId: w.project, environmentId: null, role: 'viewer' })]);
    return input;
  };
  assert.equal((await w.vault.issueToken!(handle(Date.now() + 2 * 3_600_000))).ok, false, 'past the token that made it');
  assert.ok((await w.vault.issueToken!(handle(Date.now() + 1_800_000))).ok);
  // Revoked, it makes nothing more.
  const { credentials } = tablesOf(db.owner);
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, token.credential.id));
  const revoked = await w.vault.revokeCredential!({
    actor: ROOT, before: { columns: { id: row!.id, principal: row!.principal, kind: row!.kind, scope: row!.scope, revoked: false, expiresAt: row!.expiresAt.getTime(), generation: row!.generation }, seal: Buffer.from(row!.seal!).toString('base64') },
    authMacFrom: Buffer.from(row!.authMac).toString('base64'), authMac: randomBytes(32).toString('base64'), revokedAt: Date.now(), revokedBy: 'root@acme.example', reason: 'revoke', via: null, policy: null,
  });
  assert.ok(revoked.ok);
  const outcome = await w.vault.issueToken!(handle(Date.now() + 1_800_000));
  assert.equal(!outcome.ok && outcome.refused, 'ended');
});

test('an account not at the generation named, or removed, gets no token; a policy moved since, or a retired app key, refuses it', async () => {
  const w = await world();
  assert.equal(((await w.vault.issueToken!(asked(w, (input) => ({ ...input, generation: 1 })))) as { refused?: string }).refused, 'gone');
  assert.equal(((await w.vault.issueToken!(asked(w, (input) => ({ ...input, policy: { seq: '999999', protected: [] } })))) as { refused?: string }).refused, 'policy');
  assert.ok((await w.vault.remove({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.equal(((await w.vault.issueToken!(asked(w))) as { refused?: string }).refused, 'gone');
  // The app rotated from its key (its `key.rotate`, last: the vault's own entries chain on none after it here).
  const { auditLog } = tablesOf(db.owner);
  await withLogUnlocked(db.owner, (owner) => owner.insert(auditLog).values({
    seq: 1_000_000n, author: 'app', keyId: 'app:fedcba9876543210', occurredAt: Date.now(), actor: 'system:coffre', action: 'key.rotate', decision: 'allow',
    subjectPrincipal: APP_KEY, metadata: '{}', prevHash: Buffer.alloc(32), mac: Buffer.alloc(32), hash: Buffer.alloc(32),
  }));
  assert.equal(((await w.vault.issueToken!(personal(w))) as { refused?: string }).refused, 'retired');
});

test("an issue weighed before its issuer's demotion commits is weighed again, on what they hold now: refused, nothing written (IssuerLocked, IssuerCAS)", postgresOnly('row locks'), async () => {
  const w = await world();
  const byAdmin = () => asked(w, (input) => ({ ...input, actor: ADMIN, credential: { ...input.credential, createdBy: 'admin@acme.example' } }));
  const holder = postgresSession(OWNER_URL);
  try {
    // The account's row held, which the issue's write locks first (by principal): its read done, the write waits there.
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM vault_members WHERE principal = '${CI}' FOR NO KEY UPDATE`);
    const issuing = w.vault.issueToken!(byAdmin());
    // Asked on a connection of its own: in the holder's transaction, `pg_stat_activity` stays as it first read it.
    const waits = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%issue_token(%'`))[0]!.n;
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

test("an issue the app weighed on its issuer's access as it was is refused, for the app to weigh again; at the access as it is, issued", async () => {
  const w = await world();
  const { vaultMembers } = tablesOf(db.owner);
  const [{ accessSeq }] = (await db.owner.select({ accessSeq: vaultMembers.accessSeq }).from(vaultMembers).where(eq(vaultMembers.principal, ADMIN))) as [{ accessSeq: bigint }];
  const at = (seq: bigint) => asked(w, (input) => ({ ...input, actor: ADMIN, actorAccess: seq.toString(), credential: { ...input.credential, createdBy: 'admin@acme.example' } }));
  assert.equal(((await w.vault.issueToken!(at(accessSeq - 1n))) as { refused?: string }).refused, 'access');
  assert.ok((await w.vault.issueToken!(at(accessSeq))).ok);
});

test('an issue takes the issue lock, never the fence: it commits while a change holds the fence exclusive (IssueOffFence, R58)', postgresOnly('the fence is an advisory lock'), async () => {
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
