import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createClient, type CoffreClient } from '@coffre/client';
import { entryHash, sealEntry } from '@coffre/core/audit';
import { github, signin, type Principal } from '@coffre/core/identity';
import { tablesOf } from '@coffre/db';
import { and, asc, eq, is, Table } from 'drizzle-orm';

import { auditRange } from '../src/db/queries.ts';
import { auditChainHead, auditLog } from './db/tables.ts';
import { serveApi } from '../src/api/router.ts';
import { SyncRunner } from '../src/api/syncs.ts';
import { fetchApi } from '../src/fetch-api.ts';
import { writeAuditHeartbeat } from '../src/heartbeat.ts';
import type { CoffreRuntime } from '../src/runtime.ts';
import {
  clientFor,
  contextFor,
  openTestDatabase,
  resetDatabase,
  testDeps,
  testVault,
  type FixtureDeps,
} from './api-fixture.ts';
import { appLogKey } from '../src/db/audit.ts';
import { withLogUnlocked } from './db/engine.ts';

/**
 * The vault as the last line: each test here gets past the app somehow (a
 * permission bug, a live session, a rewritten database) and checks that
 * the vault still says no, and says so in its own log.
 */

const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const quiet = { warn: () => assert.fail('the checkpoint must not warn') };

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let developer: CoffreClient;

before(async () => {
  db = await openTestDatabase();
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  developer = clientFor(deps, DEV);
});

after(async () => {
  await resetDatabase(db.owner);
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  await root.members.add(`user:${DEV}`);
  await root.projects.create('market', { name: 'Market' });
  await root.environments.create('market/dev', { name: 'Development' });
  await root.environments.create('market/prod', { name: 'Production' });
  await root.secrets.set('market/dev', { API_KEY: 'sk_test', DB_URL: 'postgres://dev' });
  await root.secrets.set('market/prod', { API_KEY: 'sk_live' });
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer' });
});

/**
 * The API with a permission bug: it believes `id` is a root admin, so every
 * check the app makes passes. Only the vault stands between them and a key.
 */
function buggyClientFor(on: FixtureDeps, id: string): CoffreClient {
  return createClient({
    url: 'https://coffre.test',
    transport: async (request) => {
      const ctx = await contextFor(on, id);
      ctx.caller = { ...ctx.caller, isRootAdmin: true, isOwner: true, instanceRole: 'root-admin' };
      return serveApi(request, ctx);
    },
  });
}

/** The vault's entries, newest first, as an owner reads them: in the one log, detail included. */
async function vaultEntries(client = root) {
  return (await client.audit.list({ detail: '1', limit: 200 })).entries.filter((entry) => entry.author === 'vault');
}

/** Why the app's own entries say `action` was denied, oldest first. */
async function appDenials(action: string): Promise<unknown[]> {
  const rows = await db.owner
    .select({ metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'app'), eq(auditLog.action, action), eq(auditLog.decision, 'deny')))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => JSON.parse(row.metadata).reason);
}

// --- keys ---------------------------------------------------------------------

test('an app permission bug does not reach prod: the vault refuses and logs the claim', async () => {
  const buggy = buggyClientFor(deps, DEV);
  assert.equal((await buggy.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'sk_test');
  await assert.rejects(buggy.secrets.reveal('market/prod/API_KEY'), {
    status: 403,
    code: 'vault_refused',
    reason: 'no_grant',
  });

  const [refused] = await vaultEntries();
  const { actorId, action, decision, reason, project, environment, key } = refused;
  assert.deepEqual(
    { actorId, action, decision, reason, project, environment, key },
    { actorId: DEV, action: 'secret.read', decision: 'deny', reason: 'no_grant', project: 'market', environment: 'prod', key: 'API_KEY' },
  );
  // The vault's entry is the record: the app keeps no copy of it.
  assert.deepEqual(await appDenials('secret.read'), []);
});

test('an expired grant refuses: in the app, and in the vault if the app were wrong', async () => {
  const until = new Date(Date.now() + 60_000).toISOString();
  await root.access.set(`user:${DEV}`, { 'market/prod': { role: 'viewer', until } });
  assert.equal((await developer.secrets.reveal('market/prod/API_KEY')).values.API_KEY, 'sk_live');

  deps.vault.advance(120_000);
  await assert.rejects(developer.secrets.reveal('market/prod/API_KEY'), { status: 403, code: 'forbidden' });
  await assert.rejects(buggyClientFor(deps, DEV).secrets.reveal('market/prod/API_KEY'), {
    status: 403,
    code: 'vault_refused',
    reason: 'expired',
  });
  assert.equal((await vaultEntries())[0].reason, 'expired');
});

test('the bulk limit counts one read per secret, trips with its own code, and is logged', async () => {
  const limited = testDeps(db.runtime, [ROOT], {
    vault: testVault([ROOT], { bulkLimit: { count: 3, windowMinutes: 1 } }, deps.vault),
  });
  const admin = clientFor(limited, ROOT);
  const dev = clientFor(limited, DEV);
  await admin.members.add(`user:${DEV}`);
  await admin.access.set(`user:${DEV}`, { 'market/dev': 'developer' });
  // Written again, so this vault's key wraps them.
  await admin.secrets.set('market/dev', { API_KEY: 'sk_test', DB_URL: 'postgres://dev' });

  // Two keys, then two more: four reads in the window, over three.
  assert.deepEqual(Object.keys((await dev.secrets.reveal('market/dev')).values).sort(), ['API_KEY', 'DB_URL']);
  await assert.rejects(dev.secrets.reveal('market/dev'), { status: 403, code: 'bulk_limit', reason: 'bulk_limit' });
  const [refused] = await vaultEntries(admin);
  assert.deepEqual([refused.action, refused.decision, refused.reason], ['secret.read', 'deny', 'bulk_limit']);

  // A rolling window: a minute later the same read goes through.
  limited.vault.advance(61_000);
  assert.equal((await dev.secrets.reveal('market/dev')).values.API_KEY, 'sk_test');
});

// --- members ------------------------------------------------------------------

test('a removed member stays out despite a live session, until the vault admits them again', async () => {
  const runtime: CoffreRuntime = {
    db: deps.db,
    vault: deps.vault,
    chainKey: deps.chainKey,
    syncs: new SyncRunner({ db: deps.db, vault: deps.vault, chainKey: deps.chainKey }),
    signin: null,
    auth: signin({ providers: [github({ clientId: 'id', clientSecret: 'secret' })] }).resolve('https://coffre.test'),
    publicUrl: 'https://coffre.test',
    // Every token is simply the email of whoever holds it, and never expires.
    verifier: { verify: async (token: string): Promise<Principal> => ({ type: 'user', id: token, email: token, subject: token }) },
    waitUntil: () => {},
  };
  const reveal = () =>
    fetchApi(
      new Request('https://coffre.test/api/reveals', {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: `__Host-coffre_session=${DEV}`, 'sec-fetch-site': 'same-origin' },
        body: JSON.stringify({ path: 'market/dev/API_KEY' }),
      }),
      runtime,
      { sourceIp: null },
    );
  assert.equal((await reveal()).status, 200);

  // What to rotate: what they read.
  const { report } = await root.members.remove(`user:${DEV}`);
  assert.deepEqual(report.exposed.map(({ environment, key, how }) => [environment, key, how]), [['dev', 'API_KEY', 'read']]);
  assert.equal((await reveal()).status, 403);
  const removal = (await vaultEntries()).find((entry) => entry.action === 'member.remove');
  assert.equal(removal?.subject, `user:${DEV}`);

  // Only the vault brings them back, and with nothing: access starts over.
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: `user:${DEV}` })).ok, true);
  assert.equal((await reveal()).status, 403);
  await root.access.set(`user:${DEV}`, { 'market/dev': 'viewer' });
  assert.equal((await reveal()).status, 200);
});

// --- logs -----------------------------------------------------------------------

test('the vault\'s entries are chained, and one rewritten fails', async () => {
  await developer.secrets.reveal('market/dev/API_KEY');
  assert.equal((await root.audit.verify()).ok, true);
  await assert.rejects(developer.audit.verify(), { status: 403 });

  // Someone who owns the database, and lifts the log's triggers.
  await withLogUnlocked(db.owner, (owner) =>
    owner
      .update(auditLog)
      .set({ actor: 'user:nobody@acme.example' })
      .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'secret.read'))),
  );
  const read = (await vaultEntries()).find((entry) => entry.action === 'secret.read')!;
  assert.deepEqual(await root.audit.verify(), {
    ok: false,
    through: read.seq - 1,
    failedAtSeq: read.seq,
    author: 'app',
    reason: 'hash does not match the entry',
  });
});

test('a read put on someone else and chained again fails: the vault wrote it, and only the vault can seal it', async () => {
  await developer.secrets.reveal('market/dev/API_KEY');
  assert.equal(await writeAuditHeartbeat(db.runtime, deps.chainKey, deps.vault, quiet), true);
  const verified = await root.audit.verify();
  assert.ok(verified.ok && verified.checkpoint !== null);

  // Someone holding the app, chain key and all, puts the read on someone
  // else and chains again: the app's entries sealed anew, the vault's
  // linked to the new hashes with the MACs they cannot remake.
  const rows = await auditRange(db.owner, 0n, 10_000);
  let previous = rows[0].prevHash;
  await withLogUnlocked(db.owner, async (owner) => {
    for (const row of rows) {
      const rewritten = { ...row, actor: row.action === 'secret.read' ? `user:${ROOT}` : row.actor };
      const { mac, hash } =
        row.author === 'app'
          ? sealEntry(appLogKey(deps.chainKey), previous, rewritten)
          : { mac: row.mac, hash: entryHash(previous, rewritten, row.mac) };
      await owner
        .update(auditLog)
        .set({ actor: rewritten.actor, prevHash: previous, mac, hash })
        .where(eq(auditLog.seq, row.seq));
      previous = hash;
    }
  });
  await db.owner.update(auditChainHead).set({ headHash: previous });

  const read = rows.find((row) => row.action === 'secret.read')!;
  assert.deepEqual(await root.audit.verify(), {
    ok: false,
    through: Number(read.seq) - 1,
    failedAtSeq: Number(read.seq),
    author: 'vault',
    reason: 'not written by the vault: its MAC does not match',
  });
  // And the vault will not sign past it.
  assert.equal(await writeAuditHeartbeat(db.runtime, deps.chainKey, deps.vault, { warn: () => {} }), false);
  const [refused] = await vaultEntries();
  assert.deepEqual([refused.action, refused.decision, refused.reason], ['audit.checkpoint', 'deny', 'log_broken']);
});

test('the audit verification checks the vault\'s rows too, and finds a grant written around it', async () => {
  await developer.secrets.reveal('market/dev/API_KEY');
  assert.equal(await writeAuditHeartbeat(db.runtime, deps.chainKey, deps.vault, quiet), true);
  const verified = await root.audit.verify();
  assert.ok(verified.ok);

  // Someone who owns the database gives the developer the whole project.
  const { projects, vaultGrants } = tablesOf(db.owner);
  const [{ id: projectId }] = await db.owner.select({ id: projects.id }).from(projects).where(eq(projects.slug, 'market'));
  await db.owner.insert(vaultGrants).values({
    principal: `user:${DEV}`, projectId, environmentId: null, role: 'owner', expiresAt: null, grantedAt: 0, grantedBy: `user:${ROOT}`,
  });
  // The developer's record no longer carries the vault's MAC, and the
  // verdict names them as the app knows them. The log itself holds.
  const reason = `the store's ${DEV}, or their grants, were changed outside the vault`;
  assert.deepEqual(await root.audit.verify(), { ok: false, through: verified.through, failedAtSeq: null, author: 'vault', reason });
});

test('a vault entry cut out of the log fails the audit verification', async () => {
  await developer.secrets.reveal('market/dev/API_KEY');
  assert.equal(await writeAuditHeartbeat(db.runtime, deps.chainKey, deps.vault, quiet), true);

  // The vault's entries have no log of their own to be cut back in:
  // taking the read out leaves a gap in the one chain.
  const [release] = await db.owner
    .select({ seq: auditLog.seq })
    .from(auditLog)
    .where(and(eq(auditLog.author, 'vault'), eq(auditLog.action, 'secret.read')));
  await withLogUnlocked(db.owner, (owner) => owner.delete(auditLog).where(eq(auditLog.seq, release.seq)));
  const failed = await root.audit.verify();
  assert.deepEqual(failed.ok ? null : [failed.author, failed.failedAtSeq, failed.reason], [
    'app',
    Number(release.seq) + 1,
    `sequence gap: expected seq ${release.seq}, found ${release.seq + 1n}`,
  ]);
});

// --- where keys live ----------------------------------------------------------

test('the database holds no key', async () => {
  await developer.secrets.reveal('market/dev');
  await writeAuditHeartbeat(db.runtime, deps.chainKey, deps.vault, quiet);

  // Every row of every table, the app's and the vault's.
  const values: Buffer[] = [];
  for (const table of Object.values(tablesOf(db.owner)).filter((value) => is(value, Table))) {
    for (const row of await db.owner.select().from(table as Table)) {
      for (const value of Object.values(row as Record<string, unknown>)) {
        values.push(value instanceof Uint8Array ? Buffer.from(value) : Buffer.from(String(value)));
      }
    }
  }
  const dump = Buffer.concat(values);
  assert.ok(dump.includes(Buffer.from(`user:${DEV}`)), 'the dump is real');

  for (const key of [deps.vault.kek, deps.vault.signingKey]) {
    for (const form of [key, ...(['base64', 'base64url', 'hex'] as const).map((encoding) => Buffer.from(key.toString(encoding)))]) {
      assert.equal(dump.includes(form), false, 'the database holds a key');
    }
  }
});
