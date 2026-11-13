// The audit projection (packages/vault/src/projection.ts) against today's audit page: every entry the page lists,
// of 0.14's log and 0.15's, the projection lists once, by its log and number, as the page shows it; and an Owner's
// rebuild, which the vault records in their name. No page reads the projection yet.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

import type { AuditEntryView, CoffreClient } from '@coffre/client';
import { rowsOf } from '@coffre/db/dialect';
import { bulkCap, logCheckpoints, logTiles, logUses } from '@coffre/db/schema';
import { derivedSigningKey } from '@coffre/vault';
import { runCheckpointer, type RunningCheckpointer } from '@coffre/vault/node';
import { sql } from 'drizzle-orm';

import { clientFor, listAudit, openTestDatabase, resetDatabase, testDeps, testVault, type FixtureDeps } from './api-fixture.ts';
import { openVaultDatabase } from './db/engine.ts';

const ROOT = 'admin@acme.example';
const ADA = 'user:ada@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
const scratch = mkdtempSync(join(tmpdir(), 'coffre-projection-'));
let signer: RunningCheckpointer | null = null;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await signer?.stop();
  await db.close();
  rmSync(scratch, { recursive: true, force: true });
});

beforeEach(async () => {
  await signer?.stop();
  await resetDatabase(db.owner);
  for (const table of [logUses, bulkCap, logCheckpoints, logTiles]) await db.owner.delete(table);
  const kek = randomBytes(32);
  signer = await runCheckpointer({ database: await openVaultDatabase(), signingKeys: [derivedSigningKey(kek)], memory: join(scratch, `memory-${Date.now()}`), intervalMs: 3_600_000 });
  const vault = testVault([ROOT], {}, { kek }, {}, { sealThrough: signer.sealThrough, heldOutside: signer.heldOutside });
  deps = testDeps(db.runtime, [ROOT], { vault, settleAudit: false });
  root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  for (const environment of ['dev', 'prod']) {
    await root.environments.create(`market/${environment}`, { name: environment });
    await root.secrets.set(`market/${environment}`, { API_KEY: `${environment}-key`, OTHER: `${environment}-other` });
  }
  await root.members.add(ADA, { role: 'developer', scope: { environments: { only: ['dev'] } } });
});

/** Every entry today's page lists, detail included, page after page. */
async function page(client: CoffreClient): Promise<AuditEntryView[]> {
  const all: AuditEntryView[] = [];
  for (let before: string | undefined; ;) {
    const { entries, next } = await client.audit.list({ detail: '1', limit: 500, ...(before === undefined ? {} : { before }) } as Parameters<CoffreClient['audit']['list']>[0]);
    all.push(...entries);
    if (next === null) return all;
    before = next;
  }
}

const member = (entry: AuditEntryView) => `${entry.actorType === 'service' ? 'token' : entry.actorType}:${entry.actorId}`;

test("every entry today's page lists, the projection lists once, by its log and number, with its action, decision, actor and member: nothing lost, nothing twice", async () => {
  const ada = clientFor(deps, 'ada@acme.example');
  assert.equal((await ada.secrets.reveal('market/dev/API_KEY')).values.API_KEY, 'dev-key');
  await root.secrets.set('market/dev', { API_KEY: 'dev-key-2' });
  await ada.secrets.reveal('market/dev');
  // A write the vault refuses, and one the app does.
  await assert.rejects(ada.secrets.set('market/prod', { API_KEY: 'mine' }));
  await assert.rejects(ada.members.add('user:eve@acme.example', { role: 'member' }));
  await listAudit(deps.vault, signer!);
  const [cursor] = await rowsOf<{ through: string; old_top: string }>(db.owner, sql`SELECT CAST(through AS text) AS through, CAST(old_top AS text) AS old_top FROM audit_cursor`);
  const listed = await rowsOf<{ k: string }>(db.owner, sql`SELECT log || ':' || number || ':' || action || ':' || allowed || ':' || actor || ':' || coalesce(subject, '-') AS k FROM audit_events`);
  // What the page lists as far as the projection has gone: 0.14's below its top, 0.15's through its cursor; a page's
  // own reads after them aside. Its heartbeats and checkpoints are not listed.
  const shown = (await page(root)).filter((entry) => !['audit.heartbeat', 'audit.checkpoint'].includes(entry.action)
    && (entry.log === '0.14' ? BigInt(entry.seq) < BigInt(cursor!.old_top) : BigInt(entry.seq) <= BigInt(cursor!.through)));
  const want = shown.map((entry) => {
    const log = entry.log === '0.14' ? 14 : entry.action === 'secret.read' && entry.author === 'vault' && entry.decision === 'allow' ? 16 : 15;
    return `${log}:${entry.seq}:${entry.action}:${entry.decision === 'allow'}:${member(entry)}:${entry.subject ?? '-'}`;
  });
  assert.ok(want.length > 10, want.join('\n'));
  assert.deepEqual(listed.map((row) => row.k).sort(), want.sort());
});

test('an Owner rebuilds the projection: the vault records it in their name, and lists every log again; no one else may', async () => {
  const ada = clientFor(deps, 'ada@acme.example');
  await ada.secrets.reveal('market/dev/API_KEY');
  await listAudit(deps.vault, signer!);
  const before = await rowsOf<{ k: string }>(db.owner, sql`SELECT log || ':' || number || ':' || encode(mac, 'hex') AS k FROM audit_events ORDER BY 1`);
  assert.ok(before.length > 0);
  const refused = await ada.audit.rebuild().then(() => null, (error: { status?: number }) => error);
  assert.equal(refused?.status, 403);
  const { number } = await root.audit.rebuild();
  assert.equal((await rowsOf<{ n: string }>(db.owner, sql`SELECT CAST(count(*) AS text) AS n FROM audit_events`))[0]!.n, '0');
  await listAudit(deps.vault, signer!);
  const record = await rowsOf<{ actor: string; action: string }>(db.owner, sql`SELECT actor, action FROM audit_events WHERE log = 15 AND number = ${BigInt(number)}`);
  assert.deepEqual(record, [{ actor: `user:${ROOT}`, action: 'audit.rebuild' }]);
  const again = await rowsOf<{ k: string }>(db.owner, sql`SELECT log || ':' || number || ':' || encode(mac, 'hex') AS k FROM audit_events ORDER BY 1`);
  for (const row of before) assert.ok(again.some((r) => r.k === row.k), row.k);
});
