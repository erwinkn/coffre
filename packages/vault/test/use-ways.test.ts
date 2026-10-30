// 0.15's uses through a way in with no credentials row (T147; formal/WaysIn.tla), on both engines: an MCP connection,
// a Cloudflare service binding, and a browser behind Cloudflare Access. Each is one `use_credential` call, its entry
// naming its way in (the purpose's bits above 512), decided on that way in's sealed object, read as the credential it
// stands for, or behind Access on the account alone. Every live answer is held to the replay of the log (R53).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import type { UseOutcome } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { sql } from 'drizzle-orm';

import { objectKey, type Input, type Op, type Ref } from '../src/inputs.ts';
import { purposeOf, replay, type Logged } from '../src/log-replay.ts';
import { openTestDatabase, rows, run, type TestDatabase } from './database.ts';
import { ask, change, DAY, emptyLog, genesis, isolate, ROOT, SEAL, seal, useDatabases, world } from './use-world.ts';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

/** Every live answer, by entry number: what the replay must say. */
const answered = new Map<string, UseOutcome>();
beforeEach(() => answered.clear());
function heard(outcome: UseOutcome): UseOutcome {
  if (!('busy' in outcome) && outcome.number !== null && !(outcome.ok && outcome.covered)) answered.set(outcome.number, outcome);
  return outcome;
}

/** The log replayed, each use's decision held to its live answer: as use.test.ts's, its way in read from its purpose. */
async function replayAgrees(): Promise<number> {
  const changes = await rows<{ number: string | number; at: string | number; object: string; payload: string; seal: Buffer | null }>(db.owner,
    sql`SELECT number, at, object, payload, seal FROM log_changes ORDER BY number`);
  const uses = await rows<{ number: string | number; at: string | number; credential: string; secret: string; purpose: number; place: string | null }>(db.owner,
    sql`SELECT number, at, credential, secret, purpose, place FROM log_uses ORDER BY number`);
  const refs = new Map<string, Ref>();
  const entries: Logged[] = [
    ...changes.map((row) => {
      const op = JSON.parse(row.payload) as Op & { old?: string };
      const { old: _, ...rest } = op;
      return { kind: 'change' as const, number: BigInt(row.number), at: Number(row.at), ref: refOf(op, row.object, refs), op: rest as Op, seal: row.seal === null ? null : Buffer.from(row.seal) };
    }),
    ...uses.map((row) => ({ kind: 'use' as const, number: BigInt(row.number), request: { credential: row.credential, secretId: row.secret, place: row.place, at: Number(row.at), ...purposeOf(Number(row.purpose))! } })),
  ].sort((a, b) => (a.number < b.number ? -1 : 1));
  let checked = 0;
  const result = replay([SEAL], entries, (entry, code) => {
    const live = answered.get(entry.number.toString());
    if (live === undefined) return;
    if (!live.ok && 'code' in live && (live.code === 'stale' || live.code === 'tampered')) return;
    assert.equal(live.ok ? null : (live as { code: string }).code, code, `entry ${entry.number}: live and replay disagree`);
    checked += 1;
  });
  assert.deepEqual(result.faults, []);
  return checked;
}

function refOf(op: Op, key: string, seen: Map<string, Ref>): Ref {
  if (op.op === 'genesis') {
    const value = op.value;
    const ref: Ref = value.kind === 'principal' ? { kind: 'principal', id: value.principal } : value.kind === 'roles' || value.kind === 'policy' ? { kind: value.kind, id: 'instance' } : { kind: value.kind, id: value.id };
    seen.set(key, ref);
  }
  return seen.get(key)!;
}

const code = (outcome: UseOutcome) => (outcome.ok ? null : 'busy' in outcome ? outcome.busy : outcome.code);

/** The way the entry `number` names: its credential column and the way its purpose carries. */
async function entryOf(number: string): Promise<{ credential: string; way: string }> {
  const [row] = await rows<{ credential: string; purpose: number }>(db.owner, sql`SELECT credential, purpose FROM log_uses WHERE number = ${BigInt(number)}`);
  return { credential: row!.credential, way: purposeOf(Number(row!.purpose))!.way ?? 'credential' };
}

/** An MCP connection of a person's world, sealed by its genesis, as the cutover or its make leaves it. */
async function connection(w: { principal: string }, generation = 0) {
  const id = randomUUID();
  const expiresAt = Date.now() + DAY;
  await db.owner.insert(tablesOf(db.owner).mcpConnections).values({
    id, authMac: Buffer.alloc(32), principal: w.principal, generation, clientId: 'https://client.example/meta', clientName: 'Client', registration: 'cimd',
    scopes: 'read reveal', redirectUri: 'https://client.example/back', expiresAt: new Date(expiresAt),
  });
  const object: Input = { kind: 'connection', id, principal: w.principal, generation, expiresAt, revoked: false };
  await genesis({ kind: 'connection', id }, object);
  return { id, object };
}

/** A Cloudflare binding of a service's world, reaching `dev` as a Viewer, sealed as the vault makes one. */
async function binding(w: { principal: string; project: string; dev: string }, options: { profile?: string; reads?: boolean } = {}) {
  const id = randomUUID();
  const scope = [{ projectId: w.project, environmentId: w.dev, role: 'viewer' }];
  const policy = JSON.stringify(options.reads === true ? { reads: { [w.dev]: { keys: [] } } } : {});
  const profile = options.profile ?? 'cloudflare';
  await db.owner.insert(tablesOf(db.owner).serviceBindings).values({
    id, authMac: Buffer.alloc(32), principal: w.principal, generation: 0, profile, issuer: 'urn:coffre:cloudflare', jwksUri: 'urn:coffre:cloudflare',
    claims: '{}', scope: JSON.stringify(scope), policy, origin: 'https://coffre.test', createdBy: ROOT,
  });
  const object: Input = {
    kind: 'binding', id, principal: w.principal, generation: 0, profile, issuer: 'urn:coffre:cloudflare', origin: 'https://coffre.test', jwksUri: 'urn:coffre:cloudflare',
    claims: '{}', scope, policy, revoked: false,
  };
  await genesis({ kind: 'binding', id }, object);
  return { id, object };
}

/** The account removed, its generation moved on, then admitted again at it, each a change, as the vault's are. */
async function removeAndRestore(w: { principal: string; objects: { principal: Input } }, restore = true) {
  const member = w.objects.principal as Extract<Input, { kind: 'principal' }>;
  const removed: Input = { ...member, status: 'removed', generation: member.generation + 1 };
  await change({ kind: 'principal', id: w.principal }, { op: 'member.remove' }, removed, async (tx, value) => {
    await run(tx, sql`UPDATE vault_members SET status = 'removed', generation = ${member.generation + 1}, seal = ${value} WHERE principal = ${w.principal}`);
  });
  if (!restore) return;
  const back: Input = { ...removed, status: 'active' };
  await change({ kind: 'principal', id: w.principal }, { op: 'member.restore', role: member.role, scope: member.scope }, back, async (tx, value) => {
    await run(tx, sql`UPDATE vault_members SET status = 'active', seal = ${value} WHERE principal = ${w.principal}`);
  });
}

// --- an MCP connection ------------------------------------------------------------------------------

test('through an MCP connection: one entry naming the connection, its value opened; disconnected, refused as an ended credential', async () => {
  const w = await world({ caller: 'person' });
  const id = await w.key('postgres://prod');
  const k = await connection(w);
  const via = (extra = {}) => ({ ...ask(w, id, { purpose: 'reveal' }), credential: k.id, way: 'connection' as const, ...extra });
  const first = heard(await (await isolate()).use(via()));
  assert.ok(first.ok, JSON.stringify(first));
  assert.deepEqual(await entryOf(first.number), { credential: k.id, way: 'connection' });
  // Its person disconnects it: a change under the fence, which every later use reads.
  await change({ kind: 'connection', id: k.id }, { op: 'connection.revoke' }, { ...k.object, revoked: true } as Input, async (tx, value) => {
    await run(tx, sql`UPDATE mcp_connections SET revoked_at = ${new Date()}, seal = ${value} WHERE id = ${k.id}`);
  });
  assert.equal(code(heard(await (await isolate()).use(via()))), 'credential');
  assert.equal(await replayAgrees(), 2);
});

test('a connection of an earlier generation of its account (removed, admitted again, not yet swept) reaches nothing (UseChecksGeneration)', async () => {
  const w = await world({ caller: 'person' });
  const id = await w.key();
  const k = await connection(w);
  // Allowed first, its key entering the cap's set: the refusal after is logged (a first use refused logs nothing: D153).
  assert.ok((heard(await (await isolate()).use({ ...ask(w, id), credential: k.id, way: 'connection' }))).ok);
  await removeAndRestore(w);
  assert.equal(code(heard(await (await isolate()).use({ ...ask(w, id), credential: k.id, way: 'connection' }))), 'credential');
  assert.equal(await replayAgrees(), 2);
});

test("a connection's revoked row put back is no object of the log's: stale (SealChecked)", async () => {
  const w = await world({ caller: 'person' });
  const id = await w.key();
  const k = await connection(w);
  const [held] = await rows<{ seal: Buffer }>(db.owner, sql`SELECT seal FROM mcp_connections WHERE id = ${k.id}`);
  await change({ kind: 'connection', id: k.id }, { op: 'connection.revoke' }, { ...k.object, revoked: true } as Input, async (tx, value) => {
    await run(tx, sql`UPDATE mcp_connections SET revoked_at = ${new Date()}, seal = ${value} WHERE id = ${k.id}`);
  });
  await run(db.owner, sql`UPDATE mcp_connections SET revoked_at = NULL, seal = ${held!.seal} WHERE id = ${k.id}`);
  assert.equal(code(heard(await (await isolate()).use({ ...ask(w, id), credential: k.id, way: 'connection' }))), 'stale');
  // Edited, its seal kept: tampered.
  await run(db.owner, sql`UPDATE mcp_connections SET generation = 7 WHERE id = ${k.id}`);
  assert.equal(code(heard(await (await isolate()).use({ ...ask(w, id), credential: k.id, way: 'connection' }))), 'tampered');
  await replayAgrees();
});

test("a credential's id named as a connection's is none: the way in is the entry's, and its object of that kind", async () => {
  const w = await world({ caller: 'person' });
  const id = await w.key();
  assert.equal(code(heard(await (await isolate()).use({ ...ask(w, id), credential: w.credentialId, way: 'connection' }))), 'credential');
  assert.equal(await replayAgrees(), 1);
});

// --- a Cloudflare binding ---------------------------------------------------------------------------

test("through a Cloudflare binding: its service's workload credential, of the binding's scope; unbound, refused", async () => {
  const w = await world();
  const id = await w.key('sk_live');
  const b = await binding(w);
  const via = () => ({ ...ask(w, id, { purpose: 'use' }), credential: b.id, way: 'binding' as const });
  const first = heard(await (await isolate()).use(via()));
  assert.ok(first.ok, JSON.stringify(first));
  assert.deepEqual(await entryOf(first.number), { credential: b.id, way: 'binding' });
  await change({ kind: 'binding', id: b.id }, { op: 'binding.revoke' }, { ...b.object, revoked: true } as Input, async (tx, value) => {
    await run(tx, sql`UPDATE service_bindings SET revoked_at = ${new Date()}, seal = ${value} WHERE id = ${b.id}`);
  });
  assert.equal(code(heard(await (await isolate()).use(via()))), 'credential');
  assert.equal(await replayAgrees(), 2);
});

test("a binding's reads list what its workload is handed back: a key unlisted is used, never read (use_only)", async () => {
  const w = await world();
  const id = await w.key();
  const b = await binding(w, { reads: true });
  const via = (purpose: 'use' | 'run') => ({ ...ask(w, id, { purpose }), credential: b.id, way: 'binding' as const });
  assert.ok((heard(await (await isolate()).use(via('use')))).ok);
  assert.equal(code(heard(await (await isolate()).use(via('run')))), 'use_only');
  assert.equal(await replayAgrees(), 2);
});

test('a binding no Cloudflare call comes through (a CI provider\'s) reaches nothing; nor one of an earlier generation', async () => {
  const w = await world();
  const id = await w.key();
  const github = await binding(w, { profile: 'github' });
  const b = await binding(w);
  const via = (binding: string) => ({ ...ask(w, id, { purpose: 'use' }), credential: binding, way: 'binding' as const });
  // Allowed first, its key entering the cap's set: the refusals after are logged (a first use refused logs nothing: D153).
  assert.ok((heard(await (await isolate()).use(via(b.id)))).ok);
  assert.equal(code(heard(await (await isolate()).use(via(github.id)))), 'credential');
  await removeAndRestore(w);
  assert.equal(code(heard(await (await isolate()).use(via(b.id)))), 'credential');
  assert.equal(await replayAgrees(), 3);
});

// --- Cloudflare Access ------------------------------------------------------------------------------

test('behind Cloudflare Access: the person alone, the entry naming their object\'s key; removed, refused; admitted again, served', async () => {
  const w = await world({ caller: 'person' });
  const id = await w.key();
  const via = () => ({ ...ask(w, id, { purpose: 'reveal' }), credential: w.principal, way: 'access' as const });
  const first = heard(await (await isolate()).use(via()));
  assert.ok(first.ok, JSON.stringify(first));
  assert.deepEqual(await entryOf(first.number), { credential: objectKey({ kind: 'principal', id: w.principal }), way: 'access' });
  await removeAndRestore(w, false);
  assert.equal(code(heard(await (await isolate()).use(via()))), 'removed');
  // Admitted again: nothing of theirs ended but the account, which stands again.
  const member = w.objects.principal as Extract<Input, { kind: 'principal' }>;
  await change({ kind: 'principal', id: w.principal }, { op: 'member.restore', role: member.role, scope: member.scope }, { ...member, generation: 1 } as Input, async (tx, value) => {
    await run(tx, sql`UPDATE vault_members SET status = 'active', seal = ${value} WHERE principal = ${w.principal}`);
  });
  assert.ok((heard(await (await isolate()).use(via()))).ok);
  assert.equal(await replayAgrees(), 3);
});

test('behind Access a service token is its account alone, a bearer of no scope; a use names its account, never a uuid', async () => {
  const w = await world();
  const id = await w.key();
  const via = () => ({ ...ask(w, id, { purpose: 'run' }), credential: w.principal, way: 'access' as const });
  assert.ok((heard(await (await isolate()).use(via()))).ok);
  await assert.rejects((await isolate()).use({ ...ask(w, id), credential: randomUUID(), way: 'access' }), /behind Access, its account/);
  assert.equal(await replayAgrees(), 1);
});

test('a repeat through each way rides its cover, keyed on its way in', async () => {
  const w = await world({ caller: 'person' });
  const id = await w.key();
  const k = await connection(w);
  const { use } = await isolate();
  for (const via of [{ credential: k.id, way: 'connection' as const }, { credential: w.principal, way: 'access' as const }]) {
    const first = heard(await use({ ...ask(w, id), ...via }));
    const again = await use({ ...ask(w, id), ...via });
    assert.ok(first.ok && again.ok && again.covered && again.number === first.number, JSON.stringify(again));
  }
  assert.equal((await rows(db.owner, sql`SELECT 1 FROM log_uses`)).length, 2);
  assert.equal(await replayAgrees(), 2);
});
