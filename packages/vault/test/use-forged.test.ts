// A use trusts the seal its input's newest change records only once that change's MAC holds. A
// database writer with no key puts an input's row back as the vault once sealed it, then writes the row's old seal into
// the newest change's `seal` column, or edits what else the use reads of that change (the cap in the policy's payload,
// the 0.14 entry the member's accounts for). The change's MAC, which
// covers every column but its number, then does not hold, and the use is refused `stale` whatever path it takes:
// by ids, probing or from the isolate's cache, as a batch, by name, as a named batch. The change path is held to the
// same check: a change to a row put back so would seal the writer's row under a new, authentic change (laundered).
// What no per-use check sees: an entry deleted or replayed whole (its MAC still holds), which the checkpoints catch
// (docs/design/merkle-checkpoints.md, (a) and (f)).
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import type { CredentialColumns, NamedManyInput, NamedManyOutcome, NamedUseInput, NamedUseOutcome, UseManyInput, UseOutcome } from '@coffre/core/vault';
import { appendEntries } from '@coffre/db/log';
import { sql } from 'drizzle-orm';

import { objectKey, sealOf, type Input, type Op, type Ref } from '../src/inputs.ts';
import { vaultLogKey } from '../src/log.ts';
import { newRequestId } from '../src/use.ts';
import { openTestDatabase, rows, run, withLogUnlocked, type TestDatabase } from './database.ts';
import { namedWorld } from './named-world.ts';
import { ask, change, emptyLog, isolate, ROOT, SEAL, seal, SIGNING_KEY, useDatabases, world } from './use-world.ts';
import { environments, secretReferences, secrets } from '@coffre/db/schema';

let db: TestDatabase;
before(async () => {
  db = await openTestDatabase();
  await useDatabases(db);
});
after(() => db.close());
beforeEach(emptyLog);

type World = Awaited<ReturnType<typeof world>>;

const code = (outcome: UseOutcome) => (outcome.ok ? 'ok' : 'code' in outcome ? outcome.code : `busy:${outcome.busy}`);

/** The newest change of `ref`'s object, by number. */
async function newestOf(ref: Ref): Promise<string> {
  const [row] = await rows<{ number: string | number }>(db.owner, sql`SELECT number FROM log_changes WHERE object = ${objectKey(ref)} ORDER BY number DESC LIMIT 1`);
  return String(row!.number);
}

/**
 * The attack: a change to `ref` that leaves `after`, logged as the vault logs one; its row left as it was before
 * (what a writer putting it back leaves, its old seal valid), and the change's `seal` column made that row's.
 */
async function forged(ref: Ref, before: Input, op: Op, after: Input): Promise<void> {
  await change(ref, op, after, async () => {});
  await run(db.owner, sql`UPDATE log_changes SET seal = ${sealOf(SEAL, ref, before)} WHERE number = ${await newestOf(ref)}`);
}

/** A use refused, never served: on a warm isolate (its cache read before the change) and a fresh one, twice each (nothing kept of the forged state). */
async function refusedEverywhere(w: { credentialId: string }, id: string, warm: (input: ReturnType<typeof ask>) => Promise<UseOutcome>, extra: Parameters<typeof ask>[2] = {}): Promise<void> {
  const fresh = (await isolate()).use;
  for (const [name, use] of [['warm', warm], ['fresh', fresh]] as const) {
    for (const round of [1, 2]) {
      const outcome: UseOutcome = await use(ask(w, id, { ...extra, purpose: round === 1 ? 'run' : 'reveal' }));
      assert.equal(code(outcome), 'stale', `${name} isolate, use ${round}: ${JSON.stringify(outcome)}`);
    }
  }
}

/** A world and a key in it, used once by a warm isolate (whose cache then holds every seal), all as the log says. */
async function used(options: Parameters<typeof world>[0] = {}) {
  const w = await world(options);
  const id = await w.key();
  const { use } = await isolate();
  assert.equal(code(await use(ask(w, id))), 'ok');
  return { w, id, use };
}

const principalOf = (w: World) => w.objects.principal as Extract<Input, { kind: 'principal' }>;

// --- each input the use reads, its newest change's seal forged ------------------------------------------------

test('the credential: revoked, its row put back, the revoke\'s seal column made the old one: refused', async () => {
  const { w, id, use } = await used();
  const ref: Ref = { kind: 'credential', id: w.credentialId };
  await forged(ref, w.objects.credential, { op: 'credential.revoke' }, { ...(w.objects.credential as Extract<Input, { kind: 'credential' }>), revoked: true });
  await refusedEverywhere(w, id, use);
});

test("the app's own change to that credential, a renewal by a minute: `prepare` refuses it tampered, so nothing the app commits seals the put-back row live (review r1)", async () => {
  const { w, id, use } = await used();
  const ref: Ref = { kind: 'credential', id: w.credentialId };
  const credential = w.objects.credential as Extract<Input, { kind: 'credential' }>;
  await forged(ref, credential, { op: 'credential.revoke' }, { ...credential, revoked: true });
  // The credential as the app reads its row (`CredentialColumns`), which the writer left as before the revoke.
  const [row] = await rows<{ kind: string; scope: string | null }>(db.owner, sql`SELECT kind, scope FROM credentials WHERE id = ${w.credentialId}`);
  const columns: CredentialColumns = { id: w.credentialId, principal: credential.principal, kind: row!.kind, scope: row!.scope, revoked: false, expiresAt: credential.expiresAt!, generation: credential.generation };
  const { vault } = await isolate();
  const outcome = await vault.prepare!({
    actor: ROOT,
    changes: [{ kind: 'credential', entry: null, id: w.credentialId, before: { columns, seal: sealOf(SEAL, ref, credential).toString('base64') }, after: { ...columns, expiresAt: credential.expiresAt! + 60_000 } }],
  });
  assert.equal(!outcome.ok && outcome.refusal.code, 'tampered', JSON.stringify(outcome));
  await refusedEverywhere(w, id, use);
});

test("a renewal of a credential whose row was put back over an authentic revoke: `prepare` answers it moved, so a seal forged after its read finds no write to launder it (review Fable)", async () => {
  const { w } = await used();
  const ref: Ref = { kind: 'credential', id: w.credentialId };
  const credential = w.objects.credential as Extract<Input, { kind: 'credential' }>;
  // The revoke, logged as the vault logs it, its MAC and seal true; the row left as before it (put back, its old seal valid).
  await change(ref, { op: 'credential.revoke' }, { ...credential, revoked: true }, async () => {});
  const [row] = await rows<{ kind: string; scope: string | null }>(db.owner, sql`SELECT kind, scope FROM credentials WHERE id = ${w.credentialId}`);
  const columns: CredentialColumns = { id: w.credentialId, principal: credential.principal, kind: row!.kind, scope: row!.scope, revoked: false, expiresAt: credential.expiresAt!, generation: credential.generation };
  const { vault } = await isolate();
  // The file's cases share the audit log: those before this one's reports stay.
  const reports = async () => (await rows<{ code: string }>(db.owner, sql`SELECT code FROM audit_log WHERE action = 'vault.tampered'`)).length;
  const before = await reports();
  const outcome = await vault.prepare!({
    actor: ROOT,
    changes: [{ kind: 'credential', entry: null, id: w.credentialId, before: { columns, seal: sealOf(SEAL, ref, credential).toString('base64') }, after: { ...columns, expiresAt: credential.expiresAt! + 60_000 } }],
  });
  // Without it, `prepare` sealed the renewal from the put-back row, and the writer, making the revoke's seal column
  // the old one before the app's `app_change`, had it commit: the revoked credential live a minute more, under an
  // authentic entry. Moved, as an honest write that came between would make it, and so reported nowhere.
  assert.equal(!outcome.ok && outcome.refusal.code, 'moved', JSON.stringify(outcome));
  assert.equal(await reports(), before, 'nothing reported');
});

test("the same renewal behind an entry that changes nothing of the credential as its revoke left it: `prepare` holds the calls, not the entries, to the newest change, and answers it moved (review r3)", async () => {
  const { w } = await used();
  const ref: Ref = { kind: 'credential', id: w.credentialId };
  const credential = w.objects.credential as Extract<Input, { kind: 'credential' }>;
  const revoked = { ...credential, revoked: true };
  await change(ref, { op: 'credential.revoke' }, revoked, async () => {});
  const [row] = await rows<{ kind: string; scope: string | null }>(db.owner, sql`SELECT kind, scope FROM credentials WHERE id = ${w.credentialId}`);
  const columns: CredentialColumns = { id: w.credentialId, principal: credential.principal, kind: row!.kind, scope: row!.scope, revoked: false, expiresAt: credential.expiresAt!, generation: credential.generation };
  const { vault } = await isolate();
  const outcome = await vault.prepare!({
    actor: ROOT,
    changes: [
      // The credential as its revoke left it, its seal the newest change's: no call.
      { kind: 'credential', entry: null, id: w.credentialId, before: { columns: { ...columns, revoked: true }, seal: sealOf(SEAL, ref, revoked).toString('base64') }, after: { ...columns, revoked: true } },
      // Then the renewal, from the row put back: the one call, from a seal that is not the newest change's.
      { kind: 'credential', entry: null, id: w.credentialId, before: { columns, seal: sealOf(SEAL, ref, credential).toString('base64') }, after: { ...columns, expiresAt: credential.expiresAt! + 60_000 } },
    ],
  });
  // Held by its first entry alone, the renewal was prepared from the put-back seal, for a forged seal column to let through.
  assert.equal(!outcome.ok && outcome.refusal.code, 'moved', JSON.stringify(outcome));
});

test("the member: their grant revoked, row and grant put back, the revoke's seal column made the old one: refused (Fable's repro)", async () => {
  const { w, id, use } = await used();
  const ref: Ref = { kind: 'principal', id: w.principal };
  await forged(ref, w.objects.principal, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } }, { ...principalOf(w), grants: [] });
  await refusedEverywhere(w, id, use);
});

test('the roles: edited, the row put back, the edit\'s seal column made the old one: refused', async () => {
  const { w, id, use } = await used();
  const ref: Ref = { kind: 'roles', id: 'instance' };
  const before: Input = { kind: 'roles', roles: {}, instanceRoles: {} };
  const definition = { name: 'Reader', description: 'reads', permissions: ['secret.read' as const], protected: [] };
  await forged(ref, before, { op: 'role.define', table: 'roles', role: 'reader', definition }, { kind: 'roles', roles: { reader: definition }, instanceRoles: {} });
  await refusedEverywhere(w, id, use);
});

test('the policy: its cap changed, the row put back, the change\'s seal column made the old one: refused', async () => {
  const { w, id, use } = await used();
  const ref: Ref = { kind: 'policy', id: 'instance' };
  const before: Input = { kind: 'policy', bulk: { count: 1000, windowMs: 15 * 60_000 } };
  const after: Input = { kind: 'policy', bulk: { count: 999, windowMs: 15 * 60_000 } };
  await forged(ref, before, { op: 'bulk.limit', value: after }, after);
  await refusedEverywhere(w, id, use);
});

test("the policy's cap: its newest change's payload raised by a writer: never let past the cap (the decision weighs the sealed row's count; the MAC now refuses it first)", async () => {
  const w = await world({ count: 1 });
  const first = await w.key();
  const second = await w.key();
  const { use } = await isolate();
  assert.equal(code(await use(ask(w, first))), 'ok');
  assert.equal(code(await use(ask(w, second))), 'bulk_limit', 'one key a window');
  const ref: Ref = { kind: 'policy', id: 'instance' };
  await run(db.owner, sql`UPDATE log_changes SET payload = replace(payload, '"count":1,', '"count":1000,') WHERE number = ${await newestOf(ref)}`);
  assert.match((await rows<{ payload: string }>(db.owner, sql`SELECT payload FROM log_changes WHERE number = ${await newestOf(ref)}`))[0]!.payload, /"count":1000,/);
  for (const isolated of [use, (await isolate()).use]) assert.notEqual(code(await isolated(ask(w, second))), 'ok');
});

test('the key: its value moved, its row put back, the write\'s seal column made the old one: refused', async () => {
  const { w, id, use } = await used();
  const ref: Ref = { kind: 'secret', id };
  const key = w.keys[0]!.object as Extract<Input, { kind: 'secret' }>;
  const after = { ...key, version: randomUUID() };
  await forged(ref, key, { op: 'secret.write', projectId: key.projectId, environmentId: key.environmentId, version: after.version, nature: 'secret', key: key.key, digest: null, source: null, reference: null }, after);
  await refusedEverywhere(w, id, use);
});

test("the key's environment: deleted, its row put back, the deletion's seal column made the old one: refused", async () => {
  const { w, id, use } = await used();
  const ref: Ref = { kind: 'environment', id: w.dev };
  await forged(ref, w.objects.environment, { op: 'environment.delete' }, { ...(w.objects.environment as Extract<Input, { kind: 'environment' }>), deleted: true });
  await refusedEverywhere(w, id, use);
});

test('the place it is read through (a fork): deleted, its row put back, the deletion\'s seal column made the old one: refused', async () => {
  const w = await world();
  const id = await w.key();
  const fork = await environment(w, 'fork', { parentId: w.dev });
  const { use } = await isolate();
  assert.equal(code(await use(ask(w, id, { place: fork.id }))), 'ok');
  await forged({ kind: 'environment', id: fork.id }, fork.object, { op: 'environment.delete' }, { ...fork.object, deleted: true });
  await refusedEverywhere(w, id, use, { place: fork.id });
});

test("a reference's source, and the source's environment: each changed, put back, its change's seal column made the old one: refused", async () => {
  for (const input of ['source', 'its environment'] as const) {
    await emptyLog();
    const w = await world();
    const source = await w.key('the source');
    const prod = await environment(w, 'prod');
    await grantAt(w, prod.id);
    const holder = await reference(w, prod.id, source);
    const { use } = await isolate();
    assert.equal(code(await use(ask(w, holder))), 'ok');
    if (input === 'source') {
      const key = w.keys[0]!.object as Extract<Input, { kind: 'secret' }>;
      const after = { ...key, version: randomUUID() };
      await forged({ kind: 'secret', id: source }, key, { op: 'secret.write', projectId: key.projectId, environmentId: key.environmentId, version: after.version, nature: 'secret', key: key.key, digest: null, source: null, reference: null }, after);
    } else {
      await forged({ kind: 'environment', id: w.dev }, w.objects.environment, { op: 'environment.delete' }, { ...(w.objects.environment as Extract<Input, { kind: 'environment' }>), deleted: true });
    }
    await refusedEverywhere(w, holder, use);
  }
});

test("a personal config's parent: deleted, its row put back, the deletion's seal column made the old one: refused", async () => {
  const w = await world({ caller: 'person' });
  const mine = await environment(w, 'dev-mine', { owner: w.principal, parentId: w.dev });
  const id = await w.key('mine', false, mine.id, w.principal);
  const { use } = await isolate();
  assert.equal(code(await use(ask(w, id))), 'ok');
  await forged({ kind: 'environment', id: w.dev }, w.objects.environment, { op: 'environment.delete' }, { ...(w.objects.environment as Extract<Input, { kind: 'environment' }>), deleted: true });
  await refusedEverywhere(w, id, use);
});

test("the member's newest change's payload, the 0.14 entry it accounts for raised by a writer past a late 0.14 write (UsesSeeOldWrites): refused", async () => {
  const { w, id, use } = await used();
  // A late 0.14 grant past the cutover, which no change of the new log accounts for: stale, as the log says.
  await withLogUnlocked(db.owner, (tx) => appendEntries(tx as never, vaultLogKey(SIGNING_KEY), [{ actor: ROOT, action: 'access.grant', decision: 'allow', subjectPrincipal: w.principal, metadata: '{}' }]));
  assert.equal(code(await use(ask(w, id))), 'stale');
  // The writer has the member's newest change account for it, by its payload alone.
  const ref: Ref = { kind: 'principal', id: w.principal };
  await run(db.owner, sql`UPDATE log_changes SET payload = ${JSON.stringify({ op: 'genesis', value: w.objects.principal, old: '9223372036854775807' })} WHERE number = ${await newestOf(ref)}`);
  await refusedEverywhere(w, id, use);
});

// --- every way a use is asked ----------------------------------------------------------------------------------

test('a batch by ids, a named use and a named batch: the member forged as in Fable\'s repro, each refused, no value back', async () => {
  const w = await namedWorld(db);
  const id = await w.key('one');
  const other = await w.key('two');
  const names = [await w.nameOf(id), await w.nameOf(other)];
  const { vault } = await isolate();
  const many = (): UseManyInput => {
    const { secretId: _, place: __, requestId: ___, ...one } = ask(w, id);
    return { ...one, items: [id, other].map((secretId) => ({ secretId, place: null, requestId: newRequestId() })) };
  };
  const named = (key: string): NamedUseInput => w.ask(key);
  const namedMany = (): NamedManyInput => {
    const { key: _, requestId: __, forks: ___, ...one } = w.ask('UNUSED');
    return { ...one, keys: names };
  };
  const manyCode = (outcome: Awaited<ReturnType<NonNullable<typeof vault.useMany>>>) => (outcome.ok ? 'ok' : 'code' in outcome ? outcome.code : `busy:${outcome.busy}`);
  const namedCode = (outcome: NamedUseOutcome) => (outcome.served ? code(outcome.outcome as UseOutcome) : 'unserved');
  const namedManyCode = (outcome: NamedManyOutcome) => {
    if (!outcome.served) return 'unserved';
    if (outcome.route !== 'name') return code(outcome.outcome as UseOutcome);
    return outcome.outcome.ok ? 'ok' : 'code' in outcome.outcome ? outcome.outcome.code : `busy:${outcome.outcome.busy}`;
  };
  assert.equal(manyCode(await vault.useMany!(many())), 'ok');
  assert.equal(namedCode(await vault.useNamed!(named(names[0]!))), 'ok');
  assert.equal(namedManyCode(await vault.useNamedMany!(namedMany())), 'ok');
  await forged({ kind: 'principal', id: w.principal }, w.objects.principal, { op: 'access.revoke', place: { projectId: w.project, environmentId: w.dev, environmentSlug: null } }, { ...principalOf(w), grants: [] });
  for (const { vault: v } of [{ vault }, await isolate()]) {
    assert.equal(manyCode(await v.useMany!(many())), 'stale');
    assert.equal(namedCode(await v.useNamed!(named(names[0]!))), 'stale');
    assert.equal(namedManyCode(await v.useNamedMany!(namedMany())), 'stale');
  }
});

// --- helpers ---------------------------------------------------------------------------------------------------

/** An environment of the world's project, made by its genesis change. */
async function environment(w: { project: string }, slug: string, extra: { owner?: string; parentId?: string } = {}) {
  const id = randomUUID();
  await db.owner.insert(environments).values({ id, projectId: w.project, slug, name: slug, protected: false, owner: extra.owner ?? null, parentId: extra.parentId ?? null });
  const object = { kind: 'environment', id, projectId: w.project, slug, owner: extra.owner ?? null, parentId: extra.parentId ?? null, protected: false, deleted: false, archived: false, projectArchived: false } as const;
  await change({ kind: 'environment', id }, { op: 'genesis', value: object }, object, seal('environments', 'id', id));
  return { id, object: object as Extract<Input, { kind: 'environment' }> };
}

/** The world's principal granted Viewer at `environmentId` too, by a change. */
async function grantAt(w: World, environmentId: string): Promise<void> {
  const added = { projectId: w.project, environmentId, environmentSlug: null, role: 'viewer', expiresAt: null };
  const after = { ...principalOf(w), grants: [...principalOf(w).grants, added] };
  await change({ kind: 'principal', id: w.principal }, { op: 'access.grant', grant: added }, after, async (tx, value) => {
    await run(tx, sql`INSERT INTO grants (principal, environment_id, role, granted_at, granted_by) VALUES (${w.principal}, ${environmentId}, 'viewer', ${Date.now()}, ${ROOT})`);
    await seal('principals', 'principal', w.principal)(tx, value);
  });
  w.objects.principal = after;
}

/** A key in `environmentId` that references `source`, sealed as 0.15's vault makes one. */
async function reference(w: World, environmentId: string, source: string): Promise<string> {
  const holder = randomUUID();
  const row = randomUUID();
  const appended = await db.vault.transaction((tx) => appendEntries(tx, vaultLogKey(SIGNING_KEY), [{ actor: ROOT, action: 'reference.create', decision: 'allow', metadata: '{}' }], undefined, undefined, [], true));
  await db.owner.insert(secrets).values({ id: holder, projectId: w.project, environmentId, key: `HELD_${holder.slice(0, 4)}` });
  await db.owner.insert(secretReferences).values({
    id: row, projectId: w.project, environmentId, secretId: holder, sourceProjectId: w.project, sourceEnvironmentId: w.dev, sourceSecretId: source,
    createdSeq: appended.seqStart, createdBy: ROOT,
  });
  const object: Input = { kind: 'secret', id: holder, projectId: w.project, environmentId, version: '', nature: 'secret', key: null, digest: null, source, reference: row };
  await change({ kind: 'secret', id: holder }, { op: 'genesis', value: object }, object, seal('secrets', 'id', holder));
  return holder;
}
