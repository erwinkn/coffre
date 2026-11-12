// The vault decides on no environment row 0.15's log does not hold (T159; R53, every decision input sealed; R64, fail
// closed): a place re-parented, renamed, or brought back from its deletion around the log, its seal kept, or put back
// after a change with that change's seal column forged (T190, T191: its MAC does not hold), is checked against its
// object's seal and its newest change's before anything is decided on it. `access` holds no grant on it,
// and keeps it protected with its slug unknown; an issue that names it, an issue to a service account that holds a
// grant on it, a change of that account by its manager, a grant there and a key's wrap there are refused. Uses decide on the place's seal too (use.test.ts, use-named.test.ts).
// Whatever the suite's log.
import { defineDeployment } from '@coffre/core/deployment';
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { issuedGrant, storedScope, type CredentialScope } from '@coffre/core/access';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { IssueTokenInput } from '@coffre/core/vault';
import { postgresSession } from '@coffre/db/connect';
import { count, sql } from 'drizzle-orm';
import { setTimeout as sleep } from 'node:timers/promises';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { openLocalVault as openEntry, spoken } from '../src/local.ts';
import { objectKey } from '../src/inputs.ts';
import { changePlace, emptyDatabase, OWNER_URL, newEnvironment, newProject, openLocalVault, openTestDatabase, rows, run, sealed, nothingHeld, speaking, storedVersions, type LocalVault, type TestDatabase } from './database.ts';
import { credentials, secrets } from '@coffre/db/schema';

/** A vault in this process, spoken to through the version gate's envelope (`spoken`). */
const openRawVault = async (...args: Parameters<typeof openEntry>) => spoken(await openEntry(...args));

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const MAYA = 'user:maya@acme.example';
const CI = 'token:ci';
const APP_KEY = 'app:0123456789abcdef';
/** What the vault answers of a decision on a place whose row is not as its log holds it. */
const TAMPERED_PLACE = "an environment it is about failed the vault's integrity check: its row is not as the log holds it";
const TAMPERED_SUBJECT = "this member's record failed the vault's integrity check: a reseal makes it the log's again";

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

/**
 * A vault keeping 0.15's log, a project with `dev` and `prod`, made as the app makes them (sealed), and `elsewhere`, a
 * project of its own. Ada a Developer of `dev` and a Viewer of `prod`, by grants on each.
 */
async function world() {
  const config = configure();
  const vault = await openLocalVault(db.vault, config, { sealThrough: sealed, heldOutside: nothingHeld });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  const [dev, prod] = [await newEnvironment(db.owner, project), await newEnvironment(db.owner, project)];
  const elsewhere = await newProject(db.owner);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADA })).ok);
  assert.ok((await vault.setAccess({
    actor: ROOT, caller: 'person', principal: ADA,
    changes: [{ projectId: project, environmentId: dev, role: 'developer', expiresAt: null }, { projectId: project, environmentId: prod, role: 'viewer', expiresAt: null }],
  })).ok);
  return { vault, config, project, dev, prod, elsewhere };
}

type World = Awaited<ReturnType<typeof world>>;

/**
 * What a writer does to `dev` around the log, its seal kept, and the project it names after: moved to `elsewhere`;
 * renamed; or deleted by the app (a change of its object), then its tombstone cleared.
 */
/**
 * `regrants`: the tamper moves what the grants on `dev` read as (an environment's grant reads its project from the
 * environment's row), so the object of every member holding one is not the one their seal covers: such a member is
 * refused whole, by the vault's decisions as by their uses (T179 PR 2, `#onLog`), and reported, not only the place.
 */
const TAMPERS: Record<string, { tamper: (w: World) => Promise<void>; projectOf: (w: World) => string; regrants?: true }> = {
  're-parented': {
    tamper: (w) => run(db.owner, sql`UPDATE environments SET project_id = ${w.elsewhere} WHERE id = ${w.dev}`),
    projectOf: (w) => w.elsewhere,
    regrants: true,
  },
  renamed: {
    tamper: (w) => run(db.owner, sql`UPDATE environments SET slug = 'renamed' WHERE id = ${w.dev}`),
    projectOf: (w) => w.project,
  },
  'brought back from its deletion': {
    tamper: async (w) => {
      const [{ slug }] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM environments WHERE id = ${w.dev}`) as [{ slug: string }];
      await changePlace(db.owner, w.dev, { slug: `${slug}~deleted-1` });
      await run(db.owner, sql`UPDATE environments SET slug = ${slug} WHERE id = ${w.dev}`);
    },
    projectOf: (w) => w.project,
  },
  // Moved as the app moves it, a change the log holds, MAC and all; then the row put back as it was before, and that
  // change's seal column made the old seal (`putBack`): the seal comparison alone passes (T190, review r3; T191).
  'put back after its archive, the archive\'s seal column made the old one': {
    tamper: (w) => putBack(w.dev, { archived: true }),
    projectOf: (w) => w.project,
  },
  'put back after its rename, the rename\'s seal column made the old one': {
    tamper: (w) => putBack(w.dev, { slug: 'renamed' }),
    projectOf: (w) => w.project,
  },
};

/**
 * What a writer with the database does to place `id` once an honest change has moved it (`honest`, made as the app
 * makes one, `changePlace`): the row put back as it was before, its old seal the vault's, and that change's seal column
 * made the old seal. Row and newest seal agree; only the change's MAC, which covers its seal, says the log never left
 * the row so (T190, review r3; T191).
 */
async function putBack(id: string, honest: { slug?: string; archived?: boolean }): Promise<void> {
  const [row] = await rows<{ slug: string; archived_at: unknown; seal: Buffer }>(db.owner, sql`SELECT slug, archived_at, seal FROM environments WHERE id = ${id}`);
  assert.ok(row !== undefined, `no environment ${id}`);
  await changePlace(db.owner, id, honest);
  await run(db.owner, sql`UPDATE environments SET slug = ${row.slug}, archived_at = ${row.archived_at}, seal = ${row.seal} WHERE id = ${id}`);
  const object = objectKey({ kind: 'environment', id });
  await run(db.owner, sql`UPDATE log_changes SET seal = ${row.seal} WHERE number = (SELECT max(number) FROM log_changes WHERE object = ${object})`);
}

/** The vault's reports of a row that fails its seal, no member's (`log.environment:<id>`): its code, `mac`, for each. */
async function placeReports(): Promise<string[]> {
  return (await rows<{ code: string }>(db.owner, sql`SELECT code FROM audit_log WHERE action = 'vault.tampered' AND subject_principal IS NULL`)).map(({ code }) => code);
}

async function credentialRows(): Promise<number> {
  return (await db.owner.select({ n: count() }).from(credentials))[0]!.n;
}

/** A service token `actor` asks the vault to issue `CI`, scoped to `scope`. */
function issue(actor: string, scope: CredentialScope): IssueTokenInput {
  return {
    actor, via: null, principal: CI, generation: 0, actorAccess: null,
    credential: {
      id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'coffre_svc_x', label: 'deploys',
      scope: storedScope(scope), places: null, expiresAt: Date.now() + 86_400_000, createdBy: actor.slice('user:'.length), passkeyId: null, authMac: randomBytes(32).toString('base64'),
    },
    policy: { seq: null, protected: [] },
    appKey: APP_KEY,
  };
}

/** The policy the app weighs an issue on: `access`'s, with its newest change's number and its protected places' slugs. */
async function issueOn(vault: LocalVault, input: IssueTokenInput): Promise<IssueTokenInput> {
  const { policy } = await vault.access(input.actor);
  const [newest] = await rows<{ seq: string | number }>(db.owner, sql`SELECT seq FROM audit_log WHERE author = 'vault' AND action = 'policy.change' AND decision = 'allow' ORDER BY seq DESC LIMIT 1`);
  return { ...input, policy: { seq: newest === undefined ? null : String(newest.seq), protected: Object.values(policy!.protectedIn).flat() } };
}

for (const [how, { tamper, projectOf, regrants }] of Object.entries(TAMPERS)) {
  test(`access: a grant on a place ${how} around the log holds nothing, and the member keeps the rest`, async () => {
    const w = await world();
    const before = await w.vault.access(ADA);
    assert.deepEqual(before.grants.map((grant) => grant.environmentId).sort(), [w.dev, w.prod].sort());
    await tamper(w);
    const access = await w.vault.access(ADA);
    if (regrants) {
      assert.deepEqual([access.status, access.grants], ['tampered', []]);
      return;
    }
    assert.equal(access.status, 'active', 'their own row is the log\'s');
    assert.deepEqual(access.grants.map(({ projectId, environmentId }) => ({ projectId, environmentId })), [{ projectId: w.project, environmentId: w.prod }]);
    assert.deepEqual(await placeReports(), ['mac'], 'reported once, the place\'s, no member\'s');
  });

  test(`a read on a kept answer of access, beside a grant on a place ${how} around the log, opens where the rest hold`, async () => {
    const w = await world();
    const id = randomUUID();
    await db.owner.insert(secrets).values({ id, projectId: w.project, environmentId: w.prod, key: 'DATABASE_URL' });
    const secret = { projectId: w.project, environmentId: w.prod, secretId: id, version: 1, path: 'p/prod/DATABASE_URL' };
    const key = randomBytes(32).toString('base64');
    const wrapped = await w.vault.wrap({ principal: ROOT, caller: 'person', items: [{ secret, key }] });
    assert.ok(wrapped.ok);
    const items = await storedVersions(db.owner, [{ secret, wrapped: wrapped.wrapped[0]! }]);
    await tamper(w);
    // The answer the app keeps is the one a decision makes of her now: the same grants hold in both.
    const kept = await w.vault.access(ADA);
    if (regrants) {
      // Refused: the answer kept is a tampered member's, which a read never opens on.
      assert.equal(kept.status, 'tampered');
      const read = await w.vault.unwrap({ principal: ADA, caller: 'person', purpose: 'reveal', accessRevision: kept.revision, items });
      assert.equal(read.ok, false);
      return;
    }
    assert.deepEqual(await w.vault.unwrap({ principal: ADA, caller: 'person', purpose: 'reveal', accessRevision: kept.revision, items }), { ok: true, keys: [key], accessRevision: kept.revision });
  });

  test(`access: a protected place ${how} around the log stays protected, its slug unknown`, async () => {
    const w = await world();
    assert.ok((await w.vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'protect', projectId: w.project, environmentIds: [w.dev], protected: true } })).ok);
    const slug = (await w.vault.access(ROOT)).policy!.protectedIn[w.project]![0]!.slug;
    assert.match(slug!, /^e-/);
    await tamper(w);
    const { policy } = await w.vault.access(ADA);
    assert.ok(policy!.protected.includes(w.dev));
    assert.deepEqual(policy!.protectedIn[w.project], [{ environmentId: w.dev, slug: null }]);
    // An issue elsewhere goes on: weighed with no slug there, that place is left out of what `issue_token` holds.
    assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
    assert.ok((await w.vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: w.project, environmentId: w.prod, role: 'viewer', expiresAt: null }] })).ok);
    const issued = await w.vault.issueToken!(await issueOn(w.vault, issue(ROOT, [issuedGrant({ projectId: w.project, environmentId: w.prod, role: 'viewer' })])));
    assert.ok(issued.ok, JSON.stringify(issued));
  });

  test(`an issue whose scope names a place ${how} around the log is refused, nothing written`, async () => {
    const w = await world();
    const at = projectOf(w);
    assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
    assert.ok((await w.vault.setAccess({
      actor: ROOT, caller: 'person', principal: CI,
      changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }, { projectId: w.elsewhere, environmentId: null, role: 'viewer', expiresAt: null }],
    })).ok);
    await tamper(w);
    const none = await credentialRows();
    const outcome = await w.vault.issueToken!(await issueOn(w.vault, issue(ROOT, [issuedGrant({ projectId: at, environmentId: w.dev, role: 'viewer' })])));
    assert.deepEqual(outcome, { ok: false, refused: 'refused', why: TAMPERED_PLACE });
    assert.equal(await credentialRows(), none);
    // Elsewhere in its project, the same Owner issues as ever.
    assert.ok((await w.vault.issueToken!(await issueOn(w.vault, issue(ROOT, [issuedGrant({ projectId: w.project, environmentId: w.prod, role: 'viewer' })])))).ok);
  });

  test(`a service account holding a grant on a place ${how} around the log is issued to by nobody, nor changed by its manager`, async () => {
    const w = await world();
    // Maya, a Developer of both projects, manages CI, a Viewer of dev and prod: until dev is not the log's.
    assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: MAYA })).ok);
    assert.ok((await w.vault.setAccess({
      actor: ROOT, caller: 'person', principal: MAYA,
      changes: [{ projectId: w.project, environmentId: null, role: 'developer', expiresAt: null }, { projectId: w.elsewhere, environmentId: null, role: 'developer', expiresAt: null }],
    })).ok);
    assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
    assert.ok((await w.vault.setAccess({
      actor: ROOT, caller: 'person', principal: CI,
      changes: [{ projectId: w.project, environmentId: w.dev, role: 'viewer', expiresAt: null }, { projectId: w.project, environmentId: w.prod, role: 'viewer', expiresAt: null }],
    })).ok);
    const atProd = [issuedGrant({ projectId: w.project, environmentId: w.prod, role: 'viewer' })];
    assert.ok((await w.vault.issueToken!(await issueOn(w.vault, issue(MAYA, atProd)))).ok, 'Maya manages CI');
    await tamper(w);
    const none = await credentialRows();
    const issued = await w.vault.issueToken!(await issueOn(w.vault, issue(MAYA, atProd)));
    if (regrants) {
      // CI's own object no longer its seal's: refused before any place is weighed, as tampered, not gone (review r1).
      assert.deepEqual(issued, { ok: false, refused: 'refused', why: TAMPERED_SUBJECT });
      assert.equal(await credentialRows(), none);
      return;
    }
    assert.deepEqual(issued, { ok: false, refused: 'refused', why: TAMPERED_PLACE });
    assert.equal(await credentialRows(), none);
    const given = await w.vault.setAccess({ actor: MAYA, caller: 'person', principal: CI, changes: [{ projectId: w.project, environmentId: w.prod, role: null, expiresAt: null }] });
    assert.deepEqual(!given.ok && given.refusal, { code: 'tampered', message: TAMPERED_PLACE });
    // Not by an Owner of the whole instance either: what the account holds is weighed on rows the log does not hold.
    assert.deepEqual(await w.vault.issueToken!(await issueOn(w.vault, issue(ROOT, atProd))), { ok: false, refused: 'refused', why: TAMPERED_PLACE });
  });

  test(`a grant on a place ${how} around the log is refused, as tampered`, async () => {
    const w = await world();
    assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
    await tamper(w);
    const given = await w.vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: projectOf(w), environmentId: w.dev, role: 'viewer', expiresAt: null }] });
    assert.deepEqual(!given.ok && given.refusal, { code: 'tampered', message: TAMPERED_PLACE });
    assert.deepEqual((await w.vault.access(CI)).grants, []);
  });
}

// A place that holds keys moves to another project only with them, whose own rows then fail theirs (`secrets`'s foreign
// key names its environment and project together): renamed, brought back from its deletion, or put back after a change
// with that change's seal column forged, it holds them still.
for (const how of ['renamed', 'brought back from its deletion', 'put back after its archive, the archive\'s seal column made the old one', 'put back after its rename, the rename\'s seal column made the old one']) {
  test(`a key's wrap in a place ${how} around the log is refused, as tampered`, async () => {
    const w = await world();
    const id = randomUUID();
    await db.owner.insert(secrets).values({ id, projectId: w.project, environmentId: w.dev, key: 'DATABASE_URL' });
    const wrap = () => w.vault.wrap({ principal: ADA, caller: 'person', items: [{ secret: { projectId: w.project, environmentId: w.dev, secretId: id, version: 1, path: 'p/dev/DATABASE_URL' }, key: randomBytes(32).toString('base64') }] });
    assert.ok((await wrap()).ok, 'a Developer of dev writes there');
    await TAMPERS[how]!.tamper(w);
    const wrapped = await wrap();
    assert.deepEqual(!wrapped.ok && wrapped.refusal, { code: 'tampered', message: TAMPERED_PLACE });
  });
}

test('a new process\'s first call, a read through a fork renamed around the log, is refused as every later one is (review r1)', async () => {
  const w = await world();
  const id = randomUUID();
  await db.owner.insert(secrets).values({ id, projectId: w.project, environmentId: w.prod, key: 'DATABASE_URL' });
  const secret = { projectId: w.project, environmentId: w.prod, secretId: id, version: 1, path: 'p/prod/DATABASE_URL' };
  const key = randomBytes(32).toString('base64');
  const wrapped = await w.vault.wrap({ principal: ROOT, caller: 'person', items: [{ secret, key }] });
  assert.ok(wrapped.ok);
  const [item] = await storedVersions(db.owner, [{ secret, wrapped: wrapped.wrapped[0]! }]);
  const read = (vault: LocalVault) => vault.unwrap({ principal: ADA, caller: 'person', purpose: 'reveal', items: [{ ...item!, through: w.dev }] });
  assert.ok((await read(w.vault)).ok, 'read through dev, another place of its project');
  await run(db.owner, sql`UPDATE environments SET slug = 'renamed' WHERE id = ${w.dev}`);
  // A vault that has made no call yet: it learns the log is cut over as it reads, not after.
  const fresh = speaking(await openRawVault(db.vault, w.config, { sealThrough: sealed, heldOutside: nothingHeld }));
  assert.equal((await read(fresh)).ok, false);
  assert.equal((await read(fresh)).ok, false);
});

test('a read through a place archived, then put back unarchived with the archive\'s seal column forged, is refused, warm and fresh: the archive\'s MAC does not hold (T191)', async () => {
  const w = await world();
  const id = randomUUID();
  await db.owner.insert(secrets).values({ id, projectId: w.project, environmentId: w.prod, key: 'DATABASE_URL' });
  const secret = { projectId: w.project, environmentId: w.prod, secretId: id, version: 1, path: 'p/prod/DATABASE_URL' };
  const wrapped = await w.vault.wrap({ principal: ROOT, caller: 'person', items: [{ secret, key: randomBytes(32).toString('base64') }] });
  assert.ok(wrapped.ok);
  const [item] = await storedVersions(db.owner, [{ secret, wrapped: wrapped.wrapped[0]! }]);
  const read = (vault: LocalVault) => vault.unwrap({ principal: ADA, caller: 'person', purpose: 'reveal', items: [{ ...item!, through: w.dev }] });
  assert.ok((await read(w.vault)).ok, 'read through dev, another place of its project');
  // Archived, dev is no place to read through; put back, its row and newest seal say it is one again.
  await putBack(w.dev, { archived: true });
  assert.equal((await read(w.vault)).ok, false);
  const fresh = speaking(await openRawVault(db.vault, w.config, { sealThrough: sealed, heldOutside: nothingHeld }));
  assert.equal((await read(fresh)).ok, false);
  assert.ok((await placeReports()).includes('mac'), 'reported as the place\'s, a MAC');
});

// A key held in the forged place itself, read once so the vault keeps the answer: the kept answer does not outlive the
// place's MAC, warm or fresh (T191, review r2).
for (const how of ['put back after its archive, the archive\'s seal column made the old one', 'put back after its rename, the rename\'s seal column made the old one']) {
  test(`a read of a key held in a place ${how} around the log is refused, warm and fresh, and reported as a MAC (T191)`, async () => {
    const w = await world();
    const id = randomUUID();
    await db.owner.insert(secrets).values({ id, projectId: w.project, environmentId: w.dev, key: 'DATABASE_URL' });
    const secret = { projectId: w.project, environmentId: w.dev, secretId: id, version: 1, path: 'p/dev/DATABASE_URL' };
    const wrapped = await w.vault.wrap({ principal: ROOT, caller: 'person', items: [{ secret, key: randomBytes(32).toString('base64') }] });
    assert.ok(wrapped.ok);
    const [item] = await storedVersions(db.owner, [{ secret, wrapped: wrapped.wrapped[0]! }]);
    const read = (vault: LocalVault) => vault.unwrap({ principal: ADA, caller: 'person', purpose: 'reveal', items: [item!] });
    assert.ok((await read(w.vault)).ok, 'a Developer of dev reads there');
    await TAMPERS[how]!.tamper(w);
    assert.equal((await read(w.vault)).ok, false);
    const fresh = speaking(await openRawVault(db.vault, w.config, { sealThrough: sealed, heldOutside: nothingHeld }));
    assert.equal((await read(fresh)).ok, false);
    assert.ok((await placeReports()).includes('mac'), 'reported as the place\'s, a MAC');
  });
}

test('unprotecting a place whose tombstone a writer set around the log is refused: the protection\'s end is its object\'s too (review r1)', async () => {
  const w = await world();
  const protect = (on: boolean) => w.vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'protect', projectId: w.project, environmentIds: [w.dev], protected: on } });
  assert.ok((await protect(true)).ok);
  const [{ slug }] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM environments WHERE id = ${w.dev}`) as [{ slug: string }];
  await run(db.owner, sql`UPDATE environments SET slug = ${`${slug}~deleted-1`} WHERE id = ${w.dev}`);
  const ended = await protect(false);
  assert.deepEqual(!ended.ok && ended.refusal, { code: 'tampered', message: TAMPERED_PLACE });
  assert.ok((await w.vault.policy()).protected.includes(w.dev), 'still protected');
});

test('a protected place in a project whose tombstone a writer set around the log stays protected: its own object says it lives (review r2)', async () => {
  const w = await world();
  assert.ok((await w.vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'protect', projectId: w.project, environmentIds: [w.dev], protected: true } })).ok);
  const [{ slug }] = await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM projects WHERE id = ${w.project}`) as [{ slug: string }];
  await run(db.owner, sql`UPDATE projects SET slug = ${`${slug}~deleted-1`} WHERE id = ${w.project}`);
  const { policy } = await w.vault.access(ADA);
  assert.ok(policy!.protected.includes(w.dev));
  assert.deepEqual(policy!.protectedIn[w.project], [{ environmentId: w.dev, slug: null }]);
  assert.deepEqual((await w.vault.access(ADA)).grants, [], 'nor does a grant there hold');
});

test('a person scoped to a slug no place has sets up no service account once a writer renames a place to it (review r2)', async () => {
  const w = await world();
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: MAYA, role: 'developer', scope: { projects: 'all', environments: { only: ['staging'] } } })).ok);
  const refused = await w.vault.admit({ actor: MAYA, caller: 'person', principal: CI });
  assert.equal(!refused.ok && refused.refusal.code, 'not_allowed');
  await run(db.owner, sql`UPDATE environments SET slug = 'staging' WHERE id = ${w.dev}`);
  const again = await w.vault.admit({ actor: MAYA, caller: 'person', principal: CI });
  assert.equal(!again.ok && again.refusal.code, 'not_allowed');
});

test('a person scoped to a slug sets up no service account once its place, renamed away, is put back with the rename\'s seal column forged (T191)', async () => {
  const w = await world();
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: MAYA, role: 'developer', scope: { projects: 'all', environments: { only: ['staging'] } } })).ok);
  // A place named staging, made so as the app renames one: Maya sets up a service account.
  await changePlace(db.owner, w.dev, { slug: 'staging' });
  assert.ok((await w.vault.admit({ actor: MAYA, caller: 'person', principal: CI })).ok, 'a place in her scope');
  // Renamed away as the app renames, then put back as staging, the rename's seal column made staging's seal.
  await putBack(w.dev, { slug: 'qa' });
  const again = await w.vault.admit({ actor: MAYA, caller: 'person', principal: 'token:ci-2' });
  assert.equal(!again.ok && again.refusal.code, 'not_allowed');
  assert.ok((await placeReports()).includes('mac'), 'reported as the place\'s, a MAC');
});

test("an issue weighed on the account's places by slug is refused when one is renamed while its write waits: those slugs are held under the issue lock too (review r2)", async () => {
  const w = await world();
  const slugOf = async (id: string) => (await rows<{ slug: string }>(db.owner, sql`SELECT slug FROM environments WHERE id = ${id}`))[0]!.slug;
  // Maya, a Developer of dev and prod by slug, manages CI, a Viewer of both, and issues it a token on prod.
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: MAYA, role: 'developer', scope: { projects: 'all', environments: { only: [await slugOf(w.dev), await slugOf(w.prod)] } } })).ok);
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.ok((await w.vault.setAccess({
    actor: ROOT, caller: 'person', principal: CI,
    changes: [{ projectId: w.project, environmentId: w.dev, role: 'viewer', expiresAt: null }, { projectId: w.project, environmentId: w.prod, role: 'viewer', expiresAt: null }],
  })).ok);
  const input = await issueOn(w.vault, issue(MAYA, [issuedGrant({ projectId: w.project, environmentId: w.prod, role: 'viewer' })]));
  const holder = postgresSession(OWNER_URL);
  try {
    // The account's row held: the issue's read is done, its write waits; meanwhile dev is renamed, as the app renames one.
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM principals WHERE principal = '${CI}' FOR NO KEY UPDATE`);
    const issuing = w.vault.issueToken!(input);
    const waits = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%issue_token(%'`))[0]!.n;
    for (let tries = 0; (await waits()) === 0; tries += 1) {
      assert.ok(tries < 200, 'the write waits on the row');
      await sleep(10);
    }
    await changePlace(db.owner, w.dev, { slug: 'renamed' });
    await holder.unsafe('COMMIT');
    const outcome = await issuing;
    assert.deepEqual(outcome, { ok: false, refused: 'policy' });
  } finally {
    await holder.end();
  }
  // Asked again, on the account as it is now: Maya manages it no more.
  assert.equal((await w.vault.issueToken!(await issueOn(w.vault, { ...input, credential: { ...input.credential, id: randomUUID() } }))).ok, false);
});

test('a reference is decided on its holder\'s project as the row the decision checks says it, not as an earlier read saw it (review r4)', async () => {
  const w = await world();
  // Maya, a Developer of billing alone, refers from billing to a key held in a new place of market's.
  const billing = w.elsewhere;
  const [kept] = [await newEnvironment(db.owner, billing)];
  const sourceId = randomUUID();
  await db.owner.insert(secrets).values({ id: sourceId, projectId: billing, environmentId: kept, key: 'SOURCE' });
  assert.ok((await w.vault.admit({ actor: ROOT, caller: 'person', principal: MAYA })).ok);
  assert.ok((await w.vault.setAccess({ actor: ROOT, caller: 'person', principal: MAYA, changes: [{ projectId: billing, environmentId: null, role: 'developer', expiresAt: null }] })).ok);
  const place = await newEnvironment(db.owner, w.project);
  const refer = () => w.vault.reference({
    principal: MAYA, caller: 'person',
    items: [{ id: randomUUID(), holder: { projectId: billing, environmentId: place, secretId: randomUUID(), path: 'billing/x/HELD' }, source: { secretId: sourceId } }],
  });
  const refused = await refer();
  assert.equal(!refused.ok && refused.refusal.code, 'bad_claim', 'a market place claimed as billing\'s');
  const holder = postgresSession(OWNER_URL);
  try {
    // A writer moves the place to billing while the request reads it, then back before its decision does.
    await run(db.owner, sql`UPDATE environments SET project_id = ${billing} WHERE id = ${place}`);
    await holder.unsafe('BEGIN');
    await holder.unsafe(`SELECT 1 FROM principals WHERE principal = '${MAYA}' FOR NO KEY UPDATE`);
    const referring = refer();
    const waits = async () => (await db.owner.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%principals%'`))[0]!.n;
    for (let tries = 0; (await waits()) === 0; tries += 1) {
      assert.ok(tries < 200, 'the decision waits on her row');
      await sleep(10);
    }
    await run(db.owner, sql`UPDATE environments SET project_id = ${w.project} WHERE id = ${place}`);
    await holder.unsafe('COMMIT');
    const outcome = await referring;
    assert.equal(!outcome.ok && outcome.refusal.code, 'bad_claim', JSON.stringify(outcome));
  } finally {
    await holder.end();
  }
});

test('a protected place whose row a writer deleted outright stays protected: the log holds it, so it is no fork never written (review r5)', async () => {
  const w = await world();
  let offset = 0;
  const vault = await openLocalVault(db.vault, w.config, { sealThrough: sealed, heldOutside: nothingHeld, clockOffset: () => offset });
  const [a, b] = [await newEnvironment(db.owner, w.project), await newEnvironment(db.owner, w.project)];
  assert.ok((await vault.changePolicy({ actor: ROOT, caller: 'person', change: { kind: 'protect', projectId: w.project, environmentIds: [a, b], protected: true } })).ok);
  // Maya, a Developer of the whole instance, reads no protected place; CI views the project, by Root's grant.
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: MAYA, role: 'developer' })).ok);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: CI })).ok);
  assert.ok((await vault.setAccess({ actor: ROOT, caller: 'person', principal: CI, changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }] })).ok);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: 'token:ci2' })).ok);
  // Past the ten minutes a fork's id protects before its row is written.
  offset = 11 * 60_000;
  const give = () => vault.setAccess({ actor: MAYA, caller: 'person', principal: 'token:ci2', changes: [{ projectId: w.project, environmentId: null, role: 'viewer', expiresAt: null }] });
  const issueProject = async () => vault.issueToken!(await issueOn(vault, issue(MAYA, [issuedGrant({ projectId: w.project, environmentId: null, role: 'viewer' })])));
  assert.equal((await give()).ok, false, 'a project-wide grant reaches the protected places, which she does not read');
  assert.equal((await issueProject()).ok, false);
  await run(db.owner, sql`DELETE FROM environments WHERE id IN (${a}, ${b})`);
  const { policy } = await vault.access(MAYA);
  assert.deepEqual([...policy!.protectedIn[w.project]!].sort((x, y) => (x.environmentId < y.environmentId ? -1 : 1)),
    [{ environmentId: a, slug: null }, { environmentId: b, slug: null }].sort((x, y) => (x.environmentId < y.environmentId ? -1 : 1)));
  assert.equal((await give()).ok, false);
  assert.equal((await issueProject()).ok, false);
});
