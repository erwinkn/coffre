// The vault decides on no environment row 0.15's log does not hold (T159; R53, every decision input sealed; R64, fail
// closed): a place re-parented, renamed, or brought back from its deletion around the log, its seal kept, is checked
// against its object's seal and its newest change's before anything is decided on it. `access` holds no grant on it,
// and keeps it protected with its slug unknown; an issue that names it, an issue to a service account that holds a
// grant on it, a change of that account by its manager, a grant there and a key's wrap there are refused. Uses decide on the place's seal too (use.test.ts, use-named.test.ts).
// Both engines, whatever the suite's log.
import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';

import { issuedGrant, storedScope, type CredentialScope } from '@coffre/core/access';
import { KekRegistry, LocalKekProvider } from '@coffre/core/kek';
import type { IssueTokenInput } from '@coffre/core/vault';
import { tablesOf } from '@coffre/db';
import { count, sql } from 'drizzle-orm';

import type { ResolvedVaultConfig } from '../src/config.ts';
import { changePlace, emptyDatabase, newEnvironment, newProject, openLocalVault, openTestDatabase, rows, run, sealed, storedVersions, type LocalVault, type TestDatabase } from './database.ts';

const ROOT = 'user:root@acme.example';
const ADA = 'user:ada@acme.example';
const MAYA = 'user:maya@acme.example';
const CI = 'token:ci';
const APP_KEY = 'app:0123456789abcdef';
/** What the vault answers of a decision on a place whose row is not as its log holds it. */
const TAMPERED_PLACE = "an environment it is about failed the vault's integrity check: its row is not as the log holds it";

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

/**
 * A vault keeping 0.15's log, a project with `dev` and `prod`, made as the app makes them (sealed), and `elsewhere`, a
 * project of its own. Ada a Developer of `dev` and a Viewer of `prod`, by grants on each.
 */
async function world() {
  const vault = await openLocalVault(db.vault, configure(), { log: '0.15', sealThrough: sealed });
  assert.equal((await vault.access(ROOT)).role, 'owner');
  const project = await newProject(db.owner);
  const [dev, prod] = [await newEnvironment(db.owner, project), await newEnvironment(db.owner, project)];
  const elsewhere = await newProject(db.owner);
  assert.ok((await vault.admit({ actor: ROOT, caller: 'person', principal: ADA })).ok);
  assert.ok((await vault.setAccess({
    actor: ROOT, caller: 'person', principal: ADA,
    changes: [{ projectId: project, environmentId: dev, role: 'developer', expiresAt: null }, { projectId: project, environmentId: prod, role: 'viewer', expiresAt: null }],
  })).ok);
  return { vault, project, dev, prod, elsewhere };
}

type World = Awaited<ReturnType<typeof world>>;

/**
 * What a writer does to `dev` around the log, its seal kept, and the project it names after: moved to `elsewhere`;
 * renamed; or deleted by the app (a change of its object), then its tombstone cleared.
 */
const TAMPERS: Record<string, { tamper: (w: World) => Promise<void>; projectOf: (w: World) => string }> = {
  're-parented': {
    tamper: (w) => run(db.owner, sql`UPDATE environments SET project_id = ${w.elsewhere} WHERE id = ${w.dev}`),
    projectOf: (w) => w.elsewhere,
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
};

/** The vault's reports of a row that fails its seal, no member's (`log.environment:<id>`): its code, `mac`, for each. */
async function placeReports(): Promise<string[]> {
  return (await rows<{ code: string }>(db.owner, sql`SELECT code FROM audit_log WHERE action = 'vault.tampered' AND subject_principal IS NULL`)).map(({ code }) => code);
}

async function credentialRows(): Promise<number> {
  const { credentials } = tablesOf(db.owner);
  return (await db.owner.select({ n: count() }).from(credentials))[0]!.n;
}

/** A service token `actor` asks the vault to issue `CI`, scoped to `scope`. */
function issue(actor: string, scope: CredentialScope): IssueTokenInput {
  return {
    actor, via: null, principal: CI, generation: 0, actorAccess: null,
    credential: {
      id: randomUUID(), kind: 'service', tokenHash: randomBytes(32).toString('base64'), tokenHint: 'coffre_svc_x', label: 'deploys',
      scope: storedScope(scope), places: null, expiresAt: Date.now() + 86_400_000, createdBy: actor.slice('user:'.length), authMac: randomBytes(32).toString('base64'),
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

for (const [how, { tamper, projectOf }] of Object.entries(TAMPERS)) {
  test(`access: a grant on a place ${how} around the log holds nothing, and the member keeps the rest`, async () => {
    const w = await world();
    const before = await w.vault.access(ADA);
    assert.deepEqual(before.grants.map((grant) => grant.environmentId).sort(), [w.dev, w.prod].sort());
    await tamper(w);
    const access = await w.vault.access(ADA);
    assert.equal(access.status, 'active', 'their own row is the log\'s');
    assert.deepEqual(access.grants.map(({ projectId, environmentId }) => ({ projectId, environmentId })), [{ projectId: w.project, environmentId: w.prod }]);
    assert.deepEqual(await placeReports(), ['mac'], 'reported once, the place\'s, no member\'s');
  });

  test(`a read on a kept answer of access, beside a grant on a place ${how} around the log, opens where the rest hold`, async () => {
    const w = await world();
    const id = randomUUID();
    await db.owner.insert(tablesOf(db.owner).secrets).values({ id, projectId: w.project, environmentId: w.prod, key: 'DATABASE_URL' });
    const secret = { projectId: w.project, environmentId: w.prod, secretId: id, version: 1, path: 'p/prod/DATABASE_URL' };
    const key = randomBytes(32).toString('base64');
    const wrapped = await w.vault.wrap({ principal: ROOT, caller: 'person', items: [{ secret, key }] });
    assert.ok(wrapped.ok);
    const items = await storedVersions(db.owner, [{ secret, wrapped: wrapped.wrapped[0]! }]);
    await tamper(w);
    // The answer the app keeps is the one a decision makes of her now: the same grants hold in both.
    const kept = await w.vault.access(ADA);
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
    assert.deepEqual(await w.vault.issueToken!(await issueOn(w.vault, issue(MAYA, atProd))), { ok: false, refused: 'refused', why: TAMPERED_PLACE });
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
// key names its environment and project together): renamed, or brought back from its deletion, it holds them still.
for (const how of ['renamed', 'brought back from its deletion']) {
  test(`a key's wrap in a place ${how} around the log is refused, as tampered`, async () => {
    const w = await world();
    const id = randomUUID();
    await db.owner.insert(tablesOf(db.owner).secrets).values({ id, projectId: w.project, environmentId: w.dev, key: 'DATABASE_URL' });
    const wrap = () => w.vault.wrap({ principal: ADA, caller: 'person', items: [{ secret: { projectId: w.project, environmentId: w.dev, secretId: id, version: 1, path: 'p/dev/DATABASE_URL' }, key: randomBytes(32).toString('base64') }] });
    assert.ok((await wrap()).ok, 'a Developer of dev writes there');
    await TAMPERS[how]!.tamper(w);
    const wrapped = await wrap();
    assert.deepEqual(!wrapped.ok && wrapped.refusal, { code: 'tampered', message: TAMPERED_PLACE });
  });
}
