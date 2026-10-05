import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import type { CoffreClient } from '@coffre/client';
import { and, asc, eq, gte } from 'drizzle-orm';

import { auditChainHead, auditLog, secretReferences, secrets, secretVersions } from './db/tables.ts';
import { clientFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

// References between environments and projects (docs/design/environments.md).
// market/prod/DATABASE_URL is the source; billing/prod holds references to it.

const ROOT = 'admin@acme.example';
/** Reads market/prod, and develops billing. */
const ADA = 'ada@acme.example';
/** Reads billing/prod, and nothing in market. */
const BO = 'bo@acme.example';
/** Manages market's access; reads nothing. */
const MAX = 'max@acme.example';
/** Maintains market: writes and archives its secrets. */
const CARO = 'caro@acme.example';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let root: CoffreClient;
let ada: CoffreClient;
let bo: CoffreClient;
let max: CoffreClient;
let caro: CoffreClient;
let firstSeq: bigint;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  root = clientFor(deps, ROOT);
  [ada, bo, max, caro] = [ADA, BO, MAX, CARO].map((email) => clientFor(deps, email));
  for (const [project, environment] of [['market', 'prod'], ['billing', 'prod']] as const) {
    await root.projects.create(project, { name: project });
    await root.environments.create(`${project}/${environment}`, { name: environment });
  }
  for (const [email, access] of [
    [ADA, { 'market/prod': 'viewer', billing: 'developer' }],
    [BO, { 'billing/prod': 'viewer' }],
    [MAX, { market: 'access-manager' }],
    [CARO, { market: 'maintainer' }],
  ] as const) {
    await root.members.add(`user:${email}`);
    await root.access.set(`user:${email}`, access);
  }
  await root.secrets.set('market/prod', { DATABASE_URL: 'postgres://v1', STRIPE_KEY: 'sk_1' });
  await root.secrets.set('billing/prod', { PORT: '8080' });
  const [head] = await db.owner.select({ nextSeq: auditChainHead.nextSeq }).from(auditChainHead);
  firstSeq = head.nextSeq;
});

const ref = (path: string) => ({ ref: path });
const refusal = (call: Promise<unknown>) => call.then(() => 'let through', (error: { status?: number; message?: string }) => `${error.status}: ${error.message}`);

test("a reader of the holder reads the source through it, live, without a grant in the source's project", async () => {
  assert.deepEqual((await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') })).keys, {
    DATABASE_URL: { reference: 'market/prod/DATABASE_URL' },
  });
  assert.deepEqual((await bo.secrets.reveal('billing/prod')).values, { DATABASE_URL: 'postgres://v1', PORT: '8080' });
  // Bo still reads nothing in market itself.
  await assert.rejects(bo.secrets.reveal('market/prod/DATABASE_URL'), { status: 403 });
  // A rotation in market is what billing reads next.
  await caro.secrets.set('market/prod', { DATABASE_URL: 'postgres://v2' });
  assert.deepEqual((await bo.secrets.reveal('billing/prod/DATABASE_URL')).values, { DATABASE_URL: 'postgres://v2' });

  const listed = (await bo.secrets.list('billing/prod')).keys.find((key) => key.key === 'DATABASE_URL')!;
  assert.deepEqual(
    [listed.version, listed.reference?.source, listed.reference?.state, listed.reference?.version, listed.reference?.canOpenSource, listed.reference?.createdBy],
    [null, 'market/prod/DATABASE_URL', 'live', 2, false, `user:${ADA}`],
  );
  assert.equal((await ada.secrets.list('billing/prod')).keys.find((key) => key.key === 'DATABASE_URL')!.reference?.canOpenSource, true);
});

test("a grant on prod in every project reads through a reference held in prod, as the holder's slug decides", async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  // Bo's grant moves from billing/prod to prod in every project: still no grant in market.
  await root.access.set(`user:${BO}`, { 'billing/prod': null, '*/prod': 'viewer' });
  assert.deepEqual((await bo.secrets.reveal('billing/prod/DATABASE_URL')).values, { DATABASE_URL: 'postgres://v1' });
  // Renamed, billing/prod is no longer prod: the grant on prod no longer reaches through it.
  await root.environments.update('billing/prod', { slug: 'live' });
  await assert.rejects(bo.secrets.reveal('billing/live/DATABASE_URL'), { status: 403 });
});

test("a reference reads its source's newest version only, whatever its current_version_id says", async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  await caro.secrets.set('market/prod', { DATABASE_URL: 'postgres://v2' });
  // The app's login may write current_version_id: pointed back at v1, the vault refuses rather than open v1 through billing.
  const [source] = await db.owner.select({ id: secrets.id }).from(secrets).where(and(eq(secrets.key, 'DATABASE_URL'), eq(secrets.currentVersion, 2)));
  const [first] = await db.owner.select({ id: secretVersions.id }).from(secretVersions).where(and(eq(secretVersions.secretId, source!.id), eq(secretVersions.version, 1)));
  await db.owner.update(secrets).set({ currentVersionId: first!.id }).where(eq(secrets.id, source!.id));
  const before = await db.owner.select({ seq: auditLog.seq }).from(auditLog).where(and(eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'allow')));
  await assert.rejects(bo.secrets.reveal('billing/prod/DATABASE_URL'), { status: 403 });
  const after = await db.owner.select({ seq: auditLog.seq }).from(auditLog).where(and(eq(auditLog.action, 'secret.read'), eq(auditLog.decision, 'allow')));
  assert.equal(after.length, before.length, 'nothing is released');
});

test('making one takes your own read on the source, and write where it is held', async () => {
  // Bo reads billing but writes nothing; Max manages market's access but reads nothing; Caro writes nothing in billing.
  await assert.rejects(bo.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') }), { status: 403 });
  await assert.rejects(caro.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') }), { status: 403 });
  await root.access.set(`user:${MAX}`, { billing: 'developer' });
  await assert.rejects(max.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') }), { status: 403 });
  await assert.rejects(ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/NOPE') }), { status: 404 });
  assert.deepEqual(await db.owner.select().from(secretReferences), []);
});

test('one hop: no reference to a reference, and no reference made of what others read through', async () => {
  await root.environments.create('billing/staging', { name: 'staging' });
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  assert.match(await refusal(ada.secrets.set('billing/staging', { DATABASE_URL: ref('billing/prod/DATABASE_URL') })),
    /409: billing\/prod\/DATABASE_URL is itself a reference to market\/prod\/DATABASE_URL: point DATABASE_URL at its source instead/);
  // market/prod/DATABASE_URL is read through billing's: it cannot become a reference itself.
  await root.secrets.set('billing/prod', { OTHER: 'x' });
  assert.match(await refusal(root.secrets.set('market/prod', { DATABASE_URL: ref('billing/prod/OTHER') })), /409: 1 reference read DATABASE_URL \(billing\/prod\/DATABASE_URL\)/);
  assert.match(await refusal(ada.secrets.set('billing/prod', { PORT: ref('billing/prod/PORT') })), /409: PORT cannot be a reference to itself/);
});

test('a value of its own ends the reference: the vault first, then the write', async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  // The same reference again changes nothing, and asks the vault nothing.
  assert.deepEqual((await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') })).keys.DATABASE_URL, { reference: 'market/prod/DATABASE_URL' });
  assert.equal((await db.owner.select().from(secretReferences)).length, 1);
  await ada.secrets.set('billing/prod', { DATABASE_URL: 'postgres://billing-own' });
  assert.deepEqual((await bo.secrets.reveal('billing/prod/DATABASE_URL')).values, { DATABASE_URL: 'postgres://billing-own' });
  assert.equal((await bo.secrets.list('billing/prod')).keys.find((key) => key.key === 'DATABASE_URL')!.reference, null);
  const ends = await entries('vault', 'reference.end');
  assert.deepEqual(ends.map((entry) => [entry.actor, entry.decision, entry.metadata.reason]), [[`user:${ADA}`, 'allow', 'replaced']]);
  // And it can follow the source again, as a new reference.
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  assert.deepEqual((await bo.secrets.reveal('billing/prod/DATABASE_URL')).values, { DATABASE_URL: 'postgres://v1' });
});

test('a new reference whose old one could not be ended, the vault call thrown, is abandoned', async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  const original = deps.vault.endReferences.bind(deps.vault);
  deps.vault.endReferences = async (input) => {
    if (input.reason === 'replaced') throw new Error('the vault is unreachable');
    return original(input);
  };
  try {
    assert.match(await refusal(ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/STRIPE_KEY') })), /^5\d\d: /);
  } finally {
    deps.vault.endReferences = original;
  }
  const [, sealed] = await entries('vault', 'reference.create');
  assert.deepEqual((await entries('vault', 'reference.end')).map((entry) => [entry.relatedSeq, entry.metadata.reason]), [[sealed!.seq, 'abandoned']]);
  // The first reference was never ended, and still reads.
  assert.deepEqual((await bo.secrets.reveal('billing/prod/DATABASE_URL')).values, { DATABASE_URL: 'postgres://v1' });
});

test("the source's access manager breaks it, and a run of the holder stops, saying why and who can fix it", async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  // Only who writes the holder, or manages the source's access: to anyone else there is no such reference.
  await assert.rejects(bo.references.break('billing/prod/DATABASE_URL'), { status: 404 });
  const broken = await max.references.break('billing/prod/DATABASE_URL');
  assert.deepEqual([broken.reference.state, broken.reference.endedBy], ['broken', `user:${MAX}`]);
  assert.match(await refusal(bo.secrets.reveal('billing/prod')),
    /409: billing\/prod\/DATABASE_URL is a reference to market\/prod\/DATABASE_URL, which max@acme\.example broke on \d{4}-\d{2}-\d{2}: set a value for DATABASE_URL, or ask someone who reads market\/prod to make the reference again/);
  assert.equal((await bo.secrets.list('billing/prod')).keys.find((key) => key.key === 'DATABASE_URL')!.reference?.state, 'broken');
  await assert.rejects(max.references.break('billing/prod/DATABASE_URL'), { status: 409 });
  // The end names the holder's key, so that key's own log shows it broken, as its environment's does.
  const [holder] = await db.owner.select({ secretId: secretReferences.secretId }).from(secretReferences);
  const ended = await db.owner.select({ secretId: auditLog.secretId }).from(auditLog)
    .where(and(eq(auditLog.action, 'reference.end'), eq(auditLog.decision, 'allow')));
  assert.deepEqual(ended, [{ secretId: holder!.secretId }]);
  const { entries } = await root.audit.list({ path: 'billing/prod', detail: '1', limit: 50 });
  assert.ok(entries.some((entry) => entry.action === 'reference.end' && entry.decision === 'allow'), "billing/prod's log shows the reference broken");
});

test('an archived source refuses reads through it until it is back, and never reads as empty', async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  // Archived before archiving a read source was refused (D41): as data from then has it.
  await db.owner.update(secrets).set({ archivedAt: new Date() }).where(eq(secrets.key, 'DATABASE_URL'));
  await db.owner.update(secrets).set({ archivedAt: null }).where(and(eq(secrets.key, 'DATABASE_URL'), eq(secrets.environmentId, (await holderEnvironment())!)));
  assert.match(await refusal(bo.secrets.reveal('billing/prod')), /409: .*which is archived: market\/prod's maintainers can unarchive it, or set a value for DATABASE_URL/);
  await caro.secrets.update('market/prod/DATABASE_URL', { archived: false });
  assert.deepEqual((await bo.secrets.reveal('billing/prod')).values.DATABASE_URL, 'postgres://v1');
});

/** The environment billing/prod's references are held in. */
async function holderEnvironment(): Promise<string | undefined> {
  const [row] = await db.owner.select({ environmentId: secretReferences.environmentId }).from(secretReferences);
  return row?.environmentId;
}

test('archiving what live references read is refused, naming them and who can break them; restoring never is (D41)', async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  const named = /409: 1 reference reads market\/prod(\/DATABASE_URL)?: billing\/prod\/DATABASE_URL reads market\/prod\/DATABASE_URL\. Archiving would stop that read, so break it first: market's owners and access managers can, or whoever writes the environment that holds it \(`coffre references break billing\/prod\/DATABASE_URL --apply`\)$/;
  assert.match(await refusal(caro.secrets.update('market/prod/DATABASE_URL', { archived: true })), named, 'the key');
  assert.match(await refusal(caro.secrets.set('market/prod', { DATABASE_URL: null })), named, 'the key, archived by a write');
  assert.match(await refusal(root.environments.update('market/prod', { archived: true })), named, 'its environment');
  assert.match(await refusal(root.projects.update('market', { archived: true })), /409: 1 reference reads market: billing\/prod\/DATABASE_URL reads market\/prod\/DATABASE_URL/, 'its project');
  // What nothing reads is archived as before; and the refusals are logged, naming the references.
  await caro.secrets.update('market/prod/STRIPE_KEY', { archived: true });
  await caro.secrets.update('market/prod/STRIPE_KEY', { archived: false });
  const refused = (await db.owner.select({ action: auditLog.action, metadata: auditLog.metadata }).from(auditLog)
    .where(eq(auditLog.decision, 'deny')).orderBy(asc(auditLog.seq)))
    .filter((row) => (JSON.parse(row.metadata) as { reason?: string }).reason === 'referenced');
  assert.deepEqual(refused.map((row) => row.action), ['secret.archive', 'secret.archive', 'environment.archive', 'project.archive']);

  // The holder's own place archives freely: archiving it stops no one else's read.
  await root.environments.update('billing/prod', { archived: true });
  await root.environments.update('billing/prod', { archived: false });
  // Broken, it blocks nothing: the source archives, and restores.
  await max.references.break('billing/prod/DATABASE_URL');
  await caro.secrets.update('market/prod/DATABASE_URL', { archived: true });
  await caro.secrets.update('market/prod/DATABASE_URL', { archived: false });
  await root.projects.update('market', { archived: true });
  await root.projects.update('market', { archived: false });
});

test('a write archiving several keys names the keys references read, in its refusal and in its entry', async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  const archiveBoth = () => refusal(caro.secrets.set('market/prod', { DATABASE_URL: null, STRIPE_KEY: null }));
  assert.match(await archiveBoth(), /^409: 1 reference reads market\/prod\/DATABASE_URL: billing\/prod\/DATABASE_URL reads market\/prod\/DATABASE_URL\. Archiving would stop that read, so break it first/);
  await ada.secrets.set('billing/prod', { STRIPE_KEY: ref('market/prod/STRIPE_KEY') });
  assert.match(await archiveBoth(), /^409: 2 references read 2 keys of market\/prod: billing\/prod\/DATABASE_URL reads market\/prod\/DATABASE_URL; billing\/prod\/STRIPE_KEY reads market\/prod\/STRIPE_KEY\. Archiving would stop those reads, so break them first/);
  // The audit page names the key, as for a PATCH, or lists the keys.
  const refused = (await root.audit.list({ path: 'market/prod', limit: 50 })).entries
    .filter((entry) => entry.action === 'secret.archive' && entry.decision === 'deny')
    .sort((a, b) => a.seq - b.seq);
  assert.deepEqual(refused.map((entry) => [entry.key, entry.metadata.path, entry.metadata.keys ?? null]), [
    ['DATABASE_URL', 'market/prod/DATABASE_URL', null],
    [null, '2 keys of market/prod', ['DATABASE_URL', 'STRIPE_KEY']],
  ]);
});

test("a reference held in the place being archived blocks nothing; a forged row blocks nothing", async () => {
  await root.environments.create('market/dev', { name: 'dev' });
  await root.access.set(`user:${ADA}`, { 'market/prod': 'viewer', 'market/dev': 'developer', billing: 'developer' });
  await ada.secrets.set('market/dev', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  assert.match(await refusal(root.environments.update('market/prod', { archived: true })), /409: 1 reference reads market\/prod: market\/dev\/DATABASE_URL reads/, 'another environment of the project reads it');
  await root.projects.update('market', { archived: true });
  await root.projects.update('market', { archived: false });

  // A row the vault never sealed, written by the database's owner, is no reference.
  const [source] = await db.owner.select({ id: secrets.id, projectId: secrets.projectId, environmentId: secrets.environmentId }).from(secrets).where(eq(secrets.key, 'STRIPE_KEY'));
  const [billing] = await db.owner.select({ id: secrets.id, projectId: secrets.projectId, environmentId: secrets.environmentId }).from(secrets).where(eq(secrets.key, 'PORT'));
  await db.owner.insert(secretReferences).values({
    id: crypto.randomUUID(), projectId: billing!.projectId, environmentId: billing!.environmentId, secretId: billing!.id,
    sourceProjectId: source!.projectId, sourceEnvironmentId: source!.environmentId, sourceSecretId: source!.id,
    createdSeq: firstSeq, createdBy: `user:${ADA}`,
  });
  await caro.secrets.update('market/prod/STRIPE_KEY', { archived: true });
});

test('an archive that commits between the vault sealing a reference and its row refuses the reference: no live reference reads an archived source', async () => {
  // The other order, a reference made first, is the refusal above.
  const original = deps.vault.reference.bind(deps.vault);
  let archived = false;
  deps.vault.reference = async (input) => {
    const made = await original(input);
    // Between the seal and the row: the archive takes the head, finds no row, and commits.
    await caro.secrets.update('market/prod/DATABASE_URL', { archived: true });
    archived = true;
    return made;
  };
  try {
    assert.match(await refusal(ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') })),
      /404: market\/prod\/DATABASE_URL was archived or deleted meanwhile: it is no live secret to refer to/);
  } finally {
    deps.vault.reference = original;
  }
  assert.ok(archived);
  assert.deepEqual(await db.owner.select().from(secretReferences), [], 'no reference row');
  assert.equal((await ada.secrets.list('billing/prod')).keys.find((key) => key.key === 'DATABASE_URL'), undefined, 'no key holds it');

  // The seal the write never stored is ended, abandoned, by its maker.
  const [seal] = await entries('vault', 'reference.create');
  assert.deepEqual((await entries('vault', 'reference.end')).map((entry) => [entry.actor, entry.relatedSeq, entry.metadata.reason]), [
    [`user:${ADA}`, seal!.seq, 'abandoned'],
  ]);
  // So a holder and a row written later around the app, naming it, read nothing, the source back or not.
  await caro.secrets.update('market/prod/DATABASE_URL', { archived: false });
  const sealed = seal!.metadata as { reference: string; secretId: string; also: { projectId: string; environmentId: string; secretId: string } };
  const [billing] = await db.owner.select({ projectId: secrets.projectId, environmentId: secrets.environmentId }).from(secrets).where(eq(secrets.key, 'PORT'));
  await db.owner.insert(secrets).values({ id: sealed.secretId, ...billing!, key: 'DATABASE_URL' });
  await db.owner.insert(secretReferences).values({
    id: sealed.reference, ...billing!, secretId: sealed.secretId,
    sourceProjectId: sealed.also.projectId, sourceEnvironmentId: sealed.also.environmentId, sourceSecretId: sealed.also.secretId,
    createdSeq: seal!.seq, createdBy: `user:${ADA}`,
  });
  assert.match(await refusal(bo.secrets.reveal('billing/prod/DATABASE_URL')), /^409: billing\/prod\/DATABASE_URL is a reference to market\/prod\/DATABASE_URL, which ada@acme.example broke/);
});

test("the source's side sees who reads through its references, and the reads are in both projects' logs", async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  await bo.secrets.reveal('billing/prod');

  const lent = (await max.references.list('market/prod/DATABASE_URL')).references;
  assert.deepEqual(lent.map((reference) => [reference.holder, reference.source, reference.readers, reference.canBreak]), [
    // Ada develops billing, so she reads its prod as Bo does.
    ['billing/prod/DATABASE_URL', 'market/prod/DATABASE_URL', [`user:${ADA}`, `user:${BO}`], true],
  ]);
  // Bo sees what billing holds, not who reads it.
  assert.deepEqual((await bo.references.list('billing')).references.map((reference) => [reference.holder, reference.readers, reference.canBreak]), [
    ['billing/prod/DATABASE_URL', null, false],
  ]);
  // Root, who manages both, sees it from either side.
  assert.equal((await root.references.list('billing/prod')).references.length, 1);
  assert.equal((await root.references.list('market/prod/STRIPE_KEY')).references.length, 0);

  const read = (await entries('vault', 'secret.read')).filter((entry) => entry.actor === `user:${BO}` && entry.metadata.via !== undefined);
  assert.equal(read.length, 1);
  const inLog = async (path: string) => (await root.audit.list({ path, limit: 50 })).entries.filter((entry) => entry.seq === Number(read[0]!.seq)).length;
  assert.deepEqual([await inLog('market'), await inLog('market/prod'), await inLog('billing'), await inLog('billing/prod')], [1, 1, 1, 1]);
});

test("an offboarding report lists the references someone made, by their seals' actor; removing them ends none (D46)", async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL'), STRIPE_KEY: ref('market/prod/STRIPE_KEY') });
  await max.references.break('billing/prod/STRIPE_KEY');
  // The root's, its row's maker rewritten to Ada: the seal says who made it, not the row.
  await root.secrets.set('billing/prod', { LEDGER_KEY: ref('market/prod/STRIPE_KEY') });
  await db.owner.update(secretReferences).set({ createdBy: `user:${ADA}` });
  const report = await root.members.get(`user:${ADA}`);
  assert.deepEqual(report.references.map((reference) => [reference.holder, reference.state]), [
    ['billing/prod/DATABASE_URL', 'live'], ['billing/prod/STRIPE_KEY', 'broken'],
  ]);
  assert.deepEqual((await root.members.get(`user:${ROOT}`)).references.map((reference) => reference.holder), ['billing/prod/LEDGER_KEY']);
  assert.deepEqual((await root.members.get(`user:${BO}`)).references, []);
  await root.members.remove(`user:${ADA}`);
  assert.deepEqual((await bo.secrets.reveal('billing/prod/DATABASE_URL')).values, { DATABASE_URL: 'postgres://v1' });
});

test('a fork as references points at the original sources, one hop, and copies what the forker reads only through its parent', async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL') });
  await root.access.set(`user:${BO}`, { billing: 'maintainer' });
  await root.access.set(`user:${ADA}`, { billing: 'maintainer' });
  // Bo reads market's value through billing/prod only: that key is copied, the rest referenced.
  const byBo = await bo.environments.create('billing/qa', { name: 'qa', from: 'prod', references: true });
  assert.deepEqual(byBo.forked, { from: 'prod', keys: 2, references: 1, copied: ['DATABASE_URL'] });
  const qa = new Map((await bo.secrets.list('billing/qa')).keys.map((key) => [key.key, key.reference?.source ?? `v${key.version}`]));
  assert.deepEqual(Object.fromEntries(qa), { DATABASE_URL: 'v1', PORT: 'billing/prod/PORT' });
  // Ada reads market herself: billing/prod's reference resolves to market's key, not to billing's.
  const byAda = await ada.environments.create('billing/staging', { name: 'staging', from: 'prod', references: true });
  assert.deepEqual(byAda.forked, { from: 'prod', keys: 2, references: 2, copied: [] });
  const staging = new Map((await ada.secrets.list('billing/staging')).keys.map((key) => [key.key, key.reference?.source]));
  assert.deepEqual(Object.fromEntries(staging), { DATABASE_URL: 'market/prod/DATABASE_URL', PORT: 'billing/prod/PORT' });
  assert.deepEqual((await bo.secrets.reveal('billing/staging')).values, { DATABASE_URL: 'postgres://v1', PORT: '8080' });
});

/** One author's entries of `action` since the setup. */
async function entries(author: 'app' | 'vault', action: string) {
  const rows = await db.owner
    .select({ seq: auditLog.seq, actor: auditLog.actor, decision: auditLog.decision, relatedSeq: auditLog.relatedSeq, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, author), eq(auditLog.action, action), gte(auditLog.seq, firstSeq)))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}
