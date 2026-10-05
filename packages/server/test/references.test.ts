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
  await caro.secrets.update('market/prod/DATABASE_URL', { archived: true });
  assert.match(await refusal(bo.secrets.reveal('billing/prod')), /409: .*which is archived: market\/prod's maintainers can unarchive it, or set a value for DATABASE_URL/);
  await caro.secrets.update('market/prod/DATABASE_URL', { archived: false });
  assert.deepEqual((await bo.secrets.reveal('billing/prod')).values.DATABASE_URL, 'postgres://v1');
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

test("an offboarding report lists the references someone made, which outlive them", async () => {
  await ada.secrets.set('billing/prod', { DATABASE_URL: ref('market/prod/DATABASE_URL'), STRIPE_KEY: ref('market/prod/STRIPE_KEY') });
  await max.references.break('billing/prod/STRIPE_KEY');
  const report = await root.members.get(`user:${ADA}`);
  assert.deepEqual(report.references.map((reference) => [reference.holder, reference.state]), [
    ['billing/prod/DATABASE_URL', 'live'], ['billing/prod/STRIPE_KEY', 'broken'],
  ]);
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
    .select({ seq: auditLog.seq, actor: auditLog.actor, decision: auditLog.decision, metadata: auditLog.metadata })
    .from(auditLog)
    .where(and(eq(auditLog.author, author), eq(auditLog.action, action), gte(auditLog.seq, firstSeq)))
    .orderBy(asc(auditLog.seq));
  return rows.map((row) => ({ ...row, metadata: JSON.parse(row.metadata) as Record<string, unknown> }));
}
