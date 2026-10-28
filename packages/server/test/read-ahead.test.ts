// `app_read` (migration 0031, src/db/read-ahead.ts, T135): what a read of values reads before anything else, in one
// call, is exactly what the app's own statements read, row for row, as Drizzle would have read it: the credential
// (`findCredential`), the place (`resolvePath`) and its keys (`environmentSecrets`). Postgres only: SQLite reads them as
// ever. A credential of each kind and none; a place missing, archived, deleted (by its slug and its tombstone's), a
// fork, whose keys its read reads; keys of every nature, a reference, one archived, one with no version yet, the named
// ones and all; and none read for a token that names no credential.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { defineSignin, github, hashToken } from '@coffre/core/identity';
import { eq, like } from 'drizzle-orm';

import { SigninService } from '../src/api/signin.ts';
import { environmentSecrets, findCredential, resolvePath } from '../src/db/queries.ts';
import { readAhead } from '../src/db/read-ahead.ts';
import { clientFor, contextFor, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';
import { postgresOnly } from './db/engine.ts';
import { environments, projects, secrets } from './db/tables.ts';

const POSTGRES = postgresOnly('app_read is a Postgres function: SQLite reads with the statements it stands for');
const ROOT = 'admin@acme.example';
const DEV = 'dev@acme.example';
const CONFIG = defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'gh-id', clientSecret: 'gh-secret' })] });

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
/** A token of each kind, by what it is. */
const tokens: Record<string, string> = {};
/** The slugs deleting left: an environment's, a project's, and its environment's. */
const tombstones = { environment: '', project: '', projectEnvironment: '' };

before(async () => {
  if (POSTGRES.skip) return;
  db = await openTestDatabase();
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const signin = new SigninService({ db: deps.db, chainKey: deps.chainKey, vault: deps.vault, signin: CONFIG });
  deps.signin = signin;
  const root = clientFor(deps, ROOT);
  await root.projects.create('market', { name: 'Market' });
  await root.projects.create('ledger', { name: 'Ledger' });
  for (const path of ['market/dev', 'market/prod', 'market/old', 'ledger/dev']) await root.environments.create(path);
  await root.environments.create('market/feature', { from: 'dev' });
  await root.secrets.set('market/prod', { SOURCE: 'from-prod' });
  await root.secrets.set('market/dev', {
    API_KEY: 'sk_dev_0123456789',
    REGION: { value: 'eu-west-3', plain: true },
    SIGNING_KEY: { value: 'ed25519-private', sensitivity: 'sensitive' },
    LINKED: { ref: 'market/prod/SOURCE' },
    GONE: 'archived-soon',
  });
  await root.secrets.set('market/dev', { GONE: null });
  await root.secrets.set('market/feature', { API_KEY: 'sk_feature_0123' });
  await root.secrets.set('market/old', { OLD: 'kept' });
  await root.environments.update('market/old', { archived: true });
  await root.secrets.set('ledger/dev', { LEDGER_KEY: 'lk' });
  await root.projects.update('ledger', { archived: true });
  // Deleted: an environment, and a project with one; each slug a tombstone's now (`market~deleted-…`, `dev~deleted`).
  await root.environments.create('market/gone');
  await root.secrets.set('market/gone', { GONE_KEY: 'g' });
  await root.environments.update('market/gone', { archived: true });
  await root.environments.delete('market/gone');
  await root.projects.create('old', { name: 'Old' });
  await root.environments.create('old/dev');
  await root.secrets.set('old/dev', { OLD_KEY: 'o' });
  await root.projects.update('old', { archived: true });
  await root.projects.delete('old');
  tombstones.environment = (await db.owner.select({ slug: environments.slug }).from(environments).where(like(environments.slug, 'gone~%')))[0]!.slug;
  tombstones.project = (await db.owner.select({ slug: projects.slug }).from(projects).where(like(projects.slug, 'old~%')))[0]!.slug;
  tombstones.projectEnvironment = (await db.owner.select({ slug: environments.slug }).from(environments).innerJoin(projects, eq(projects.id, environments.projectId)).where(like(projects.slug, 'old~%')))[0]!.slug;
  // A key with no version, as a row written around the app leaves one: its own row, no current version.
  const [api] = await db.owner.select().from(secrets).where(eq(secrets.key, 'API_KEY')).limit(1);
  await db.owner.insert(secrets).values({ ...api!, id: crypto.randomUUID(), key: 'HOLLOW', currentVersionId: null, currentVersion: 0, seal: null });

  await root.members.add(`user:${DEV}`);
  await root.access.set(`user:${DEV}`, { 'market/dev': 'developer' });
  // A browser session, with its sign-in account; a handle and a service token, with none.
  const signedIn = await signin.completeSignin({ provider: 'github', subject: '101', emails: [DEV], name: null }, { requestId: crypto.randomUUID(), sourceIp: null, label: 'browser' });
  if (!signedIn.ok) throw new Error('not signed in');
  tokens.session = signedIn.credential.token;
  tokens.handle = (await signin.issueHandle({ ...(await contextFor(deps, DEV)), personalToken: null }, { label: 'run', expiresInMinutes: 60, paths: ['market/dev'] })).token;
  await root.members.add('token:ci');
  await root.access.set('token:ci', { 'market/dev': 'viewer' });
  tokens.service = (await root.tokens.issue('token:ci', { label: 'ci', expiresInDays: 1 })).token;
  tokens.unknown = 'coffre_use_not-a-handle-anyone-was-given-0123456789abcdefghijk';
  // One change to the policy, the newest the credential's read names.
  await root.environments.protect('market/prod');
});

after(async () => {
  if (POSTGRES.skip) return;
  await resetDatabase(db.owner);
  await db.close();
});

test("a credential read ahead is the credential's own read, of every kind and of none", POSTGRES, async () => {
  for (const [kind, token] of Object.entries(tokens)) {
    const tokenHash = hashToken(token);
    const ahead = await readAhead(deps.db, { tokenHash });
    const own = await findCredential(deps.db, deps.chainKey, { tokenHash });
    const read = await findCredential(deps.db, deps.chainKey, { tokenHash }, ahead!.credential);
    // The database's clock, read by each statement as it ran.
    const at = ({ now: _now, ...rest }: NonNullable<typeof own>) => rest;
    assert.deepEqual(read === null ? null : at(read), own === null ? null : at(own), kind);
    assert.equal(own === null, kind === 'unknown', kind);
    if (kind === 'session') assert.notEqual(own!.subject, null, 'a session has its sign-in account');
    assert.equal(typeof own?.policySeq, kind === 'unknown' ? 'undefined' : 'bigint', kind);
  }
});

test('a place and its keys read ahead are what the read resolves and reads, every key or the named ones', POSTGRES, async () => {
  const paths = [
    { project: 'market', environment: 'dev' },
    // A fork: its parent's slug; its keys, its read's.
    { project: 'market', environment: 'feature' },
    // Archived: the place resolves, its keys read as none.
    { project: 'market', environment: 'old' },
    { project: 'ledger', environment: 'dev' },
    // No such environment, no such project.
    { project: 'market', environment: 'nowhere' },
    { project: 'nowhere', environment: 'dev' },
  ];
  // A deleted place, by the slug it had and by its tombstone's: nothing a read reaches.
  paths.push(
    { project: 'market', environment: 'gone' },
    { project: 'market', environment: tombstones.environment },
    { project: 'old', environment: 'dev' },
    { project: tombstones.project, environment: tombstones.projectEnvironment },
    { project: tombstones.project, environment: 'dev' },
  );
  for (const path of paths) {
    const place = await resolvePath(deps.db, path);
    for (const keys of [undefined, ['API_KEY', 'LINKED', 'HOLLOW', 'MISSING'], [] as string[]]) {
      const ahead = await readAhead(deps.db, { path, keys });
      const what = `${path.project}/${path.environment} ${JSON.stringify(keys)}`;
      assert.deepEqual(ahead!.place, place, what);
      // No environment, or a fork, whose layers its read reads together: the read reads the keys itself.
      if (place?.environment == null || place.environment.parentId !== null) {
        assert.equal(ahead!.secrets, undefined, what);
        continue;
      }
      const rows = (await environmentSecrets(deps.db, place.environment.id)).filter((row) => keys === undefined || keys.includes(row.key));
      assert.deepEqual(ahead!.secrets, rows, what);
    }
  }
  // Every nature, a reference and a key archived or with no version, as the read has them.
  const dev = (await readAhead(deps.db, { path: { project: 'market', environment: 'dev' } }))!.secrets!;
  assert.deepEqual(dev.map((row) => [row.key, row.archivedAt !== null, row.current === null, row.current?.plaintext ?? null, row.current?.sensitive ?? null]), [
    ['API_KEY', false, false, null, false],
    ['GONE', true, false, null, false],
    ['HOLLOW', false, true, null, null],
    ['LINKED', false, true, null, null],
    ['REGION', false, false, 'eu-west-3', false],
    ['SIGNING_KEY', false, false, null, true],
  ]);
});

test('a token that names no credential reads no key: refused on that alone, it costs its probe', POSTGRES, async () => {
  const ahead = await readAhead(deps.db, { tokenHash: hashToken(tokens.unknown!), path: { project: 'market', environment: 'dev' } });
  assert.equal(ahead!.credential, null);
  assert.notEqual(ahead!.place?.environment, null);
  assert.equal(ahead!.secrets, undefined);
  // A credential's own, with the place, reads them.
  assert.ok((await readAhead(deps.db, { tokenHash: hashToken(tokens.handle!), path: { project: 'market', environment: 'dev' } }))!.secrets!.length > 0);
});

test('a personal config is read by its own statements, the credential still ahead', POSTGRES, async () => {
  const tokenHash = hashToken(tokens.handle!);
  const ahead = await readAhead(deps.db, { tokenHash, path: { project: 'market', environment: 'dev@me' }, keys: ['API_KEY'] });
  assert.notEqual(ahead!.credential, null);
  assert.equal(ahead!.place, undefined);
  assert.equal(ahead!.secrets, undefined);
  assert.equal(await readAhead(deps.db, { path: { project: 'market', environment: 'dev@me' } }), null);
});
