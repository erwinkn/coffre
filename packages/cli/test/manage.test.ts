import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { byFolder, createClient, CoffreError } from '@coffre/client';
import { EVERYWHERE } from '@coffre/core/access';

import * as manage from '../src/manage.ts';
import { signedInWithToken } from './fakes.ts';

type Call = { method: string; path: string; body: unknown };

/** A client whose requests go to `answer`, each one kept; and what the command wrote. */
function fixture(answer: (call: Call) => unknown) {
  const calls: Call[] = [];
  const api = createClient({
    url: 'https://coffre.test',
    transport: async (request) => {
      const url = new URL(request.url);
      const text = await request.text();
      const call = { method: request.method, path: decodeURIComponent(url.pathname.slice('/api'.length)) + url.search, body: text === '' ? undefined : JSON.parse(text) };
      calls.push(call);
      const body = answer(call);
      return body instanceof Response ? body : Response.json(body);
    },
  });
  const written = { out: '', err: '' };
  const io = { out: { write: (text: string) => (written.out += text) }, err: { write: (text: string) => (written.err += text), isTTY: true } };
  return { connect: () => api, calls, written, io };
}

const TOKEN = 'coffre_svc_' + 'x'.repeat(40);

test('tokens issue prints the token once, on stdout, and says on a terminal that it will not be shown again', async () => {
  const { connect, calls, written, io } = fixture(() => ({ id: 'tok-1', token: TOKEN, expiresAt: '2027-01-01T00:00:00.000Z', scope: { 'market/dev': 'developer' } }));
  await manage.tokensIssue(connect, ['deploy-slides', '--label', 'CI', '--expires-in', '30'], io);
  assert.deepEqual(calls, [{ method: 'POST', path: '/members/token:deploy-slides/tokens', body: { expiresInDays: 30, label: 'CI' } }]);
  assert.equal(written.out, `${TOKEN}\n`);
  assert.equal(written.err, "coffre: service:deploy-slides's bearer token tok-1, reaching developer on market/dev, until 2027-01-01. It is shown this once\n");
  assert.ok(!written.err.includes(TOKEN));
});

test('tokens issue --output-file writes a new 0600 file, prints no token, and never overwrites', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-tokens-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'token');
  const { connect, written, io } = fixture(() => ({ id: 'tok-1', token: TOKEN, expiresAt: '2027-01-01T00:00:00.000Z', scope: { 'market/dev': 'developer' } }));
  await manage.tokensIssue(connect, ['deploy-slides', '--output-file', path], io);
  assert.equal(readFileSync(path, 'utf8'), `${TOKEN}\n`);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.ok(!written.out.includes(TOKEN) && !written.err.includes(TOKEN));
  assert.match(written.out, /^wrote service:deploy-slides's bearer token tok-1, reaching developer on market\/dev, until 2027-01-01, to .*token, readable by you alone/);

  // A file there already: refused before any token is made.
  const again = fixture(() => assert.fail('no token is issued'));
  await assert.rejects(manage.tokensIssue(again.connect, ['deploy-slides', '--output-file', path], again.io), /exists already: the token goes only into a new file/);
  assert.equal(again.calls.length, 0);

  // Refused by the instance: the file made for it goes.
  const refused = fixture(() => Response.json({ error: 'forbidden', message: 'no' }, { status: 403 }));
  const other = join(dir, 'other');
  await assert.rejects(manage.tokensIssue(refused.connect, ['deploy-slides', '--output-file', other], refused.io), CoffreError);
  assert.equal(existsSync(other), false);
});

test('tokens issue takes 1 to 366 days, 90 unless told', async () => {
  const { connect, calls, io } = fixture(() => ({ id: 't', token: TOKEN, expiresAt: '2027-01-01T00:00:00.000Z', scope: {} }));
  await manage.tokensIssue(connect, ['token:deploy'], io);
  assert.deepEqual(calls[0]!.body, { expiresInDays: 90, label: null });
  for (const bad of ['0', '367', '1.5', 'soon']) {
    await assert.rejects(manage.tokensIssue(connect, ['deploy', '--expires-in', bad], io), manage.UsageError);
  }
});

test('tokens issue --scope narrows what it reaches, by path and role, repeated or a comma list; all the account holds unless told', async () => {
  const { connect, calls, io } = fixture(() => ({ id: 't', token: TOKEN, expiresAt: '2027-01-01T00:00:00.000Z', scope: {} }));
  await manage.tokensIssue(connect, ['deploy', '--scope', 'market/dev=developer,market/prod=viewer', '--scope', 'billing=auditor'], io);
  assert.deepEqual(calls[0]!.body, { expiresInDays: 90, label: null, scope: { 'market/dev': 'developer', 'market/prod': 'viewer', billing: 'auditor' } });
  for (const bad of ['market/dev', 'market/dev=Reader', '=viewer', 'a=b=c']) {
    await assert.rejects(manage.tokensIssue(connect, ['deploy', '--scope', bad], io), manage.UsageError, bad);
  }
  assert.equal(calls.length, 1, 'nothing asked for a bad scope');
});

const PERSONAL = 'coffre_pat_' + 'x'.repeat(40);
/** What `/me` answers for Ada, as the personal token commands ask who they are about. */
const ADA_ME = { principal: { type: 'user', id: 'ada@acme.example' } };

test('tokens issue with no service makes a personal token: its label and scope said, an hour unless told, a week at most', async () => {
  const { connect, calls, written, io } = fixture((call) =>
    call.path === '/me' ? ADA_ME : { id: 'pat-1', token: PERSONAL, expiresAt: '2026-10-17T18:30:00.000Z', scope: { 'market/dev': 'viewer' } });
  await manage.tokensIssue(connect, ['--label', 'cursor-agent', '--scope', 'market/dev=viewer', '--expires-in', '4h'], io);
  assert.deepEqual(calls.map((call) => [call.method, call.path, call.body]), [
    ['GET', '/me', undefined],
    ['POST', '/members/user:ada@acme.example/tokens', { label: 'cursor-agent', expiresInMinutes: 240, scope: { 'market/dev': 'viewer' } }],
  ]);
  assert.equal(written.out, `${PERSONAL}\n`);
  assert.equal(written.err, 'coffre: your personal token pat-1 "cursor-agent", acting as you on viewer on market/dev, until 2026-10-17 18:30 UTC. It is shown this once\n');

  calls.length = 0;
  await manage.tokensIssue(connect, ['--label', 'script', '--scope', 'market/dev=viewer'], io);
  assert.equal((calls[1]!.body as { expiresInMinutes: number }).expiresInMinutes, 60);
  for (const [given, minutes] of [['30m', 30], ['2d', 2880], ['7d', 10080], ['1', 1440]] as const) {
    calls.length = 0;
    await manage.tokensIssue(connect, ['--label', 'script', '--scope', 'market/dev=viewer', '--expires-in', given], io);
    assert.equal((calls[1]!.body as { expiresInMinutes: number }).expiresInMinutes, minutes, given);
  }
  for (const bad of ['0m', '8d', '10081m', '4w', 'soon', '1.5h']) {
    await assert.rejects(manage.tokensIssue(connect, ['--label', 'script', '--scope', 'market/dev=viewer', '--expires-in', bad], io), manage.UsageError, bad);
  }
});

test('tokens with no service lists your personal tokens, to the minute; tokens revoke <id> ends one, shown first', async () => {
  const token = { id: 'pat-1', label: 'cursor-agent', hint: 'coffre_pat_…abcd', createdAt: '2026-10-17T14:30:00.000Z', createdBy: 'ada@acme.example', expiresAt: '2026-10-17T18:30:00.000Z', lastUsedAt: null, lastUsedIp: null, scope: { 'market/dev': 'viewer' } };
  const { connect, calls, written, io } = fixture((call) => (call.path === '/me' ? ADA_ME : call.method === 'DELETE' ? { revoked: true } : { tokens: [token] }));
  await manage.tokens(connect, [], io);
  assert.equal(written.out, 'pat-1  …coffre_pat_…abcd  cursor-agent      expires 2026-10-17 18:30 UTC  last used never  reaches viewer on market/dev\n');
  assert.deepEqual(calls.map((call) => call.path), ['/me', '/members/user:ada@acme.example/tokens']);

  written.out = '';
  await manage.tokensRevoke(connect, ['pat-1'], io);
  assert.match(written.out, /^would revoke your personal token pat-1, …coffre_pat_…abcd "cursor-agent", last used never: whatever uses it stops at once\./);
  assert.ok(!calls.some((call) => call.method === 'DELETE'));
  written.out = '';
  await manage.tokensRevoke(connect, ['pat-1', '--apply'], io);
  assert.equal(written.out, 'revoked your personal token pat-1, …coffre_pat_…abcd "cursor-agent", last used never\n');
  assert.equal(calls.at(-1)!.path, '/members/user:ada@acme.example/tokens/pat-1');
  await assert.rejects(manage.tokensRevoke(connect, ['pat-2', '--apply'], io), /you hold no personal token pat-2/);

  // A service account holds none.
  const service = fixture(() => ({ principal: { type: 'service', id: 'ci' } }));
  await assert.rejects(manage.tokens(service.connect, [], service.io), /a service account holds no personal token/);
});

const LISTED = {
  tokens: [{ id: 'tok-1', label: 'CI', hint: 'abcd', createdAt: '2026-10-01T00:00:00Z', createdBy: 'root@acme.example', expiresAt: '2027-01-01T00:00:00Z', lastUsedAt: null, lastUsedIp: null, scope: { 'market/dev': 'viewer' } }],
};

test('tokens revoke shows what it would end, and ends it only with --apply', async () => {
  const preview = fixture(() => LISTED);
  await manage.tokensRevoke(preview.connect, ['deploy', 'tok-1'], preview.io);
  assert.deepEqual(preview.calls.map(({ method }) => method), ['GET']);
  assert.match(preview.written.out, /^would revoke service:deploy's bearer token tok-1, …abcd "CI", last used never: whatever uses it stops at once\.\nNothing changed\. Re-run with --apply/);

  const applied = fixture(({ method }) => (method === 'GET' ? LISTED : { revoked: true }));
  await manage.tokensRevoke(applied.connect, ['deploy', 'tok-1', '--apply'], applied.io);
  assert.deepEqual(applied.calls.map(({ method, path }) => `${method} ${path}`), ['GET /members/token:deploy/tokens', 'DELETE /members/token:deploy/tokens/tok-1']);
  await assert.rejects(manage.tokensRevoke(preview.connect, ['deploy', 'tok-9'], preview.io), /service:deploy holds no bearer token tok-9: `coffre tokens deploy` lists them/);
});

test('admit makes a member, and for a service names the next steps: grant, then trust or a token', async () => {
  const { connect, calls, written, io } = fixture(() => ({ member: 'token:deploy-slides', instanceRole: 'member', scope: EVERYWHERE, created: true }));
  await manage.admit(connect, ['deploy-slides', '--service'], io);
  assert.deepEqual(calls, [{ method: 'PUT', path: '/members/token:deploy-slides', body: {} }]);
  assert.match(written.out, /^admitted service:deploy-slides\n  next: coffre grant <project> deploy-slides --role viewer \[--env <env>\] --service,\n        then let its CI sign in by OIDC, coffre trust deploy-slides --github … --apply,\n        or, for CI without OIDC, give it a bearer token, coffre tokens issue deploy-slides\n$/);

  const DEV_ONLY = { projects: { except: ['billing'] }, environments: { only: ['dev', 'staging'] } };
  const person = fixture(() => ({ member: 'user:ada@acme.example', instanceRole: 'developer', scope: DEV_ONLY, created: false }));
  await manage.admit(person.connect, ['ada@acme.example', '--role', 'developer', '--except-projects', 'billing', '--environments', 'dev, staging'], person.io);
  assert.deepEqual(person.calls[0]!.body, { role: 'developer', scope: DEV_ONLY });
  assert.equal(person.written.out, 'user:ada@acme.example is a member as Developer, All projects but billing · dev, staging only now\n');
  const admin = fixture(() => ({ member: 'user:ada@acme.example', instanceRole: 'admin', scope: EVERYWHERE, created: true }));
  await manage.admit(admin.connect, ['ada@acme.example', '--role', 'admin'], admin.io);
  assert.deepEqual(admin.calls[0]!.body, { role: 'admin' });
  assert.equal(admin.written.out, 'admitted user:ada@acme.example as Admin\n');
  for (const [args, refusal] of [
    [['deploy', '--service', '--role', 'developer'], /a service account holds project grants only/],
    [['ada@acme.example', '--role', 'boss'], /no instance role "boss"/],
    [['ada@acme.example', '--environments', 'dev'], /a scope goes with a role/],
    [['ada@acme.example', '--role', 'developer', '--projects', 'a', '--except-projects', 'b'], /--projects or --except-projects, not both/],
  ] as const) {
    await assert.rejects(manage.admit(person.connect, [...args], person.io), refusal);
  }
  // A service account with its first grants: one call, and no next step to grant it.
  const granted = fixture(() => ({ member: 'token:deploy', instanceRole: 'member', scope: EVERYWHERE, created: true, changes: { 'market/dev': 'created', 'market/prod': 'created' } }));
  await manage.admit(granted.connect, ['deploy', '--service', '--grant', 'market/dev=developer,market/prod=viewer'], granted.io);
  assert.deepEqual(granted.calls, [{ method: 'PUT', path: '/members/token:deploy', body: { access: { 'market/dev': 'developer', 'market/prod': 'viewer' } } }]);
  assert.equal(granted.written.out, 'admitted service:deploy, holding developer on market/dev, viewer on market/prod\n');
  for (const [args, refusal] of [
    [['ada@acme.example', '--grant', 'market=viewer'], /--grant comes with a service account/],
    [['deploy', '--service', '--grant', 'market=Boss'], /--grant takes <project>\[\/<environment>\]=<role>/],
  ] as const) {
    await assert.rejects(manage.admit(granted.connect, [...args], granted.io), refusal);
  }
  // A name that says it is a service account's is one, with --service or not: service:deploy, or token:deploy as before.
  for (const name of ['service:deploy', 'token:deploy']) {
    const service = fixture(() => ({ member: 'token:deploy', instanceRole: 'member', scope: EVERYWHERE, created: false }));
    await manage.admit(service.connect, [name], service.io);
    assert.deepEqual(service.calls, [{ method: 'PUT', path: '/members/token:deploy', body: {} }]);
    assert.equal(service.written.out, 'service:deploy is a member already\n');
  }
});

test('revoke takes a grant away, and says when there was none', async () => {
  const { connect, calls, written, io } = fixture(() => ({ changes: { 'market/prod': 'revoked' } }));
  await manage.revoke(connect, ['market', 'deploy', '--env', 'prod', '--service'], io);
  assert.deepEqual(calls, [{ method: 'PATCH', path: '/access/token:deploy', body: { 'market/prod': null } }]);
  assert.equal(written.out, "revoked service:deploy's grant on market/prod\n");
  const none = fixture(() => ({ changes: { market: 'unchanged' } }));
  await manage.revoke(none.connect, ['market', 'ada@acme.example'], none.io);
  assert.equal(none.written.out, 'user:ada@acme.example held no grant on market: nothing changed\n');
});

test("a grant is on a project or an environment: '*' says what reaches every project instead", async () => {
  const { connect, calls, io } = fixture(() => ({ changes: {} }));
  await assert.rejects(manage.revoke(connect, ['*', 'ada@acme.example', '--env', 'dev'], io), /a person reaches every project by their instance role, `coffre admit <email> --role <role>`/);
  assert.deepEqual(calls, []);
  await assert.rejects(manage.revoke(connect, ['README.md', 'package.json', 'ada@acme.example'], io), /^Error: too many arguments: ada@acme.example$/);
  await assert.rejects(manage.revoke(connect, ['market'], io), /name <principal>/);
});

test('giving an environment a new slug says who its instance roles reach now', async () => {
  const { connect, written, io } = fixture(() => ({ environment: { slug: 'dev', name: 'dev', archivedAt: null } }));
  await manage.environmentsRename(connect, ['slides/staging', '--slug', 'dev'], io);
  assert.equal(written.out, 'slides/staging is now slides/dev\n  instance roles scoped to staging no longer reach it; those scoped to dev do\n');
});

test('projects and environments: create, rename and archive, each one request, by slug alone', async () => {
  const project = { slug: 'slides', name: 'Slides', archivedAt: null };
  const { connect, calls, written, io } = fixture(({ method, path }) =>
    path.split('/').length === 4
      ? method === 'PUT'
        ? { environment: { slug: 'prod', name: 'prod', archivedAt: null }, created: true }
        : { environment: { slug: 'production', name: 'Production', archivedAt: null } }
      : method === 'PUT'
        ? { project, created: true }
        : { project: { ...project, slug: 'deck' } },
  );
  await manage.projectsCreate(connect, ['slides', '--name', 'Slides'], io);
  await manage.environmentsCreate(connect, ['slides/prod'], io);
  await manage.projectsRename(connect, ['slides', '--slug', 'deck'], io);
  await manage.environmentsRename(connect, ['deck/prod', '--slug', 'production', '--name', 'Production'], io);
  await manage.projectsArchive(connect, ['deck'], true, io);
  await manage.environmentsArchive(connect, ['deck/production'], false, io);
  // A name only as an instance before 0.6.2 wants one: the slug, whatever --name says.
  assert.deepEqual(calls, [
    { method: 'PUT', path: '/projects/slides', body: { name: 'slides' } },
    { method: 'PUT', path: '/projects/slides/prod', body: { name: 'prod' } },
    { method: 'PATCH', path: '/projects/slides', body: { slug: 'deck' } },
    { method: 'PATCH', path: '/projects/deck/prod', body: { slug: 'production' } },
    { method: 'PATCH', path: '/projects/deck', body: { archived: true } },
    { method: 'PATCH', path: '/projects/deck/production', body: { archived: false } },
  ]);
  assert.equal(
    written.out,
    'created slides\ncreated slides/prod\nslides is now deck\ndeck/prod is now deck/production\n  instance roles scoped to prod no longer reach it; those scoped to production do\n' +
      'archived deck: `coffre projects unarchive deck` brings it back\nunarchived deck/production\n',
  );
  assert.equal(written.err, 'coffre: --name is ignored: a project goes by its slug\ncoffre: --name is ignored: an environment goes by its slug\n');
  await assert.rejects(manage.projectsRename(connect, ['deck'], io), /give it a new --slug/);
  // --name alone, as a script from before 0.6.2 passes it: said to be ignored, and nothing sent.
  const sent = calls.length;
  await manage.projectsRename(connect, ['deck', '--name', 'Deck'], io);
  await manage.environmentsRename(connect, ['deck/production', '--name', 'Production'], io);
  assert.equal(calls.length, sent);
  assert.match(written.err, /--name is ignored: a project goes by its slug\ncoffre: --name is ignored: an environment goes by its slug\n$/);
  await assert.rejects(manage.environmentsCreate(connect, ['deck'], io), /expected <project>\/<environment>, not "deck"/);
});

test('projects delete and environments delete show what they would take, and delete only with --apply', async () => {
  const deletion = (path: string, dryRun: boolean) => ({
    dryRun,
    deletion: {
      path,
      tombstone: `${path.split('/').at(-1)}~deleted-2026-10-05`,
      environments: path.includes('/') ? ['prod'] : ['dev', 'prod'],
      keys: 3,
      versions: 1,
      grants: [{ member: 'token:ci-deploy', place: 'slides/prod', role: 'viewer' }],
      references: [{ holder: 'deck/prod/API_KEY', source: 'slides/prod/API_KEY' }],
      stranded: ['token:ci-deploy'],
    },
  });
  const { connect, calls, written, io } = fixture(({ path }) =>
    deletion(path.replace(/^\/projects\//, '').replace(/\?.*$/, ''), path.endsWith('?dryRun=1')),
  );
  await manage.placeDelete(connect, ['slides'], false, io);
  assert.equal(
    written.out,
    'would delete slides, for good:\n' +
      '  erased: 1 version, in dev, prod\n' +
      '  revoked: 1 grant, service:ci-deploy (viewer on slides/prod)\n' +
      '  ended: 1 reference, deck/prod/API_KEY → slides/prod/API_KEY\n' +
      '  kept, names only: slides~deleted-2026-10-05 and its 3 keys, for the audit log\n' +
      '  slides would be free to use again\n' +
      '  service:ci-deploy would hold nothing anywhere: `coffre offboard ci-deploy --service` removes them\n' +
      'Backups taken before the deletion still hold the encrypted values.\n' +
      'Nothing changed. Re-run with --apply to delete it.\n',
  );
  written.out = '';
  await manage.placeDelete(connect, ['slides/prod', '--apply'], true, io);
  assert.match(written.out, /^deleted slides\/prod, for good:\n/);
  assert.match(written.out, /  prod is free to use again\n/);
  assert.doesNotMatch(written.out, /Re-run/);
  assert.deepEqual(calls.map(({ method, path }) => `${method} ${path}`), ['DELETE /projects/slides?dryRun=1', 'DELETE /projects/slides/prod']);
  await assert.rejects(manage.placeDelete(connect, ['slides'], true, io), /expected <project>\/<environment>, not "slides"/);
});

test("a secret's key: renamed with its versions, archived and back", async () => {
  const { connect, calls, written, io } = fixture(({ body }) => ({ key: (body as { key?: string }).key ?? 'API_KEY', archived: false }));
  await manage.renameSecret(connect, ['market/prod/API_TOKEN', 'API_KEY'], io);
  await manage.archiveSecret(connect, ['market/prod/API_KEY'], true, io);
  assert.deepEqual(calls, [
    { method: 'PATCH', path: '/secrets/market/prod/API_TOKEN', body: { key: 'API_KEY' } },
    { method: 'PATCH', path: '/secrets/market/prod/API_KEY', body: { archived: true } },
  ]);
  assert.match(written.out, /^market\/prod\/API_TOKEN is now market\/prod\/API_KEY, its versions with it\narchived market\/prod\/API_KEY: `coffre unarchive market\/prod\/API_KEY` brings it back\n$/);
  await assert.rejects(manage.renameSecret(connect, ['market/prod', 'X'], io), /expected <project>\/<environment>\/<KEY>/);
});

test('move files a project or a secret in a folder, or takes it out with --none', async () => {
  const { connect, calls, written, io } = fixture(({ path }) =>
    path.startsWith('/projects') ? { project: { slug: 'acme', name: 'Acme', archivedAt: null, folder: 'Clients' } } : { key: 'STRIPE_KEY', archived: false, folder: null });
  await manage.move(connect, ['acme', 'Clients'], io);
  await manage.move(connect, ['market/prod/STRIPE_KEY', '--none'], io);
  assert.deepEqual(calls, [
    { method: 'PATCH', path: '/projects/acme', body: { folder: 'Clients' } },
    { method: 'PATCH', path: '/secrets/market/prod/STRIPE_KEY', body: { folder: null } },
  ]);
  assert.equal(written.out, 'acme is in Clients/ now\nmarket/prod/STRIPE_KEY is in no folder now\n');
  await assert.rejects(manage.move(connect, ['acme'], io), /name a folder, or --none/);
  await assert.rejects(manage.move(connect, ['acme', 'Clients', '--none'], io), /not both/);
  await assert.rejects(manage.move(connect, ['market/prod', 'x'], io), /expected <project>\/<environment>\/<KEY>/);
});

test('fork makes the new environment from its sibling, and says how many keys it copied', async () => {
  const { connect, calls, written, io } = fixture(() => ({ environment: { slug: 'staging', name: 'Staging', archivedAt: null }, created: true, forked: { from: 'prod', keys: 3 } }));
  await manage.fork(connect, ['market/prod', 'staging'], io);
  assert.deepEqual(calls, [{ method: 'PUT', path: '/projects/market/staging', body: { name: 'staging', from: 'prod' } }]);
  assert.equal(written.out, 'created market/staging from market/prod: 3 keys, values copied, no history\n');
  await assert.rejects(manage.fork(connect, ['market/prod', 'other/staging'], io), /name the new environment alone/);
  await assert.rejects(manage.fork(connect, ['market', 'staging'], io), /expected <project>\/<environment>/);
});

test('references lists what a place lends and holds, and who reads through each', async () => {
  const listed = {
    id: 'r1', holder: 'billing/prod/DATABASE_URL', source: 'market/prod/DATABASE_URL', state: 'live', version: 3,
    createdBy: 'user:ada@acme.example', createdAt: '2026-10-05T09:00:00.000Z', endedBy: null, endedAt: null,
    readers: ['user:bo@acme.example', 'token:deploy'], canBreak: true,
  };
  const { connect, calls, written, io } = fixture(() => ({ references: [listed] }));
  await manage.references(connect, ['market/prod'], io);
  assert.deepEqual(calls, [{ method: 'GET', path: '/references?path=market%2Fprod', body: undefined }]);
  assert.equal(written.out, 'billing/prod/DATABASE_URL → market/prod/DATABASE_URL\n  made by ada@acme.example on 2026-10-05\n  read through by bo@acme.example, service:deploy\n');

  // Breaking shows who stops reading, and breaks only with --apply.
  const breaking = fixture(({ method }) => (method === 'GET' ? { references: [listed] } : { reference: { ...listed, state: 'broken' } }));
  await manage.referencesBreak(breaking.connect, ['billing/prod/DATABASE_URL'], breaking.io);
  assert.match(breaking.written.out, /breaking it stops bo@acme\.example, service:deploy reading it there[\s\S]*Re-run with --apply to break it/);
  assert.deepEqual(breaking.calls.map((call) => call.method), ['GET']);
  await manage.referencesBreak(breaking.connect, ['billing/prod/DATABASE_URL', '--apply'], breaking.io);
  assert.deepEqual(breaking.calls.at(-1), { method: 'DELETE', path: '/secrets/billing/prod/DATABASE_URL/reference', body: undefined });
  assert.match(breaking.written.out, /broke billing\/prod\/DATABASE_URL: it no longer reads market\/prod\/DATABASE_URL\n$/);
});

test('fork --reference makes references, and names the keys it copied instead', async () => {
  const { connect, calls, written, io } = fixture(() => ({
    environment: { slug: 'qa', name: 'qa', archivedAt: null }, created: true, forked: { from: 'staging', keys: 3, references: 2, copied: ['STRIPE_KEY'], inherits: false },
  }));
  await manage.fork(connect, ['market/staging', 'qa', '--reference'], io);
  assert.deepEqual(calls[0]!.body, { name: 'qa', from: 'staging', references: true });
  assert.equal(written.out, 'created market/qa from market/staging: 3 keys, 2 references, and 1 copied: STRIPE_KEY, whose source you read only through staging\n  whoever reads market/qa reads those values through them, as they change\n');
});

test('fork --inherit copies nothing, says what its readers need, and is no fork as references', async () => {
  const { connect, calls, written, io } = fixture(({ method }) => method === 'GET'
    ? { permissions: [], keys: [], parents: [], rotateAfterDays: null }
    : { environment: { slug: 'prod-eu', name: 'prod-eu', archivedAt: null }, created: true, forked: { from: 'prod', keys: 0, references: 0, copied: [], inherits: true } });
  await manage.fork(connect, ['market/prod', 'prod-eu', '--inherit'], io);
  assert.deepEqual(calls.map((call) => [call.method, call.path, call.body]), [
    ['GET', '/secrets/market/prod', undefined],
    ['PUT', '/projects/market/prod-eu', { name: 'prod-eu', from: 'prod', inherit: true }],
  ]);
  assert.equal(written.out, "created market/prod-eu, inheriting market/prod: nothing copied\n  it reads prod's keys as they change, but for those it sets or removes; its readers need read on prod for those\n");
  await assert.rejects(manage.fork(connect, ['market/prod', 'x', '--inherit', '--reference'], io), /--reference or --inherit, not both/);
  assert.equal(calls.length, 2);

  // An instance before 0.7 would copy: refused before anything is made.
  const old = fixture(({ method }) => (method === 'GET' ? { permissions: [], keys: [], rotateAfterDays: null } : assert.fail('nothing is made')));
  await assert.rejects(manage.fork(old.connect, ['market/prod', 'prod-eu', '--inherit'], old.io), /older than forks that inherit \(coffre 0\.7\)/);
  // And an answer that does not say it inherits is no success.
  const copied = fixture(({ method }) => method === 'GET'
    ? { permissions: [], keys: [], parents: [], rotateAfterDays: null }
    : { environment: { slug: 'prod-eu', name: 'prod-eu', archivedAt: null }, created: true, forked: { from: 'prod', keys: 3, references: 0, copied: [] } });
  await assert.rejects(manage.fork(copied.connect, ['market/prod', 'prod-eu', '--inherit'], copied.io), /does not inherit from market\/prod/);
});

test("reset and remove, in a fork: back to the parent's value, or without its key, and --undo for each", async () => {
  const { connect, calls, written, io } = fixture(({ method, path, body }) => {
    if (method === 'GET') return { permissions: [], keys: [], parents: path.includes('prod-eu') ? ['prod'] : [], rotateAfterDays: null };
    if (path.startsWith('/secrets/')) return { key: 'DATABASE_URL', archived: (body as { inherit: boolean }).inherit, folder: null, from: 'prod' };
    return { operationId: 'op', keys: { SENTRY_DSN: (body as Record<string, unknown>).SENTRY_DSN === true ? 'dismissed' : 'restored' } };
  });
  await manage.resetSecret(connect, ['market/prod-eu/DATABASE_URL'], io);
  await manage.resetSecret(connect, ['market/prod-eu/DATABASE_URL', '--undo'], io);
  assert.deepEqual(calls.map((call) => call.body), [{ inherit: true }, { inherit: false }]);
  assert.equal(written.out, [
    "market/prod-eu/DATABASE_URL reads market/prod's value again; its own is kept: `coffre reset market/prod-eu/DATABASE_URL --undo` serves it again",
    'market/prod-eu/DATABASE_URL overrides market/prod again, with the value it had',
    '',
  ].join('\n'));

  written.out = '';
  await manage.removeSecret(connect, ['market/prod-eu/SENTRY_DSN'], io);
  await manage.removeSecret(connect, ['market/prod-eu/SENTRY_DSN', '--undo'], io);
  assert.deepEqual(calls.slice(2).map((call) => [call.method, call.path, call.body]), [
    ['GET', '/secrets/market/prod-eu', undefined],
    ['PATCH', '/projects/market/prod-eu/dismissals', { SENTRY_DSN: true }],
    ['GET', '/secrets/market/prod-eu', undefined],
    ['PATCH', '/projects/market/prod-eu/dismissals', { SENTRY_DSN: null }],
  ]);
  assert.match(written.out, /^market\/prod-eu does without its parent's SENTRY_DSN: `coffre remove market\/prod-eu\/SENTRY_DSN --undo` inherits it again\nmarket\/prod-eu inherits SENTRY_DSN again/);
  // Outside a fork, remove is no dismissal: archive is what takes a key out.
  await assert.rejects(manage.removeSecret(connect, ['market/prod/SENTRY_DSN'], io), /market\/prod inherits from no environment: `coffre archive market\/prod\/SENTRY_DSN`/);
});

test("personal lists a project's personal configs, whose and of what, with their key names and the slug that deletes each", async () => {
  const { connect, calls, written, io } = fixture(() => ({
    configs: [{ owner: 'user:ada@acme.example', of: 'dev', slug: 'dev-p-3f9c2a1b', keys: ['DATABASE_URL'], archived: false, createdAt: '2026-10-17T00:00:00.000Z' }],
  }));
  await manage.personal(connect, ['market'], io);
  assert.deepEqual(calls, [{ method: 'GET', path: '/personal/market', body: undefined }]);
  assert.equal(written.out, 'market/dev@ada@acme.example\tmarket/dev-p-3f9c2a1b\n  DATABASE_URL\n');
});

test('missing lists what siblings have, and dismiss --all dismisses each in one call', async () => {
  const listing = { missing: [{ key: 'SENTRY_DSN', in: ['prod', 'staging'], folder: null }, { key: 'STRIPE_KEY', in: ['staging'], folder: 'stripe' }], dismissed: [] };
  const { connect, calls, written, io } = fixture(({ method, body }) =>
    method === 'GET' ? listing : { operationId: 'op', keys: Object.fromEntries(Object.keys(body as object).map((key) => [key, 'dismissed'])) });
  await manage.missing(connect, ['market/dev'], io);
  assert.match(written.out, /^SENTRY_DSN\s+in prod, staging\nSTRIPE_KEY\s+in staging\n\n`coffre set market\/dev\/<KEY>` adds one/);
  await manage.missingDismiss(connect, ['market/dev', '--all'], true, io);
  assert.deepEqual(calls.at(-1), { method: 'PATCH', path: '/projects/market/dev/dismissals', body: { SENTRY_DSN: true, STRIPE_KEY: true } });
  await manage.missingDismiss(connect, ['market/dev/SENTRY_DSN'], false, io);
  assert.deepEqual(calls.at(-1)!.body, { SENTRY_DSN: null });
  await assert.rejects(manage.missingDismiss(connect, ['market/dev'], true, io), /expected <project>\/<environment>\/<KEY>/);
});

test('missing --check is a gate: it lists what is missing and fails, passes when nothing is, and a dismissed key never fails it', async () => {
  let listing = { missing: [{ key: 'SENTRY_DSN', in: ['prod', 'staging'], folder: null }], dismissed: [] as unknown[] };
  const { connect, written, io } = fixture(() => listing);
  await assert.rejects(manage.missing(connect, ['market/dev', '--check'], io), (error: Error) =>
    error instanceof manage.CheckFailed && /^market\/dev lacks a key its sibling environments have: `coffre set market\/dev\/<KEY>` adds one/.test(error.message));
  assert.match(written.out, /^SENTRY_DSN\s+in prod, staging\n$/, 'the key, and the advice once, in the error');
  written.out = '';
  await assert.rejects(manage.missing(connect, ['market/dev', '--check', '--json'], io), /lacks a key/);
  assert.deepEqual(JSON.parse(written.out), listing.missing);

  listing = { missing: [], dismissed: [{ key: 'SENTRY_DSN', in: ['prod'], folder: null, dismissedBy: 'ada@acme.example', dismissedAt: '2026-10-16T00:00:00.000Z' }] };
  written.out = '';
  await manage.missing(connect, ['market/dev', '--check'], io);
  assert.equal(written.out, 'market/dev has every key of its sibling environments, but 1 dismissed: --dismissed lists them\n');
  await assert.rejects(manage.missing(connect, ['market/dev', '--check', '--dismissed'], io), manage.UsageError);
});

test('the CLI exits 1 on missing --check only once all it printed is out, through a pipe too', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'coffre-missing-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  // Far past a pipe's buffer: exiting at once would cut the JSON short.
  const missing = Array.from({ length: 2000 }, (_, i) => ({ key: `KEY_${String(i).padStart(4, '0')}`, in: ['prod', 'staging'], folder: null }));
  const server = createServer((req, res) => {
    assert.equal(req.url, '/api/projects/market/dev/missing');
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ missing, dismissed: [] }));
  });
  t.after(() => new Promise<void>((resolve) => (server.close(() => resolve()), server.closeAllConnections())));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  signedInWithToken(directory, `http://127.0.0.1:${address.port}`, 'coffre_svc_test');
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_'))), HOME: directory, COFFRE_STATE_DIR: directory };
  for (const json of [true, false]) {
    const child = spawn(process.execPath, ['--conditions=coffre:source', new URL('../src/main.ts', import.meta.url).pathname, 'missing', 'market/dev', '--check', ...(json ? ['--json'] : [])], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000 });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (data: string) => (stdout += data));
    child.stderr.setEncoding('utf8').on('data', (data: string) => (stderr += data));
    const [code] = await once(child, 'close');
    assert.equal(code, 1, stderr);
    assert.match(stderr, /^coffre: market\/dev lacks 2000 keys its sibling environments have: /);
    if (json) assert.deepEqual(JSON.parse(stdout), missing);
    else assert.equal(stdout.split('\n').length, missing.length + 1);
  }
});

test('lists group by folder: the unfiled first, then each folder by name, each in its own order', () => {
  const rows = [{ key: 'B', folder: 'stripe' }, { key: 'A', folder: null }, { key: 'C', folder: 'database' }, { key: 'D', folder: 'stripe' }];
  assert.deepEqual(byFolder(rows).map(([folder, keys]) => [folder, keys.map((row) => row.key)]), [
    [null, ['A']], ['database', ['C']], ['stripe', ['B', 'D']],
  ]);
  assert.deepEqual(byFolder([{ key: 'A', folder: 'x' }]).map(([folder]) => folder), ['x']);
});

test("sessions revoke warns when it is this CLI's own, and identities unlink says what ends with it", async () => {
  const listed = {
    sessions: [{ id: 'ses-1', kind: 'cli', label: 'coffre CLI on laptop', hint: 'wxyz', provider: 'github', createdAt: '2026-10-01T00:00:00Z', expiresAt: '2026-10-31T00:00:00Z', lastUsedAt: '2026-10-04T00:00:00Z', lastUsedIp: null, current: true }],
  };
  const preview = fixture(() => listed);
  await manage.sessionsRevoke(preview.connect, ['ses-1'], preview.io);
  assert.match(preview.written.out, /would sign out your cli session ses-1, "coffre CLI on laptop", last used 2026-10-04: the one this command runs with, so this CLI signs out too\.\nNothing changed/);
  await manage.sessions(preview.connect, ['--json'], preview.io);
  assert.deepEqual(JSON.parse(preview.written.out.slice(preview.written.out.indexOf('['))), listed.sessions);

  const identities = { identities: [{ id: 'idn-1', provider: 'github', email: 'ada@acme.example', createdAt: '2026-01-01T00:00:00Z', lastSignInAt: null }] };
  const unlink = fixture(({ method }) => (method === 'GET' ? identities : { unlinked: true }));
  await manage.identitiesUnlink(unlink.connect, ['idn-1', '--apply'], unlink.io);
  assert.deepEqual(unlink.calls.map(({ method, path }) => `${method} ${path}`), ['GET /identities', 'DELETE /identities/idn-1']);
  assert.equal(unlink.written.out, 'unlinked your github account ada@acme.example (idn-1), and ended its sessions\n');
});

test('apps lists the MCP clients you connected, unverified ones said so, and apps revoke disconnects one only with --apply', async () => {
  const listed = {
    apps: [
      { id: 'c0nn-1', name: 'Claude', host: 'claude.ai', registration: 'cimd', scopes: ['read'], createdAt: '2026-10-01T00:00:00Z', lastUsedAt: '2026-10-04T00:00:00Z', lastUsedIp: null, expiresAt: '2026-10-31T00:00:00Z' },
      { id: 'c0nn-2', name: 'Cursor', host: null, registration: 'dcr', scopes: ['read', 'write'], createdAt: '2026-10-02T00:00:00Z', lastUsedAt: null, lastUsedIp: null, expiresAt: '2026-11-01T00:00:00Z' },
    ],
  };
  const on = { features: { mcp: 'https://secrets.acme.example/mcp', workloads: false } };
  const answer = ({ path }: Call) => (path === '/me' ? on : listed);
  const list = fixture(answer);
  await manage.apps(list.connect, [], list.io);
  assert.equal(
    list.written.out,
    'c0nn-1  Claude                        claude.ai                 read              last used 2026-10-04  ends 2026-10-31\n' +
      'c0nn-2  Cursor (unverified)           -                         read write        last used never  ends 2026-11-01\n',
  );

  const preview = fixture(answer);
  await manage.appsRevoke(preview.connect, ['c0nn-1'], preview.io);
  assert.deepEqual(preview.calls.map(({ method, path }) => `${method} ${path}`), ['GET /me', 'GET /apps']);
  assert.match(preview.written.out, /^would disconnect Claude \(claude\.ai\), connected 2026-10-01, last used 2026-10-04: it would stop working at once\.\nNothing changed/);

  const revoke = fixture((call) => (call.method === 'GET' ? answer(call) : { disconnected: true }));
  await manage.appsRevoke(revoke.connect, ['c0nn-2', '--apply'], revoke.io);
  assert.deepEqual(revoke.calls.map(({ method, path }) => `${method} ${path}`), ['GET /me', 'GET /apps', 'DELETE /apps/c0nn-2']);
  assert.equal(revoke.written.out, 'disconnected Cursor, connected 2026-10-02, last used never\n');
  await assert.rejects(manage.appsRevoke(fixture(answer).connect, ['c0nn-9'], list.io), /you have no connected app c0nn-9: `coffre apps` lists them/);

  // Where the deployment serves no MCP, as /me reports it, apps says so, and asks nothing more.
  const off = fixture(() => ({ features: { mcp: null, workloads: false } }));
  await manage.apps(off.connect, [], off.io);
  assert.match(off.written.out, /^MCP is off on this instance: no app connects here/);
  assert.deepEqual(off.calls.map(({ path }) => path), ['/me']);
  await assert.rejects(manage.appsRevoke(off.connect, ['c0nn-1', '--apply'], off.io), /MCP is off on this instance/);
});

test('folders lists the projects\' folders, or an environment\'s with its path; rename and remove send the folder, never a key path', async () => {
  const projects = { projects: [{ slug: 'acme', folder: 'Clients' }, { slug: 'globex', folder: 'Clients' }, { slug: 'market', folder: null }] };
  const keys = { permissions: [], keys: [{ key: 'DATABASE_URL', folder: 'database' }, { key: 'PORT', folder: null }] };
  const answer = ({ method, path }: Call) => {
    if (method === 'GET') return path.startsWith('/projects') ? projects : keys;
    return { folder: method === 'DELETE' ? null : 'Customers', moved: path.includes('/market/') ? ['DATABASE_URL'] : ['acme', 'globex'] };
  };
  const list = fixture(answer);
  await manage.folders(list.connect, [], list.io);
  assert.equal(list.written.out, 'Clients/  acme, globex\n');
  await manage.folders(list.connect, ['market/prod', '--json'], list.io);
  assert.deepEqual(JSON.parse(list.written.out.slice(list.written.out.indexOf('['))), [{ folder: 'database', keys: ['DATABASE_URL'] }]);

  const rename = fixture(answer);
  await manage.foldersRename(rename.connect, ['Clients', 'Customers'], rename.io);
  await manage.foldersRename(rename.connect, ['market/prod', 'database', 'db'], rename.io);
  assert.deepEqual(rename.calls.map(({ method, path, body }) => [method, path, body]), [
    ['PATCH', '/folders/Clients', { name: 'Customers' }],
    ['PATCH', '/folders/market/prod/database', { name: 'db' }],
  ]);
  assert.match(rename.written.out, /^Clients\/ is Customers\/ now: acme, globex\ndatabase\/ is db\/ now in market\/prod: DATABASE_URL\n$/);

  // More than one project out of a folder is shown first.
  const preview = fixture(answer);
  await manage.foldersRemove(preview.connect, ['Clients'], preview.io);
  assert.deepEqual(preview.calls.map(({ method }) => method), ['GET']);
  assert.match(preview.written.out, /^would take 2 projects out of Clients\/: acme, globex\. Each stays where it is, in no folder\.\nNothing changed/);
  const removed = fixture(answer);
  await manage.foldersRemove(removed.connect, ['Clients', '--apply'], removed.io);
  await manage.foldersRemove(removed.connect, ['market/prod', 'database'], removed.io);
  assert.deepEqual(removed.calls.filter(({ method }) => method === 'DELETE').map(({ path }) => path), ['/folders/Clients', '/folders/market/prod/database']);
  assert.match(removed.written.out, /acme, globex are in no folder now; Clients\/ is gone\nDATABASE_URL is in no folder now; database\/ is gone\n/);

  // A folder's name has no slash: what has one is an environment, or a mistake.
  await assert.rejects(manage.foldersRename(rename.connect, ['market/prod/database', 'db'], rename.io), /a folder's name has no \//);
  await assert.rejects(manage.foldersRemove(rename.connect, ['market', 'database'], rename.io), /expected <project>\/<environment>, not "market"/);
});

test('a command reads its arguments before it asks for a session', async () => {
  const connect = () => assert.fail('no session is asked for');
  await assert.rejects(manage.tokens(connect, ['a', 'b'], fixture(() => null).io), /too many arguments: b/);
  await assert.rejects(manage.tokensIssue(connect, [], fixture(() => null).io), /a personal token needs --label/);
  await assert.rejects(manage.tokensIssue(connect, ['--label', 'agent'], fixture(() => null).io), /a personal token needs --scope/);
  await assert.rejects(manage.tokensIssue(connect, ['--label', 'agent', '--scope', 'market/dev=viewer', '--expires-in', '8d'], fixture(() => null).io), /a minute to 7 days/);
  await assert.rejects(manage.tokensIssue(connect, ['deploy', '--expires-in', '4h'], fixture(() => null).io), /days for a service token/);
  await assert.rejects(manage.projectsCreate(connect, ['a', 'b'], fixture(() => null).io), /too many arguments: b/);
  await assert.rejects(manage.tokensIssue(connect, ['deploy', '--bogus'], fixture(() => null).io), { code: 'ERR_PARSE_ARGS_UNKNOWN_OPTION' });
});

const BINDING = {
  id: 'bnd-1',
  profile: 'github',
  issuer: 'https://token.actions.githubusercontent.com',
  jwksUri: 'https://token.actions.githubusercontent.com/.well-known/jwks',
  keys: null,
  claims: { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' },
  scope: { 'market/dev': 'viewer', 'market/prod': 'viewer' },
  label: 'deploys',
  createdAt: '2026-10-01T00:00:00Z',
  createdBy: 'root@acme.example',
  lastUsedAt: '2026-10-04T12:30:00Z',
};

test('untrust shows the binding and the runs it would cut off, and removes it only with --apply', async () => {
  const preview = fixture(() => ({ bindings: [BINDING] }));
  await manage.untrust(preview.connect, ['api-deploy', 'bnd-1'], preview.io);
  assert.deepEqual(preview.calls.map(({ method, path }) => `${method} ${path}`), ['GET /members/token:api-deploy/bindings']);
  assert.match(preview.written.out, /^Would remove service:api-deploy's trust binding bnd-1  deploys  \(added by root@acme\.example 2026-10-01, last used 2026-10-04 12:30\)\n  profile  github\n/);
  assert.match(
    preview.written.out,
    /\nGitHub Actions runs of acme\/api's workflow deploy\.yml, on branch main, by push would no longer sign in as service:api-deploy, and the credentials they hold would end at once\.\nNothing changed\. Re-run with --apply to remove it\.\n$/,
  );

  const applied = fixture(({ method }) => (method === 'GET' ? { bindings: [BINDING] } : { removed: true }));
  await manage.untrust(applied.connect, ['token:api-deploy', 'bnd-1', '--apply'], applied.io);
  assert.deepEqual(applied.calls.map(({ method, path }) => `${method} ${path}`), ['GET /members/token:api-deploy/bindings', 'DELETE /members/token:api-deploy/bindings/bnd-1']);
  assert.match(applied.written.out, /^Removed service:api-deploy's trust binding bnd-1/);
  assert.match(applied.written.out, /can no longer sign in as service:api-deploy, and the credentials they hold have ended\.\n$/);

  await assert.rejects(manage.untrust(preview.connect, ['api-deploy', 'bnd-9'], preview.io), /service:api-deploy has no trust binding bnd-9: `coffre trust api-deploy` lists them/);
  await assert.rejects(manage.untrust(() => assert.fail('no session is asked for'), ['api-deploy'], preview.io), /name <binding-id>/);
});

test('version prints the version alone, or the JSON answer, and asks nothing else', async () => {
  const { connect, calls, written, io } = fixture(() => ({ version: 'u0Hq2bWk1M6l0j3t5rH4dQyT1vXJ9n0dD8c2F7k3pZa' }));
  await manage.version(connect, ['market/prod'], io);
  await manage.version(connect, ['market/prod', '--json'], io);
  assert.deepEqual(calls.map((call) => [call.method, call.path]), [['GET', '/projects/market/prod/version'], ['GET', '/projects/market/prod/version']]);
  assert.equal(written.out, 'u0Hq2bWk1M6l0j3t5rH4dQyT1vXJ9n0dD8c2F7k3pZa\n{\n  "version": "u0Hq2bWk1M6l0j3t5rH4dQyT1vXJ9n0dD8c2F7k3pZa"\n}\n');
  await assert.rejects(manage.version(connect, ['market/prod/KEY'], io), /expected <project>\/<environment>/);
});

/** A role as `GET /roles` lists it, as it ships unless told. */
function listedRole(id: string, definition: { name: string; permissions: string[]; protected: string[] }, more: Record<string, unknown> = {}) {
  const shipped = { ...definition, description: '' };
  return { id, ...shipped, builtin: true, edited: false, fixed: false, default: shipped, assignableToEnvironment: true, grants: 0, ...more };
}

const LISTED_ROLES = {
  roles: [
    listedRole('developer', { name: 'Developer', permissions: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.use', 'secret.write'] }, { edited: true }),
    listedRole('release-manager', { name: 'Release manager', permissions: ['secret.use', 'secret.write'], protected: ['secret.use'] }, { builtin: false, default: null }),
    listedRole('owner', { name: 'Owner', permissions: ['secret.read', 'grant.manage'], protected: ['secret.read'] }, { fixed: true, assignableToEnvironment: false }),
  ],
  instanceRoles: [listedRole('member', { name: 'Member', permissions: [], protected: [] }, { fixed: true, assignableToEnvironment: false })],
  editable: true,
};

test('roles lists both columns of every role, says which an Owner made, edited or nobody edits, and one role by its permissions', async () => {
  const { connect, calls, written, io } = fixture(() => LISTED_ROLES);
  await manage.roles(connect, [], io);
  assert.deepEqual(calls.map(({ method, path }) => `${method} ${path}`), ['GET /roles']);
  // The first column as wide as its widest entry, Owner's, and two spaces after: every "protected:" lines up.
  assert.match(written.out, /\n {2}developer {8}\[project or env\] read, use, write {4}protected: use, write {2}\[edited\]\n/);
  assert.match(written.out, /\n {2}owner {12}\[project only\] {3}read, grant\.manage {2}protected: read {2}\[fixed\]\n/);
  assert.match(written.out, /\n {2}release-manager .*protected: use {2}\[custom\]\n/);
  assert.match(written.out, /\n {2}owner .*\[project only\].*\[fixed\]\n/);
  assert.match(written.out, /\n {2}member .*nothing .*protected: nothing {2}\[fixed\]\n/);
  const one = fixture(() => LISTED_ROLES);
  await manage.roles(one.connect, ['developer'], one.io);
  assert.equal(one.written.out, 'developer  Developer  [edited]\n  secret.read   yes   protected: no\n  secret.use    yes   protected: yes\n  secret.write  yes   protected: yes\n');
  await assert.rejects(manage.roles(one.connect, ['boss'], one.io), /no role "boss": `coffre roles` lists them/);
});

test('roles set says what the change would do and saves it only with --apply, keeping what the flags leave out', async () => {
  const impact = { impact: [], sentence: 'Widens secret.read for 1 person on market/prod, protected', policySeq: 57 };
  const preview = fixture(({ method }) => (method === 'GET' ? LISTED_ROLES : impact));
  await manage.rolesSet(preview.connect, ['developer', '--protected', 'read,use,write'], preview.io);
  const definition = { name: 'Developer', description: '', permissions: ['secret.read', 'secret.use', 'secret.write'], protected: ['secret.read', 'secret.use', 'secret.write'] };
  assert.deepEqual(preview.calls, [{ method: 'GET', path: '/roles', body: undefined }, { method: 'PUT', path: '/roles/developer?dryRun=1', body: definition }]);
  assert.equal(preview.written.out, 'developer: read, use, write, protected: read, use, write\n  Widens secret.read for 1 person on market/prod, protected\nNothing changed. Re-run with --apply to save it.\n');
  const applied = fixture(({ method, path }) => (method === 'GET' ? LISTED_ROLES : path.endsWith('dryRun=1') ? impact : { role: null }));
  await manage.rolesSet(applied.connect, ['developer', '--protected', 'secret.read,secret.use,secret.write', '--apply'], applied.io);
  // Saved as previewed, from the policy its preview was weighed from.
  assert.deepEqual(applied.calls.map(({ method, path }) => `${method} ${path}`), ['GET /roles', 'PUT /roles/developer?dryRun=1', 'PUT /roles/developer?policySeq=57']);
  assert.match(applied.written.out, /^saved developer: /);
  // A new role holds nothing it is not given; an instance role is one that ships.
  const made = fixture(({ method }) => (method === 'GET' ? LISTED_ROLES : impact));
  await manage.rolesSet(made.connect, ['qa', '--name', 'QA', '--permissions', 'use'], made.io);
  assert.deepEqual(made.calls[1]!.body, { name: 'QA', description: '', permissions: ['secret.use'], protected: [] });
  await assert.rejects(manage.rolesSet(made.connect, ['qa', '--instance', '--name', 'QA'], made.io), /no instance role "qa"/);
  await assert.rejects(manage.rolesSet(() => assert.fail('no session is asked for'), ['developer'], made.io), /say what changes/);
});

test('roles reset puts an edited role back, shown first; roles remove deletes one an Owner made, and neither the other kind', async () => {
  const impact = { impact: [], sentence: 'Changes what nobody holds', policySeq: null };
  const reset = fixture(({ method, path }) => (method === 'GET' ? LISTED_ROLES : path.endsWith('dryRun=1') ? impact : { role: LISTED_ROLES.roles[0] }));
  await manage.rolesReset(reset.connect, ['developer'], reset.io);
  await manage.rolesReset(reset.connect, ['developer', '--apply'], reset.io);
  assert.deepEqual(reset.calls.map(({ method, path }) => `${method} ${path}`), ['GET /roles', 'DELETE /roles/developer?dryRun=1', 'GET /roles', 'DELETE /roles/developer?dryRun=1', 'DELETE /roles/developer?policySeq=none']);
  assert.match(reset.written.out, /Nothing changed\. Re-run with --apply to reset it\.\nreset developer, as it ships\n/);
  await assert.rejects(manage.rolesReset(reset.connect, ['release-manager'], reset.io), /`coffre roles remove release-manager` deletes it/);
  const removed = fixture(({ method }) => (method === 'GET' ? LISTED_ROLES : { role: null }));
  await manage.rolesRemove(removed.connect, ['release-manager'], removed.io);
  assert.deepEqual(removed.calls.map(({ method, path }) => `${method} ${path}`), ['GET /roles', 'DELETE /roles/release-manager']);
  assert.equal(removed.written.out, 'removed release-manager\n');
  await assert.rejects(manage.rolesRemove(removed.connect, ['developer'], removed.io), /ships with coffre, and stays/);
});

test('environments protect and unprotect send the flag, and say what it does', async () => {
  const on = fixture(() => ({ environment: { slug: 'prod', name: 'prod', archivedAt: null, protected: true } }));
  await manage.environmentsProtect(on.connect, ['market/prod'], true, on.io);
  assert.deepEqual(on.calls, [{ method: 'PATCH', path: '/projects/market/prod', body: { protected: true } }]);
  assert.match(on.written.out, /^market\/prod is protected: each role holds there what its protected column says, for people/);
  const off = fixture(() => ({ environment: { slug: 'prod', name: 'prod', archivedAt: null, protected: false } }));
  await manage.environmentsProtect(off.connect, ['market/prod'], false, off.io);
  assert.deepEqual(off.calls[0]!.body, { protected: false });
  assert.equal(off.written.out, 'market/prod is not protected: each role holds there what it holds anywhere\n');
});
