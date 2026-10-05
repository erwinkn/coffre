import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createClient, CoffreError } from '@coffre/client';

import * as manage from '../src/manage.ts';

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
  const { connect, calls, written, io } = fixture(() => ({ id: 'tok-1', token: TOKEN, expiresAt: '2027-01-01T00:00:00.000Z' }));
  await manage.tokensIssue(connect, ['deploy-slides', '--label', 'CI', '--expires-in', '30'], io);
  assert.deepEqual(calls, [{ method: 'POST', path: '/members/token:deploy-slides/tokens', body: { expiresInDays: 30, label: 'CI' } }]);
  assert.equal(written.out, `${TOKEN}\n`);
  assert.equal(written.err, "coffre: service:deploy-slides's bearer token tok-1, until 2027-01-01. It is shown this once: coffre keeps only its hash\n");
  assert.ok(!written.err.includes(TOKEN));
});

test('tokens issue --output-file writes a new 0600 file, prints no token, and never overwrites', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-tokens-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'token');
  const { connect, written, io } = fixture(() => ({ id: 'tok-1', token: TOKEN, expiresAt: '2027-01-01T00:00:00.000Z' }));
  await manage.tokensIssue(connect, ['deploy-slides', '--output-file', path], io);
  assert.equal(readFileSync(path, 'utf8'), `${TOKEN}\n`);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.ok(!written.out.includes(TOKEN) && !written.err.includes(TOKEN));
  assert.match(written.out, /^wrote service:deploy-slides's bearer token tok-1, until 2027-01-01, to .*token, readable by you alone/);

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
  const { connect, calls, io } = fixture(() => ({ id: 't', token: TOKEN, expiresAt: '2027-01-01T00:00:00.000Z' }));
  await manage.tokensIssue(connect, ['token:deploy'], io);
  assert.deepEqual(calls[0]!.body, { expiresInDays: 90, label: null });
  for (const bad of ['0', '367', '1.5', 'soon']) {
    await assert.rejects(manage.tokensIssue(connect, ['deploy', '--expires-in', bad], io), manage.UsageError);
  }
});

const LISTED = {
  tokens: [{ id: 'tok-1', label: 'CI', hint: 'abcd', createdAt: '2026-10-01T00:00:00Z', createdBy: 'root@acme.example', expiresAt: '2027-01-01T00:00:00Z', lastUsedAt: null, lastUsedIp: null }],
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
  const { connect, calls, written, io } = fixture(() => ({ member: 'token:deploy-slides', instanceRole: 'user', created: true }));
  await manage.admit(connect, ['deploy-slides', '--service'], io);
  assert.deepEqual(calls, [{ method: 'PUT', path: '/members/token:deploy-slides', body: {} }]);
  assert.match(written.out, /^admitted service:deploy-slides\n  next: coffre grant <project> deploy-slides --role viewer \[--env <env>\] --service,\n        then let its CI sign in by OIDC, coffre trust deploy-slides --github … --apply,\n        or, for CI without OIDC, give it a bearer token, coffre tokens issue deploy-slides\n$/);

  const person = fixture(() => ({ member: 'user:ada@acme.example', instanceRole: 'owner', created: false }));
  await manage.admit(person.connect, ['ada@acme.example', '--owner'], person.io);
  assert.deepEqual(person.calls[0]!.body, { owner: true });
  assert.equal(person.written.out, 'user:ada@acme.example is a member, an owner of the instance now\n');
  await assert.rejects(manage.admit(person.connect, ['deploy', '--service', '--owner'], person.io), /a service account cannot own the instance/);
  await assert.rejects(manage.admit(person.connect, ['ada@acme.example', '--owner', '--no-owner'], person.io), manage.UsageError);
  // A name that says it is a service account's is one, with --service or not: service:deploy, or token:deploy as before.
  for (const name of ['service:deploy', 'token:deploy']) {
    const service = fixture(() => ({ member: 'token:deploy', instanceRole: 'user', created: false }));
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

test("revoke takes a grant on every project too, and asks for '*' quoted when the shell expanded it", async () => {
  const { connect, calls, written, io } = fixture(() => ({ changes: { '*/dev': 'revoked' } }));
  await manage.revoke(connect, ['*', 'ada@acme.example', '--env', 'dev'], io);
  assert.deepEqual(calls, [{ method: 'PATCH', path: '/access/user:ada@acme.example', body: { '*/dev': null } }]);
  assert.equal(written.out, "revoked user:ada@acme.example's grant on dev in every project\n");
  await assert.rejects(manage.revoke(connect, ['README.md', 'package.json', 'ada@acme.example'], io), /too many arguments: ada@acme.example; to name every project, quote it: '\*'/);
  await assert.rejects(manage.revoke(connect, ['market'], io), /name <principal>/);
});

test('making a place, or giving an environment a new slug, says who reaches it through grants on every project', async () => {
  const inherited = [
    { member: 'user:ada@acme.example', place: '*', role: 'auditor', roleName: 'Auditor', expiresAt: null },
    { member: 'token:ci', place: '*/dev', role: 'viewer', roleName: 'Viewer', expiresAt: '2027-01-31T23:59:59.999Z' },
  ];
  const { connect, written, io } = fixture(({ method, path }) =>
    path.split('/').length === 4
      ? method === 'PUT'
        ? { environment: { slug: 'dev', name: 'dev', archivedAt: null }, created: true, inherited }
        : { environment: { slug: 'dev', name: 'dev', archivedAt: null }, inherited }
      : { project: { slug: 'slides', name: 'slides', archivedAt: null }, created: true, inherited: inherited.slice(0, 1) },
  );
  await manage.projectsCreate(connect, ['slides'], io);
  await manage.environmentsCreate(connect, ['slides/dev'], io);
  await manage.environmentsRename(connect, ['slides/staging', '--slug', 'dev'], io);
  assert.equal(written.out, [
    'created slides, "slides"',
    'who reaches it already:',
    '  user:ada@acme.example as auditor, through every project',
    'created slides/dev, "dev"',
    'who reaches it already:',
    '  user:ada@acme.example as auditor, through every project',
    '  service:ci as viewer, through dev in every project until 2027-01-31',
    'slides/staging is now slides/dev, "dev"',
    'who reaches it now by its new slug:',
    '  service:ci as viewer, through dev in every project until 2027-01-31',
    '',
  ].join('\n'));
});

test('projects and environments: create, rename and archive, each one request', async () => {
  const project = { slug: 'slides', name: 'Slides', archivedAt: null };
  const { connect, calls, written, io } = fixture(({ method, path }) =>
    path.split('/').length === 4
      ? method === 'PUT'
        ? { environment: { slug: 'prod', name: 'prod', archivedAt: null }, created: true, inherited: [] }
        : { environment: { slug: 'production', name: 'Production', archivedAt: null }, inherited: [] }
      : method === 'PUT'
        ? { project, created: true, inherited: [] }
        : { project: { ...project, slug: 'deck' } },
  );
  await manage.projectsCreate(connect, ['slides', '--name', 'Slides'], io);
  await manage.environmentsCreate(connect, ['slides/prod'], io);
  await manage.projectsRename(connect, ['slides', '--slug', 'deck'], io);
  await manage.environmentsRename(connect, ['deck/prod', '--slug', 'production', '--name', 'Production'], io);
  await manage.projectsArchive(connect, ['deck'], true, io);
  await manage.environmentsArchive(connect, ['deck/production'], false, io);
  assert.deepEqual(calls, [
    { method: 'PUT', path: '/projects/slides', body: { name: 'Slides' } },
    { method: 'PUT', path: '/projects/slides/prod', body: { name: 'prod' } },
    { method: 'PATCH', path: '/projects/slides', body: { slug: 'deck' } },
    { method: 'PATCH', path: '/projects/deck/prod', body: { name: 'Production', slug: 'production' } },
    { method: 'PATCH', path: '/projects/deck', body: { archived: true } },
    { method: 'PATCH', path: '/projects/deck/production', body: { archived: false } },
  ]);
  assert.equal(
    written.out,
    'created slides, "Slides"\ncreated slides/prod, "prod"\nslides is now deck, "Slides"\ndeck/prod is now deck/production, "Production"\n' +
      'archived deck: `coffre projects unarchive deck` brings it back\nunarchived deck/production\n',
  );
  await assert.rejects(manage.projectsRename(connect, ['deck'], io), /give it a new --name, a new --slug, or both/);
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
      "  erased: 1 version, each one's ciphertext and wrapped data key, in dev, prod\n" +
      '  revoked: 1 grant, service:ci-deploy (viewer on slides/prod)\n' +
      '  kept, names only: slides~deleted-2026-10-05 and its 3 keys, which the audit log names\n' +
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
  assert.equal(unlink.written.out, 'unlinked your github account ada@acme.example (idn-1), and ended the sessions it signed in\n');
});

test('a command reads its arguments before it asks for a session', async () => {
  const connect = () => assert.fail('no session is asked for');
  await assert.rejects(manage.tokens(connect, [], fixture(() => null).io), /name <service>/);
  await assert.rejects(manage.projectsCreate(connect, ['a', 'b'], fixture(() => null).io), /too many arguments: b/);
  await assert.rejects(manage.tokensIssue(connect, ['deploy', '--bogus'], fixture(() => null).io), { code: 'ERR_PARSE_ARGS_UNKNOWN_OPTION' });
});

const BINDING = {
  id: 'bnd-1',
  profile: 'github',
  issuer: 'https://token.actions.githubusercontent.com',
  jwksUri: 'https://token.actions.githubusercontent.com/.well-known/jwks',
  claims: { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/deploy.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' },
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
