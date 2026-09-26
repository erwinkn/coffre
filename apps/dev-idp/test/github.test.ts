import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import { DevIdp } from '../src/idp.ts';
import { form, get, location, pkce, REDIRECT_URI } from './helpers.ts';

const CLIENT = { client_id: 'coffre-local', client_secret: 'coffre-local-secret' };
const JSON_ACCEPT = { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' };

let idp: DevIdp;
let web: string;
let api: string;

before(async () => {
  idp = new DevIdp({ autoApprove: true });
  await idp.start();
  web = `${idp.origin}/github`;
  api = `${idp.origin}/github/api`;
});

after(async () => {
  await idp.stop();
});

async function authorize(opts: { email?: string; login?: string; scope?: string } = {}) {
  const { verifier, challenge } = pkce();
  const url = new URL(`${web}/login/oauth/authorize`);
  url.searchParams.set('client_id', CLIENT.client_id);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', opts.scope ?? 'read:user user:email read:org');
  url.searchParams.set('state', 'st');
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('allow_signup', 'false');
  if (opts.login) url.searchParams.set('login', opts.login);
  else url.searchParams.set('login_hint', opts.email ?? 'dev@equisafe.io');

  const back = location(await get(url));
  return { back, code: back.searchParams.get('code')!, verifier };
}

async function exchange(body: Record<string, string>, headers: Record<string, string> = JSON_ACCEPT) {
  const response = await fetch(`${web}/login/oauth/access_token`, { ...form(body), headers });
  return response;
}

async function signIn(opts: Parameters<typeof authorize>[0] = {}): Promise<string> {
  const { code, verifier } = await authorize(opts);
  const response = await exchange({ ...CLIENT, code, code_verifier: verifier, redirect_uri: REDIRECT_URI });
  return (await response.json()).access_token;
}

function apiGet(path: string, token?: string, scheme = 'Bearer') {
  return get(`${api}${path}`, token ? { headers: { authorization: `${scheme} ${token}` } } : {});
}

test('the web flow returns code and state, without iss', async () => {
  const { back, code } = await authorize();
  assert.equal(back.origin + back.pathname, REDIRECT_URI);
  assert.equal(back.searchParams.get('state'), 'st');
  assert.equal(back.searchParams.get('iss'), null);
  assert.ok(code);
});

test('the token endpoint answers JSON only when asked, with comma-separated scopes', async () => {
  const first = await authorize({ scope: 'read:user user:email' });
  const asJson = await exchange({ ...CLIENT, code: first.code, code_verifier: first.verifier, redirect_uri: REDIRECT_URI });
  assert.equal(asJson.status, 200);
  const body = await asJson.json();
  assert.match(body.access_token, /^gho_/);
  assert.equal(body.token_type, 'bearer');
  assert.equal(body.scope, 'read:user,user:email');

  // JSON bodies are accepted too.
  const second = await authorize({ scope: 'read:user' });
  const asForm = await fetch(`${web}/login/oauth/access_token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...CLIENT, code: second.code, code_verifier: second.verifier }),
  });
  assert.match(asForm.headers.get('content-type')!, /^application\/x-www-form-urlencoded/);
  const params = new URLSearchParams(await asForm.text());
  assert.match(params.get('access_token')!, /^gho_/);
  assert.equal(params.get('scope'), 'read:user');
});

test('token errors are HTTP 200 with an error field', async () => {
  const cases: Array<[() => Promise<Record<string, string>>, string]> = [
    [async () => ({ client_id: CLIENT.client_id, client_secret: 'nope', code: (await authorize()).code }), 'incorrect_client_credentials'],
    [async () => ({ ...CLIENT, code: 'not-a-code', code_verifier: pkce().verifier }), 'bad_verification_code'],
    [async () => ({ ...CLIENT, code: (await authorize()).code, code_verifier: pkce().verifier }), 'bad_verification_code'],
    [async () => ({ ...CLIENT, code: (await authorize()).code }), 'bad_verification_code'],
    [
      async () => {
        const { code, verifier } = await authorize();
        return { ...CLIENT, code, code_verifier: verifier, redirect_uri: 'http://127.0.0.1:3000/other' };
      },
      'redirect_uri_mismatch',
    ],
  ];
  for (const [body, error] of cases) {
    const response = await exchange(await body());
    assert.equal(response.status, 200);
    const json = await response.json();
    assert.equal(json.error, error);
    assert.equal(json.access_token, undefined);
    assert.ok(json.error_description);
  }

  const { code, verifier } = await authorize();
  const ok = { ...CLIENT, code, code_verifier: verifier };
  assert.ok((await (await exchange(ok)).json()).access_token);
  assert.equal((await (await exchange(ok)).json()).error, 'bad_verification_code');

  const asForm = await exchange({ ...CLIENT, code: 'nope' }, { 'content-type': 'application/x-www-form-urlencoded' });
  assert.equal(asForm.status, 200);
  assert.equal(new URLSearchParams(await asForm.text()).get('error'), 'bad_verification_code');
});

test('the API requires a token, under Bearer or token', async () => {
  assert.equal((await apiGet('/user')).status, 401);
  assert.equal((await apiGet('/user', 'gho_nope')).status, 401);

  const token = await signIn({ email: 'lead@equisafe.io' });
  for (const scheme of ['Bearer', 'token']) {
    const response = await apiGet('/user', token, scheme);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-oauth-scopes'), 'read:user, user:email, read:org');
    const user = await response.json();
    assert.equal(typeof user.id, 'number');
    assert.equal(user.login, 'lead');
    assert.equal(user.name, 'Lea Lead');
    assert.equal(user.email, 'lead@equisafe.io');
  }
});

test('user ids are stable per persona', async () => {
  const a = await (await apiGet('/user', await signIn({ email: 'auditor@equisafe.io' }))).json();
  const b = await (await apiGet('/user', await signIn({ email: 'auditor@equisafe.io' }))).json();
  const c = await (await apiGet('/user', await signIn({ email: 'dev@equisafe.io' }))).json();
  assert.equal(a.id, b.id);
  assert.notEqual(a.id, c.id);
});

test('GitHub’s login hint names a user, not an email', async () => {
  const user = await (await apiGet('/user', await signIn({ login: 'accessmgr' }))).json();
  assert.equal(user.name, 'Max Access');
});

test('emails list unverified addresses too, and need user:email', async () => {
  const token = await signIn({ email: 'outsider@equisafe.io' });
  const response = await apiGet('/user/emails', token);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), [
    { email: 'outsider@equisafe.io', primary: true, verified: true, visibility: 'public' },
    { email: 'lead@equisafe.io', primary: false, verified: false, visibility: null },
  ]);

  const narrow = await signIn({ email: 'outsider@equisafe.io', scope: 'read:user' });
  assert.equal((await apiGet('/user/emails', narrow)).status, 404);
  assert.equal((await apiGet('/user/emails', await signIn({ scope: 'user' }))).status, 200);
});

test('org membership needs read:org, and is 404 for non-members', async () => {
  const token = await signIn({ email: 'dev@equisafe.io' });
  const member = await apiGet('/user/memberships/orgs/equisafe', token);
  assert.equal(member.status, 200);
  const body = await member.json();
  assert.equal(body.state, 'active');
  assert.equal(body.role, 'member');
  assert.equal(body.organization.login, 'equisafe');
  assert.equal(body.user.login, 'dev');

  assert.equal((await apiGet('/user/memberships/orgs/EquiSafe', token)).status, 200);
  assert.equal((await apiGet('/user/memberships/orgs/other-org', token)).status, 404);

  const narrow = await signIn({ email: 'dev@equisafe.io', scope: 'read:user user:email' });
  assert.equal((await apiGet('/user/memberships/orgs/equisafe', narrow)).status, 403);
});

test('setGitHubUser simulates a recycled email, several emails, and leaving the org', async () => {
  const email = 'recycled@equisafe.io';
  const before = await (await apiGet('/user', await signIn({ email }))).json();

  idp.setGitHubUser(email, {
    id: 424242,
    login: 'newcomer',
    emails: [
      { email: 'newcomer@personal.example', visibility: 'private' },
      { email, primary: true },
      { email: 'old@equisafe.io', verified: false },
    ],
    orgs: [],
  });
  const token = await signIn({ email });
  const after = await (await apiGet('/user', token)).json();
  assert.notEqual(before.id, 424242);
  assert.equal(after.id, 424242);
  assert.equal(after.login, 'newcomer');
  assert.equal(after.email, email);

  const emails = await (await apiGet('/user/emails', token)).json();
  assert.deepEqual(
    emails.map((e: { email: string; primary: boolean; verified: boolean }) => [e.email, e.primary, e.verified]),
    [
      ['newcomer@personal.example', false, true],
      [email, true, true],
      ['old@equisafe.io', false, false],
    ],
  );
  assert.equal((await apiGet('/user/memberships/orgs/equisafe', token)).status, 404);

  // A patch keeps what it does not mention.
  idp.setGitHubUser(email, { orgs: ['equisafe'] });
  assert.equal(idp.gitHubUserFor(email).id, 424242);
  assert.equal((await apiGet('/user/memberships/orgs/equisafe', await signIn({ email }))).status, 200);
});

test('GitHub codes and tokens do not cross into OIDC', async () => {
  const { code, verifier } = await authorize();
  const oidc = await fetch(
    `${idp.origin}/oauth/token`,
    form({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT_URI, ...CLIENT }),
  );
  assert.equal((await oidc.json()).error, 'invalid_grant');

  const token = await signIn();
  const userinfo = await get(`${idp.origin}/oauth/userinfo`, { headers: { authorization: `Bearer ${token}` } });
  assert.equal(userinfo.status, 401);
});

test('unknown clients get an error page; missing PKCE is an error redirect', async () => {
  const { challenge } = pkce();
  const unknown = await get(
    `${web}/login/oauth/authorize?client_id=who&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=s&code_challenge=${challenge}&code_challenge_method=S256`,
  );
  assert.equal(unknown.status, 400);
  assert.equal(unknown.headers.get('location'), null);

  const noPkce = location(
    await get(`${web}/login/oauth/authorize?client_id=coffre-local&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=s`),
  );
  assert.equal(noPkce.searchParams.get('error'), 'invalid_request');
  assert.equal(noPkce.searchParams.get('state'), 's');
});
