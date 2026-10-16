import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { inspect } from 'node:util';

import { DevIdp, fakeInstallations } from '@coffre/conformance/idp';
import { jwtVerify } from 'jose';

import {
  defineSignin,
  github,
  GitHubApp,
  GitHubAppUnavailable,
  MAX_LISTING_REQUESTS,
  pkcs8Of,
  TOKEN_MARGIN_MS,
  type GitHubAppOptions,
} from '../src/identity/index.ts';

const LIMITS = { perSource: { limit: async () => ({ success: true }) }, total: { limit: async () => ({ success: true }) } };

let idp: DevIdp;
/** Every request the app made, by method and path. */
let requests: string[];
let clock: number;

before(async () => {
  idp = new DevIdp();
  await idp.start();
});

after(async () => {
  await idp.stop();
});

beforeEach(() => {
  idp.githubApp.installations = fakeInstallations();
  idp.githubApp.down = false;
  idp.githubApp.tokensIssued = 0;
  idp.githubApp.revokeTokens();
  requests = [];
  clock = Date.now();
});

/** The dev IdP's app, its requests counted and its clock ours. */
function appOf(options: { privateKey?: string } = {}): GitHubApp {
  return new GitHubApp({ appId: idp.githubApp.appId, apiUrl: idp.githubApp.options.apiUrl, pkcs8: pkcs8Of(options.privateKey ?? idp.githubApp.privateKey) }, {
    fetch: async (input, init) => {
      requests.push(`${init?.method ?? 'GET'} ${new URL(String(input)).pathname.replace('/github/api', '')}`);
      return fetch(input, init);
    },
    now: () => clock,
  });
}

test('a PEM as GitHub downloads it, PKCS #1, imports as PKCS #8; so does PKCS #8 itself, and escaped newlines', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pkcs1 = privateKey.export({ type: 'pkcs1', format: 'pem' }) as string;
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  assert.match(pkcs1, /BEGIN RSA PRIVATE KEY/);
  const expected = privateKey.export({ type: 'pkcs8', format: 'der' });
  assert.deepEqual(Buffer.from(pkcs8Of(pkcs1)), expected);
  assert.deepEqual(Buffer.from(pkcs8Of(pkcs8)), expected);
  assert.deepEqual(Buffer.from(pkcs8Of(pkcs1.replaceAll('\n', '\\n'))), expected);
  await crypto.subtle.importKey('pkcs8', pkcs8Of(pkcs1), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
});

test('the configuration is checked where it is written, and a refusal never repeats the key', () => {
  const configure = (githubApp: GitHubAppOptions) =>
    defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: LIMITS, githubApp } });
  const key = idp.githubApp.privateKey;
  assert.throws(() => configure({ appId: 'Iv1.abc', privateKey: key }), /appId must be the app's numeric ID/);
  const broken = key.replace('-----END RSA PRIVATE KEY-----', '');
  assert.throws(() => configure({ appId: 1001, privateKey: broken }), (error: Error) => {
    assert.match(error.message, /privateKey must be the app's private key, the PEM file GitHub downloads/);
    assert.ok(!error.message.includes(broken.split('\n')[1]!));
    return true;
  });
  assert.throws(() => configure({ appId: 1001, privateKey: key, apiUrl: 'http://github.acme.example/api/v3' }), /apiUrl must use HTTPS/);
  assert.equal(configure({ appId: 1001, privateKey: key }).workloads!.githubApp!.apiUrl, 'https://api.github.com');
  assert.equal(defineSignin({ publicUrl: 'https://secrets.acme.example', providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits: LIMITS } }).workloads!.githubApp, null);
});

test('the app signs its JWT with RS256 over its ID, issued a minute back, for nine minutes', async () => {
  let jwt: string | undefined;
  const app = new GitHubApp({ appId: '1001', apiUrl: 'https://api.github.com', pkcs8: pkcs8Of(idp.githubApp.privateKey) }, {
    fetch: async (_input, init) => {
      jwt = new Headers(init?.headers).get('authorization')!.replace(/^Bearer /, '');
      return new Response(null, { status: 404 });
    },
    now: () => clock,
  });
  assert.equal(await app.repository('acme/api'), null);
  const publicKey = createPublicKey(idp.githubApp.privateKey);
  const { payload, protectedHeader } = await jwtVerify(jwt!, publicKey, { currentDate: new Date(clock) });
  const now = Math.floor(clock / 1000);
  assert.deepEqual(protectedHeader, { alg: 'RS256', typ: 'JWT' });
  assert.deepEqual(payload, { iat: now - 60, exp: now + 540, iss: '1001' });
});

test('it lists every repository of the installations not suspended, private ones too, by name', async () => {
  const listed = await appOf().repositories();
  assert.deepEqual(listed.app, { name: 'Coffre (dev)', installUrl: `${idp.origin}/github/apps/coffre-dev/installations/new` });
  assert.deepEqual(listed.installations, ['acme', 'octo-dev']);
  assert.equal(listed.truncated, false);
  assert.deepEqual(listed.repositories, [
    { github: 'acme/api', repositoryId: '41532', ownerId: '9919', private: false },
    { github: 'acme/deploy-actions', repositoryId: '41550', ownerId: '9919', private: true },
    { github: 'acme/infra', repositoryId: '41540', ownerId: '9919', private: true },
    { github: 'acme/payments', repositoryId: '41541', ownerId: '9919', private: true },
    { github: 'acme/web', repositoryId: '41533', ownerId: '9919', private: false },
    { github: 'octo-dev/dotfiles', repositoryId: '70001', ownerId: '583231', private: true },
  ]);
});

test('an installation token is kept until shortly before it expires, then issued again', async () => {
  const app = appOf();
  await app.repositories();
  assert.equal(idp.githubApp.tokensIssued, 2);
  await app.repositories();
  await app.repository('acme/infra');
  assert.equal(idp.githubApp.tokensIssued, 2, 'kept, one per installation');
  // The app's name is asked once too.
  assert.equal(requests.filter((request) => request === 'GET /app').length, 1);

  // GitHub's expiry is to the second: a second's slack either side.
  clock += 60 * 60 * 1000 - TOKEN_MARGIN_MS - 2000;
  await app.repositories();
  assert.equal(idp.githubApp.tokensIssued, 2, 'still kept, just before its margin');
  clock += 4000;
  await app.repositories();
  assert.equal(idp.githubApp.tokensIssued, 4, 'issued again, within five minutes of its end');
});

test('a kept token GitHub refuses is issued again, once', async () => {
  const app = appOf();
  await app.repositories();
  idp.githubApp.revokeTokens();
  requests = [];
  assert.equal((await app.repositories()).repositories.length, 6);
  assert.deepEqual(requests.filter((request) => request.startsWith('POST')).length, 2);
  assert.equal(idp.githubApp.tokensIssued, 4);
});

test('an installation of many repositories is listed page by page, and a listing stops at its budget, saying so', async () => {
  const many = (count: number, from: number) => Array.from({ length: count }, (_, i) => ({ id: from + i, name: `repo-${String(i).padStart(4, '0')}`, private: i % 2 === 0 }));
  idp.githubApp.installations = [{ id: 10, account: { login: 'big', id: 500, type: 'Organization' }, suspended: false, repositories: many(250, 1_000_000) }];
  const listed = await appOf().repositories();
  assert.equal(listed.repositories.length, 250);
  assert.equal(listed.truncated, false);
  assert.equal(requests.filter((request) => request === 'GET /installation/repositories').length, 3);

  idp.githubApp.installations = Array.from({ length: 30 }, (_, i) => ({
    id: 100 + i,
    account: { login: `org-${String(i).padStart(2, '0')}`, id: 600 + i, type: 'Organization' as const },
    suspended: false,
    repositories: many(150, 2_000_000 + i * 1000),
  }));
  requests = [];
  const capped = await appOf().repositories();
  assert.equal(capped.truncated, true);
  assert.ok(requests.length <= MAX_LISTING_REQUESTS, `${requests.length} requests`);
  assert.equal(capped.installations.length, 30);
  assert.ok(capped.repositories.length > 0);
});

test('a listing spends its budget on every request it makes, tokens issued again and retries included', async () => {
  idp.githubApp.installations = Array.from({ length: 19 }, (_, i) => ({
    id: 200 + i,
    account: { login: `team-${String(i).padStart(2, '0')}`, id: 900 + i, type: 'Organization' as const },
    suspended: false,
    repositories: [{ id: 3_000_000 + i, name: 'only', private: true }],
  }));
  const app = appOf();
  // The app, its installations, then a token and a page for each: 40, just within.
  const first = await app.repositories();
  assert.equal(requests.length, MAX_LISTING_REQUESTS);
  assert.deepEqual([first.repositories.length, first.truncated], [19, false]);
  // Every kept token refused: each installation's page costs three, its refusal, a token and the page again.
  idp.githubApp.revokeTokens();
  requests = [];
  const again = await app.repositories();
  assert.ok(requests.length <= MAX_LISTING_REQUESTS, `${requests.length} requests after the tokens were revoked`);
  assert.equal(again.truncated, true);
  assert.ok(again.repositories.length < 19);
});

test('with a cold cache and more installations than the budget reaches, those it reaches are listed whole, the others left out', async () => {
  for (const count of [38, 100]) {
    idp.githubApp.installations = Array.from({ length: count }, (_, i) => ({
      id: 400 + i,
      account: { login: `unit-${String(i).padStart(3, '0')}`, id: 1200 + i, type: 'Organization' as const },
      suspended: false,
      repositories: [{ id: 4_000_000 + i, name: 'only', private: true }],
    }));
    requests = [];
    const listed = await appOf().repositories();
    assert.ok(requests.length <= MAX_LISTING_REQUESTS, `${requests.length} requests`);
    // The app and its installations, then a token and a page each: 19 of them.
    assert.deepEqual([listed.repositories.length, listed.truncated], [19, true], `${count} installations`);
    assert.equal(listed.installations.length, count);
  }
});

test("a repository by name: its IDs when the app is installed on it, private or not; null when it is not", async () => {
  const app = appOf();
  assert.deepEqual(await app.repository('acme/infra'), { github: 'acme/infra', repositoryId: '41540', ownerId: '9919', private: true });
  assert.deepEqual(await app.repository('ACME/api'), { github: 'acme/api', repositoryId: '41532', ownerId: '9919', private: false });
  assert.equal(await app.repository('acme/nothing'), null);
  assert.equal(await app.repository('someone/else'), null);
  assert.equal(await app.repository('old-co/legacy'), null, 'suspended');
});

test('GitHub down, or refusing the app, says so, and neither the key nor a token is ever in a message or the object', async () => {
  const app = appOf();
  await app.repositories();
  idp.githubApp.down = true;
  await assert.rejects(app.repositories(), (error: Error) => error instanceof GitHubAppUnavailable && /GitHub answered \/app\/installations with 503/.test(error.message));
  await assert.rejects(app.repository('acme/api'), /GitHub answered \/repos\/acme\/api\/installation with 503/);
  idp.githubApp.down = false;

  const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }) as string;
  await assert.rejects(appOf({ privateKey: other }).repositories(), /GitHub refused the app \(401\): check its app ID and private key/);

  const unreachable = new GitHubApp({ appId: '1001', apiUrl: 'http://127.0.0.1:9', pkcs8: pkcs8Of(idp.githubApp.privateKey) });
  await assert.rejects(unreachable.repositories(), /GitHub could not be reached/);

  const keyLine = idp.githubApp.privateKey.split('\n')[1]!;
  for (const shown of [JSON.stringify(app), inspect(app, { showHidden: true, depth: 5 }), String(app)]) {
    assert.ok(!shown.includes(keyLine), shown);
    assert.ok(!shown.includes('ghs_'), shown);
  }
});
