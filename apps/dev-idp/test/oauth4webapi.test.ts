import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import * as oauth from 'oauth4webapi';

import { DevIdp } from '../src/idp.ts';
import { get, location, REDIRECT_URI } from './helpers.ts';

// coffre's OIDC client is built on oauth4webapi; this is the same sequence of
// calls it makes, so a regression in either shows up here first.

let idp: DevIdp;

before(async () => {
  idp = new DevIdp({ autoApprove: true });
  await idp.start();
});

after(async () => {
  await idp.stop();
});

for (const [name, auth] of [
  ['client_secret_basic', oauth.ClientSecretBasic('coffre-local-secret')],
  ['client_secret_post', oauth.ClientSecretPost('coffre-local-secret')],
] as const) {
  test(`oauth4webapi completes the code flow (${name})`, async () => {
    const issuer = new URL(idp.issuer);
    const as = await oauth.processDiscoveryResponse(
      issuer,
      await oauth.discoveryRequest(issuer, { [oauth.allowInsecureRequests]: true }),
    );
    const client: oauth.Client = { client_id: 'coffre-local' };

    const verifier = oauth.generateRandomCodeVerifier();
    const state = oauth.generateRandomState();
    const nonce = oauth.generateRandomNonce();
    const url = new URL(as.authorization_endpoint!);
    url.searchParams.set('client_id', client.client_id);
    url.searchParams.set('redirect_uri', REDIRECT_URI);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', await oauth.calculatePKCECodeChallenge(verifier));
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('login_hint', 'admin@acme.example');

    const callback = location(await get(url));
    const params = oauth.validateAuthResponse(as, client, callback, state);

    const response = await oauth.authorizationCodeGrantRequest(as, client, auth, params, REDIRECT_URI, verifier, {
      [oauth.allowInsecureRequests]: true,
    });
    const result = await oauth.processAuthorizationCodeResponse(as, client, response, {
      expectedNonce: nonce,
      requireIdToken: true,
    });
    const claims = oauth.getValidatedIdTokenClaims(result)!;
    assert.equal(claims.iss, idp.issuer);
    assert.equal(claims.aud, 'coffre-local');
    assert.equal(claims.email, 'admin@acme.example');
    assert.equal(claims.nonce, nonce);
    assert.equal(claims.sub, idp.subjectFor('admin@acme.example'));

    const userinfo = await oauth.processUserInfoResponse(
      as,
      client,
      claims.sub,
      await oauth.userInfoRequest(as, client, result.access_token, { [oauth.allowInsecureRequests]: true }),
    );
    assert.equal(userinfo.email, 'admin@acme.example');
  });
}

test('oauth4webapi rejects a callback carrying another issuer', async () => {
  const issuer = new URL(idp.issuer);
  const as = await oauth.processDiscoveryResponse(
    issuer,
    await oauth.discoveryRequest(issuer, { [oauth.allowInsecureRequests]: true }),
  );
  const forged = new URL(`${REDIRECT_URI}?code=x&state=s&iss=${encodeURIComponent('https://evil.example')}`);
  assert.throws(() => oauth.validateAuthResponse(as, { client_id: 'coffre-local' }, forged, 's'));
});
