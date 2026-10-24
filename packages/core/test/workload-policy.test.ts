import test from 'node:test';
import assert from 'node:assert/strict';

import { isCredentialScope } from '../src/access.ts';
import { checkConstraints, constraintsAllow, ConstraintsInvalid, intersect } from '../src/identity/constraints.ts';
import { generateToken, isCoffreToken, tokenHint, tokenKind } from '../src/identity/tokens.ts';
import {
  addressWithin,
  BEARER_PROFILES,
  BindingInvalid,
  checkBinding,
  checkPolicy,
  defaultIssuer,
  freezeTarget,
  OIDC_PROFILES,
  parseCidr,
  policyText,
  PROFILE_URNS,
  REQUIRED_CLAIMS,
  WORKLOAD_PROFILES,
} from '../src/identity/workloads.ts';

const SERVICE = 'token:api-prod';
const ENV = '6b1c2d3e-4f50-4a6b-8c7d-8e9fa0b1c2d3';
const KEY = '0f0e0d0c-0b0a-4908-8706-050403020100';

test("today's five profiles are the bearer ones, and a profile that is no ID token's has its URN for an issuer, and no claims", () => {
  assert.deepEqual([...BEARER_PROFILES], ['github', 'github-reusable', 'github-reusable-organization', 'gitlab', 'custom']);
  assert.deepEqual(WORKLOAD_PROFILES.filter((profile) => !OIDC_PROFILES.includes(profile)), ['aws', 'enrollment', 'cloudflare']);
  for (const [profile, urn] of Object.entries(PROFILE_URNS)) {
    assert.equal(defaultIssuer(profile as keyof typeof PROFILE_URNS), urn);
    assert.equal(checkBinding({ profile, issuer: null, claims: profile === 'aws' ? { account: '671742253563', role_id: 'AROAZ3EXAMPLE7QXYZ' } : {} }).issuer, urn);
    assert.throws(() => checkBinding({ profile, issuer: 'https://evil.example', claims: {} }), BindingInvalid, `${profile}: another issuer`);
    assert.throws(() => checkBinding({ profile, issuer: urn, claims: {} }, { uploaded: true }), BindingInvalid, `${profile}: keys`);
  }
  assert.throws(() => checkBinding({ profile: 'enrollment', issuer: null, claims: { sub: 'x' } }), /names no claims/);
  // An ID token's binding never takes coffre's own URNs, nor defaults to GitHub's issuer.
  assert.throws(() => checkBinding({ profile: 'custom', issuer: 'urn:coffre:aws', claims: { sub: 'x' } }, { uploaded: true }), /coffre's own/);
  assert.equal(defaultIssuer('kubernetes'), null);
  assert.equal(defaultIssuer('gcp'), 'https://accounts.google.com');
  assert.throws(() => checkBinding({ profile: 'kubernetes', issuer: null, claims: {} }), /names its issuer/);
  const cluster = checkBinding({ profile: 'kubernetes', issuer: 'https://cluster.acme.example', claims: { sub: 'system:serviceaccount:api:api', 'kubernetes.io.serviceaccount.uid': '4f1c' } });
  assert.deepEqual(cluster.claims, { 'kubernetes.io.serviceaccount.uid': '4f1c', sub: 'system:serviceaccount:api:api' });
  assert.throws(() => checkBinding({ profile: 'azure', issuer: 'https://sts.windows.net/t/', claims: { tid: 't' } }), /requires oid/);
  for (const profile of WORKLOAD_PROFILES) assert.ok(Array.isArray(REQUIRED_CLAIMS[profile]));
});

test('a policy holds only what its profile allows, and is canonical: one policy, one spelling', () => {
  const policy = checkPolicy('enrollment', {
    onContention: 'freeze',
    sources: ['162.220.232.0/24', '2001:DB8:0:0::/32', '162.220.232.0/24'],
    reads: { [ENV.toUpperCase()]: { keys: [KEY, KEY.toUpperCase()], mints: ['aws', 'aws'] } },
    replicas: 2,
    mintedBy: 'deploy',
    sessionDays: 30,
    overlapMinutes: 15,
    approve: false,
  }, { service: SERVICE });
  assert.equal(policyText(policy), `{"mintedBy":"token:deploy","reads":{"${ENV}":{"keys":["${KEY}"],"mints":["aws"]}},"replicas":2,"sources":["162.220.232.0/24","2001:db8::/32"]}`);
  // The same, said otherwise, is the same text; and checking it again changes nothing.
  const again = checkPolicy('enrollment', { replicas: 2, sources: ['2001:db8::/32', '162.220.232.0/24'], mintedBy: 'token:deploy', reads: { [ENV]: { mints: ['aws'], keys: [KEY] } } }, { service: SERVICE });
  assert.equal(policyText(again), policyText(policy));
  assert.deepEqual(checkPolicy('enrollment', JSON.parse(policyText(policy)), { service: SERVICE }), policy);

  // A platform whose caller picks the audience always names the key in it, said or not; never off.
  for (const profile of ['github', 'github-reusable', 'github-reusable-organization', 'gcp', 'fly'] as const) {
    assert.equal(policyText(checkPolicy(profile, {}, { service: SERVICE })), '{"keyAudience":true}', profile);
    assert.equal(policyText(checkPolicy(profile, { keyAudience: true, sessionHours: 24 }, { service: SERVICE })), '{"keyAudience":true}', profile);
    assert.throws(() => checkPolicy(profile, { keyAudience: false }, { service: SERVICE }), /name the session's key/, profile);
  }
  assert.equal(policyText(checkPolicy('custom', {}, { service: SERVICE })), '{}');
  assert.equal(policyText(checkPolicy('custom', { keyAudience: false }, { service: SERVICE })), '{}');
  assert.equal(policyText(checkPolicy('custom', { keyAudience: true }, { service: SERVICE })), '{"keyAudience":true}');
  assert.equal(policyText(checkPolicy('azure', { audience: 'api://coffre-acme', reads: { [ENV]: { keys: '*' } } }, { service: SERVICE })), `{"audience":"api://coffre-acme","reads":{"${ENV}":{"keys":"*"}}}`);
  // A place listing nothing reads nothing, and is left out.
  assert.equal(policyText(checkPolicy('aws', { reads: { [ENV]: { keys: [] } }, sources: [] }, { service: SERVICE })), '{}');

  const refused: [Parameters<typeof checkPolicy>[0], unknown, RegExp][] = [
    ['github', { audience: 'x' }, /not audience/],
    ['kubernetes', { keyAudience: true }, /not keyAudience/],
    ['azure', {}, /names the audience/],
    ['vercel', { audience: '' }, /exact audience/],
    ['enrollment', {}, /replicas/],
    ['enrollment', { replicas: 0 }, /replicas is a whole number/],
    ['enrollment', { replicas: 2, sessionDays: 91 }, /sessionDays/],
    ['enrollment', { replicas: 2, mintedBy: 'api-prod' }, /mintedBy names another service than service:api-prod/],
    ['enrollment', { replicas: 2, mintedBy: SERVICE }, /mintedBy names another service/],
    ['enrollment', { replicas: 2, onContention: 'ignore' }, /onContention/],
    ['enrollment', { replicas: 2, sessionHours: 4 }, /not sessionHours/],
    ['aws', { sessionHours: 169 }, /sessionHours/],
    ['aws', { sources: ['162.220.232.5/24'] }, /CIDRs/],
    ['aws', { sources: ['not an address'] }, /CIDRs/],
    ['aws', { reads: { 'market/prod': { keys: [] } } }, /by ID/],
    ['aws', { reads: { [ENV]: { keys: ['STRIPE_SECRET_KEY'] } } }, /IDs/],
    ['aws', { reads: { [ENV]: { keys: [KEY], values: true } } }, /not values/],
    ['aws', { reads: { [ENV]: {}, [ENV.toUpperCase()]: {} } }, /twice/],
    ['cloudflare', { sources: ['10.0.0.0/8'] }, /not sources/],
    ['custom', { keyAudience: 'yes' }, /true or false/],
    ['custom', [], /an object/],
  ];
  for (const [profile, input, message] of refused) assert.throws(() => checkPolicy(profile, input, { service: SERVICE }), message, `${profile} ${JSON.stringify(input)}`);
});

test('a CIDR has one spelling, and an address is within it or not, IPv4 and IPv6 apart', () => {
  assert.equal(parseCidr('10.0.0.0/8')?.text, '10.0.0.0/8');
  assert.equal(parseCidr('2001:0DB8:0000:0000:0000:0000:0000:0000/32')?.text, '2001:db8::/32');
  assert.equal(parseCidr('2001:db8:0:1:0:0:0:0/64')?.text, '2001:db8:0:1::/64');
  // RFC 5952: the longest run of zero groups is `::`, and of two as long, the first.
  assert.equal(parseCidr('2001:db8:0:0:1:0:0:0/80')?.text, '2001:db8:0:0:1::/80');
  assert.equal(parseCidr('2001:db8:0:0:1:0:0:1/128')?.text, '2001:db8::1:0:0:1/128');
  assert.equal(parseCidr('2001:db8:1:0:1:1:1:1/128')?.text, '2001:db8:1:0:1:1:1:1/128');
  assert.equal(parseCidr('::/0')?.text, '::/0');
  for (const bad of ['10.0.0.1/8', '10.0.0.0/33', '10.0.0/8', '010.0.0.0/8', '10.0.0.0', '::1::/128', '2001:db8::/129', 'fe80::1%eth0/128', '1.2.3.4/08']) {
    assert.equal(parseCidr(bad), null, bad);
  }
  assert.ok(addressWithin('162.220.232.17', ['162.220.232.0/24']));
  assert.ok(!addressWithin('162.220.233.17', ['162.220.232.0/24']));
  assert.ok(addressWithin('2001:db8::5', ['10.0.0.0/8', '2001:db8::/32']));
  assert.ok(!addressWithin('::ffff:a00:1', ['10.0.0.0/8']), 'an IPv4-mapped address is IPv6, and fails closed');
  assert.ok(!addressWithin('not an address', ['0.0.0.0/0']));
  assert.ok(addressWithin('203.0.113.9', ['0.0.0.0/0']));
});

test('a freeze target has one spelling, or none', () => {
  assert.equal(freezeTarget('instance'), 'instance');
  assert.equal(freezeTarget('token:api-prod'), 'token:api-prod');
  assert.equal(freezeTarget(`binding:${KEY.toUpperCase()}`), `binding:${KEY}`);
  assert.equal(freezeTarget(`session:${KEY}`), `session:${KEY}`);
  assert.equal(freezeTarget(`credential:${ENV.toUpperCase()}/stripe`), `credential:${ENV}/stripe`);
  for (const bad of ['tokenx', 'tokens', 'instancex', 'Instance', 'token:', 'token:a b', 'binding:x', `credential:${ENV}`, `credential:${ENV}/Stripe`, `credential:${ENV}/a/b`, 'credential:market/prod/stripe', `secret:${KEY}`, '']) {
    assert.equal(freezeTarget(bad), null, bad);
  }
});

test("a workload's session and an enrollment code are tokens of their own kinds, which a scanner tells by prefix", () => {
  for (const kind of ['workload', 'enrollment'] as const) {
    const token = generateToken(kind);
    assert.match(token, kind === 'workload' ? /^coffre_wl_[A-Za-z0-9_-]{43}$/ : /^coffre_enr_[A-Za-z0-9_-]{43}$/);
    assert.ok(isCoffreToken(token));
    assert.equal(tokenKind(token), kind);
    assert.equal(tokenHint(token), `${kind === 'workload' ? 'coffre_wl_' : 'coffre_enr_'}…${token.slice(-4)}`);
  }
  assert.equal(tokenKind(`coffre_wlx_${'A'.repeat(43)}`), null);
});

test("a scope's grant may carry a workload's reads, by ID or every key", () => {
  const grant = { projectId: 'p', environmentId: 'e', role: 'viewer' };
  assert.ok(isCredentialScope([{ ...grant, reads: [KEY] }]));
  assert.ok(isCredentialScope([{ ...grant, reads: '*' }]));
  assert.ok(!isCredentialScope([{ ...grant, reads: [KEY, KEY] }]));
  assert.ok(!isCredentialScope([{ ...grant, reads: 'STRIPE' }]));
});

test("a child's constraints are checked and canonical, and its operations held to them on the URL sent", () => {
  const child = checkConstraints({ credentials: ['stripe', 'stripe'], methods: ['post'], paths: ['/v1/refunds', '/v1/refunds/re_1'] });
  assert.deepEqual(child, { credentials: ['stripe'], methods: ['POST'], paths: ['/v1/refunds'] });
  for (const bad of [{ paths: ['v1'] }, { paths: ['/v1/'] }, { paths: ['/v1/%2e'] }, { paths: ['/v1/../x'] }, { paths: ['/v1;x'] }, { methods: ['get it'] }, { places: ['market'] }, { credentials: ['Stripe'] }, { extra: [] }]) {
    assert.throws(() => checkConstraints(bad), ConstraintsInvalid, JSON.stringify(bad));
  }
  const at = (url: string, method = 'POST') => constraintsAllow(child, { place: 'market/prod', credential: 'stripe', request: { method, url } });
  assert.ok(at('https://api.stripe.com/v1/refunds'));
  assert.ok(at('https://api.stripe.com/v1/refunds/re_1?expand[]=x'));
  assert.ok(!at('https://api.stripe.com/v1/refundsX'));
  assert.ok(!at('https://api.stripe.com/v1/refunds/%2e%2e/charges'));
  assert.ok(!at('https://api.stripe.com/v1/refunds/..;/charges'));
  assert.ok(!at('https://api.stripe.com/v1/refunds/re%2F1'));
  assert.ok(!at('https://api.stripe.com/v1/refunds/re%252e'));
  assert.ok(!at('https://api.stripe.com/v1/refunds', 'GET'));
  assert.ok(at('https://api.stripe.com/v1/refunds', 'post'), 'post is POST, as Fetch sends it');
  assert.ok(!constraintsAllow({ methods: ['PATCH'] }, { place: 'market/prod', credential: 'stripe', request: { method: 'patch', url: 'https://api.stripe.com/v1' } }), 'patch is not PATCH');
  assert.ok(!constraintsAllow(child, { place: 'market/prod', credential: 'openai', request: { method: 'POST', url: 'https://api.openai.com/v1/refunds' } }));
  // No request to check: sign, verify, mint and the tunnel are refused wherever methods or paths are limited.
  assert.ok(!constraintsAllow(child, { place: 'market/prod', credential: 'stripe' }));
  assert.ok(constraintsAllow({ credentials: ['stripe'] }, { place: 'market/prod', credential: 'stripe' }));
  assert.ok(constraintsAllow(null, { place: 'market/prod', credential: 'anything' }));

  assert.deepEqual(intersect({ credentials: ['stripe', 'openai'], paths: ['/v1'] }, child), { credentials: ['stripe'], methods: ['POST'], paths: ['/v1/refunds'] });
  assert.deepEqual(intersect({ paths: ['/v1/refunds/re_1'] }, { paths: ['/v1'] }), { paths: ['/v1/refunds/re_1'] });
  assert.deepEqual(intersect({ credentials: ['stripe'] }, { credentials: ['openai'] }), { credentials: [] });
});
