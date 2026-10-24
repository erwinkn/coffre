import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign as signWith } from 'node:crypto';

import {
  BindingInvalid,
  checkBinding,
  checkPolicy,
  differingClaims,
  REQUIRED_CLAIMS,
  verifyWorkloadToken,
  WorkloadTokenRefused,
  type BindingClaims,
  type JSONWebKeySet,
  type WorkloadProfile,
} from '@coffre/core/identity';

import { expectedAudiences, PROFILE_RULES } from '../src/workloads/profiles.ts';

/**
 * A token of each platform, shaped from its documentation (none of these
 * has an account to sign one live: section 12.1), and the binding that
 * names its workload: each verifies and matches, and each of its
 * profile's required claims, left out, refuses it.
 */

const ORIGIN = 'https://secrets.acme.example';
const SERVICE = 'token:web';
const JKT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
const OTHER_KEY = 'Ab3dLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9X';
const TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';
const OBJECT = '4c1d3b2a-9f8e-4d7c-b6a5-0123456789ab';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const KEYS: JSONWebKeySet = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' }] as JSONWebKeySet['keys'] };
const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const seconds = () => Math.floor(Date.now() / 1000);

function jwt(claims: Record<string, unknown>): string {
  const input = `${part({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${part(claims)}`;
  return `${input}.${signWith('sha256', Buffer.from(input), privateKey).toString('base64url')}`;
}

type Platform = {
  profile: WorkloadProfile;
  issuer: string | null;
  claims: BindingClaims;
  policy?: Record<string, unknown>;
  /** What the platform signs, but `iat`, `exp` and the audience. */
  token: Record<string, unknown>;
  /** How long the platform's token lives, in seconds. */
  lifetime: number;
  /** Another workload's value of each claim the binding names. */
  another: Record<string, string>;
};

const KUBERNETES_ISSUER = 'https://oidc.prod.acme.example';
const SA_UID = '8f2d6a1e-5b3c-4e7f-9a0b-1c2d3e4f5a6b';
const PLATFORMS: Record<'kubernetes' | 'gcp' | 'azure' | 'fly' | 'vercel', Platform> = {
  // A projected service account token (kubernetes.io/docs, "Service account token volume projection").
  kubernetes: {
    profile: 'kubernetes',
    issuer: KUBERNETES_ISSUER,
    claims: { sub: 'system:serviceaccount:ingest:api', 'kubernetes.io.serviceaccount.uid': SA_UID },
    token: {
      iss: KUBERNETES_ISSUER,
      sub: 'system:serviceaccount:ingest:api',
      jti: randomUUID(),
      'kubernetes.io': {
        namespace: 'ingest',
        node: { name: 'node-1', uid: randomUUID() },
        pod: { name: 'api-7c9f5d8b6-x2k4q', uid: randomUUID() },
        serviceaccount: { name: 'api', uid: SA_UID },
      },
    },
    lifetime: 600,
    another: { sub: 'system:serviceaccount:ingest:other', 'kubernetes.io.serviceaccount.uid': randomUUID() },
  },
  // The metadata server's identity token, format=full (cloud.google.com, "Verifying the identity of instances").
  gcp: {
    profile: 'gcp',
    issuer: null,
    claims: { sub: '104729384756102938475' },
    token: {
      iss: 'https://accounts.google.com',
      azp: '104729384756102938475',
      sub: '104729384756102938475',
      email: 'web@acme-prod.iam.gserviceaccount.com',
      email_verified: true,
      google: { compute_engine: { project_id: 'acme-prod', zone: 'europe-west1-b', instance_id: '5012345678901234567', instance_name: 'web-1' } },
    },
    lifetime: 3600,
    another: { sub: '104729384756102938476' },
  },
  // A managed identity's access token for a registered resource, v1 (learn.microsoft.com, "Access token claims reference").
  azure: {
    profile: 'azure',
    issuer: `https://sts.windows.net/${TENANT}/`,
    claims: { tid: TENANT, oid: OBJECT },
    policy: { audience: 'api://coffre-acme' },
    token: {
      iss: `https://sts.windows.net/${TENANT}/`,
      idp: `https://sts.windows.net/${TENANT}/`,
      tid: TENANT,
      oid: OBJECT,
      sub: OBJECT,
      appid: '6c3b1a2d-0e9f-4a8b-b7c6-d5e4f3a2b1c0',
      appidacr: '2',
      ver: '1.0',
      xms_mirid: '/subscriptions/0b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e/resourcegroups/web/providers/Microsoft.ManagedIdentity/userAssignedIdentities/web',
    },
    lifetime: 86_400,
    another: { oid: randomUUID() },
  },
  // A machine's token from /.fly/api (fly.io/docs, "OpenID Connect").
  fly: {
    profile: 'fly',
    issuer: 'https://oidc.fly.io/acme',
    claims: { org_id: '29873298', app_id: '3671581' },
    token: {
      iss: 'https://oidc.fly.io/acme',
      sub: 'acme:web:3d8d9e0ce77789',
      app_id: '3671581',
      app_name: 'web',
      org_id: '29873298',
      org_name: 'acme',
      machine_id: '3d8d9e0ce77789',
      machine_name: 'web-1',
      machine_version: '01HZ0Q8B6Y5J8X9N3W2V1T0S9R',
      image: 'registry.fly.io/web:deployment-01HZ0Q8B6Y5J8X9N3W2V1T0S9R',
      image_digest: `sha256:${'a'.repeat(64)}`,
      region: 'cdg',
      jti: randomUUID(),
    },
    lifetime: 600,
    another: { org_id: '29873299', app_id: '3671582' },
  },
  // A function's token, exchanged for an audience of its choosing (vercel.com/docs, "OIDC reference"; @vercel/oidc's exchangeVercelOidcToken).
  vercel: {
    profile: 'vercel',
    issuer: 'https://oidc.vercel.com/acme',
    claims: { owner_id: 'team_7Gw5ZMBpQA8h9GF832KGp7nw', project_id: 'prj_8bFh2nVq3eDcJ7tY5mWx', environment: 'production' },
    token: {
      iss: 'https://oidc.vercel.com/acme',
      sub: 'owner:acme:project:web:environment:production',
      scope: 'owner:acme:project:web:environment:production',
      owner: 'acme',
      owner_id: 'team_7Gw5ZMBpQA8h9GF832KGp7nw',
      project: 'web',
      project_id: 'prj_8bFh2nVq3eDcJ7tY5mWx',
      environment: 'production',
    },
    lifetime: 3600,
    another: { owner_id: 'team_0000000000000000000000', project_id: 'prj_00000000000000000000', environment: 'preview' },
  },
};

/** The binding the platform's workload is bound by, made as binding creation makes it: checked, its policy, then the platform's own rules. */
function bindingOf(platform: Platform) {
  const binding = checkBinding({ profile: platform.profile, issuer: platform.issuer, claims: platform.claims });
  const policy = checkPolicy(binding.profile, platform.policy ?? {}, { service: SERVICE });
  PROFILE_RULES[binding.profile]!.binding(binding, policy);
  return { ...binding, policy };
}

/** Why the exchange refuses a token for a binding, or null: verified for the audience its SDK asks for, its claims matched, then its platform's rules. */
async function refusal(platform: Platform, token: Record<string, unknown>, jkt = JKT): Promise<string | null> {
  const binding = bindingOf(platform);
  const [audience] = expectedAudiences(binding.profile, binding.policy, { publicUrl: ORIGIN, jkt });
  let claims: Record<string, unknown>;
  try {
    claims = await verifyWorkloadToken(jwt(token), KEYS, { issuer: binding.issuer, audience: audience!, now: new Date() });
  } catch (error) {
    if (error instanceof WorkloadTokenRefused) return error.reason;
    throw error;
  }
  const differing = differingClaims(binding.profile, binding.claims, claims);
  if (differing.length > 0) return `no_match: ${differing.join(', ')}`;
  return PROFILE_RULES[binding.profile]!.token(claims, binding);
}

function issued(platform: Platform, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const binding = bindingOf(platform);
  const [aud] = expectedAudiences(binding.profile, binding.policy, { publicUrl: ORIGIN, jkt: JKT });
  const iat = seconds() - 5;
  return { ...platform.token, aud: platform.profile === 'kubernetes' ? [aud] : aud, iat, nbf: iat, exp: iat + platform.lifetime, ...extra };
}

/** The token without a claim, at the top or nested where `claimAt` reads it. */
function without(token: Record<string, unknown>, name: string): Record<string, unknown> {
  const copy = structuredClone(token);
  if (name in copy) {
    delete copy[name];
    return copy;
  }
  const at = name.indexOf('.', name.indexOf('kubernetes.io') === 0 ? 'kubernetes.io'.length : 0);
  let node = copy[name.slice(0, at)] as Record<string, unknown>;
  const path = name.slice(at + 1).split('.');
  for (const step of path.slice(0, -1)) node = node[step] as Record<string, unknown>;
  delete node[path.at(-1)!];
  return copy;
}

for (const [name, platform] of Object.entries(PLATFORMS)) {
  test(`a ${name} token verifies and matches its binding, and each claim its profile requires, left out, refuses it`, async () => {
    assert.equal(await refusal(platform, issued(platform)), null);
    const required = REQUIRED_CLAIMS[platform.profile];
    assert.ok(required.length > 0);
    for (const claim of required) {
      const outcome = await refusal(platform, without(issued(platform), claim));
      // Every such claim is matched; a token without `sub`, which every token carries, is malformed before.
      assert.ok(outcome !== null && (outcome.includes(claim) || (claim === 'sub' && outcome === 'malformed')), `${name} without ${claim}: ${outcome}`);
    }
    // Another workload's value, for every claim but the tenant, which names the issuer too, is no match either.
    for (const [claim, value] of Object.entries(platform.another)) {
      const outcome = await refusal({ ...platform, claims: { ...platform.claims, [claim]: value } }, issued(platform));
      assert.ok(outcome?.startsWith('no_match'), `${name} bound to another ${claim}: ${outcome}`);
    }
  });
}

test('gcp, fly and vercel tokens name the key in their audience: one for the publicUrl alone, or another key, is refused', async () => {
  for (const platform of [PLATFORMS.gcp, PLATFORMS.fly, PLATFORMS.vercel]) {
    assert.deepEqual(checkPolicy(platform.profile, {}, { service: SERVICE }), { keyAudience: true });
    assert.deepEqual(expectedAudiences(platform.profile, { keyAudience: true }, { publicUrl: ORIGIN, jkt: JKT }), [`${ORIGIN}#jkt=${JKT}`, `${ORIGIN}?jkt=${JKT}`]);
    assert.equal(await refusal(platform, issued(platform, { aud: ORIGIN })), 'audience', `${platform.profile} for ${ORIGIN} alone`);
    assert.equal(await refusal(platform, issued(platform), OTHER_KEY), 'audience', `${platform.profile} naming another key`);
  }
  // Vercel's audience is the function's to choose (`getVercelOidcToken({ audience })`): a binding names none.
  assert.throws(() => checkPolicy('vercel', { audience: 'https://vercel.com/acme' }, { service: SERVICE }), /not audience/);
  // Azure's is the resource's, fixed, and its binding names it; Kubernetes' is the projected volume's, this instance's URL.
  assert.deepEqual(expectedAudiences('azure', { audience: 'api://coffre-acme' }, { publicUrl: ORIGIN, jkt: JKT }), ['api://coffre-acme']);
  assert.deepEqual(expectedAudiences('kubernetes', {}, { publicUrl: ORIGIN, jkt: JKT }), [ORIGIN]);
  assert.equal(await refusal(PLATFORMS.azure, issued(PLATFORMS.azure, { aud: ORIGIN })), 'audience');
});

test("a token is refused where its platform's own facts disagree with it", async () => {
  // Entra issues v1 tokens under sts.windows.net and v2 under login.microsoftonline.com, never the other way.
  assert.match(String(await refusal(PLATFORMS.azure, issued(PLATFORMS.azure, { ver: '2.0' }))), /version "2.0".*issues 1.0/);
  const v2 = { ...PLATFORMS.azure, issuer: `https://login.microsoftonline.com/${TENANT}/v2.0` };
  assert.equal(await refusal(v2, issued(v2, { iss: v2.issuer, ver: '2.0' })), null);
  assert.match(String(await refusal(v2, issued(v2, { iss: v2.issuer }))), /version "1.0"/);
  // A cluster names the service account in sub and under kubernetes.io alike.
  const kubernetes = PLATFORMS.kubernetes;
  const moved = issued(kubernetes);
  (moved['kubernetes.io'] as Record<string, unknown>).namespace = 'other';
  assert.match(String(await refusal(kubernetes, moved)), /another service account/);
});

test("a binding is refused where it names a platform's IDs in another shape, or its issuer in another form", () => {
  const refused: [Platform, RegExp][] = [
    [{ ...PLATFORMS.kubernetes, claims: { ...PLATFORMS.kubernetes.claims, sub: 'api' } }, /system:serviceaccount:<namespace>:<name>/],
    [{ ...PLATFORMS.kubernetes, claims: { ...PLATFORMS.kubernetes.claims, 'kubernetes.io.serviceaccount.uid': 'api' } }, /service account's UID/],
    [{ ...PLATFORMS.kubernetes, claims: { ...PLATFORMS.kubernetes.claims, 'kubernetes.io.namespace': 'other' } }, /kubernetes.io.namespace is ingest/],
    [{ ...PLATFORMS.gcp, claims: { sub: 'web@acme-prod.iam.gserviceaccount.com' } }, /unique ID, its digits/],
    [{ ...PLATFORMS.azure, claims: { tid: TENANT, oid: 'web' } }, /object ID/],
    [{ ...PLATFORMS.azure, claims: { tid: randomUUID(), oid: OBJECT } }, /tid is the tenant its issuer names/],
    [{ ...PLATFORMS.azure, issuer: `https://login.microsoftonline.com/${TENANT}/` }, /v2\.0/],
    [{ ...PLATFORMS.azure, issuer: 'https://sts.windows.net/acme.onmicrosoft.com/' }, /tenant's ID/],
    [{ ...PLATFORMS.fly, claims: { org_id: '29873298', app_id: 'web app' } }, /app's ID/],
    [{ ...PLATFORMS.fly, issuer: 'https://oidc.fly.io/acme/web' }, /oidc.fly.io\/<organization>/],
    [{ ...PLATFORMS.vercel, claims: { ...PLATFORMS.vercel.claims, project_id: 'web' } }, /prj_/],
    [{ ...PLATFORMS.vercel, claims: { ...PLATFORMS.vercel.claims, environment: 'Production ' } }, /environment/],
    [{ ...PLATFORMS.vercel, issuer: 'https://oidc.vercel.com/acme/web' }, /team mode/],
    [{ profile: 'aws', issuer: null, claims: { account: '671742253563', role_id: 'AIDAZ3EXAMPLEUSER001' }, token: {}, lifetime: 0, another: {} }, /AROA/],
    [{ profile: 'aws', issuer: null, claims: { account: '6717-4225-3563', role_id: 'AROAZ3EXAMPLE7QXYZAB' }, token: {}, lifetime: 0, another: {} }, /12 digits/],
    [{ profile: 'aws', issuer: null, claims: { account: '671742253563', role_id: 'AROAZ3EXAMPLE7QXYZAB', session: 'ingest-fn' }, token: {}, lifetime: 0, another: {} }, /account and role_id alone, not session/],
  ];
  for (const [platform, message] of refused) {
    assert.throws(() => bindingOf(platform), (error: unknown) => error instanceof BindingInvalid && message.test(error.message), `${platform.profile} ${JSON.stringify(platform.claims)} ${platform.issuer}`);
  }
  assert.doesNotThrow(() => bindingOf({ profile: 'aws', issuer: null, claims: { account: '671742253563', role_id: 'AROAZ3EXAMPLE7QXYZAB' }, token: {}, lifetime: 0, another: {} }));
  // Vercel's global issuer, and a custom environment.
  assert.doesNotThrow(() => bindingOf({ ...PLATFORMS.vercel, issuer: 'https://oidc.vercel.com', claims: { ...PLATFORMS.vercel.claims, environment: 'staging' } }));
});
