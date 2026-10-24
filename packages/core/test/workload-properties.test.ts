import assert from 'node:assert/strict';
import test from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';

import { base64url, bodyDigest, createProof, generateProofKey, UNSIGNED_HEADERS, type ProofKey } from '@coffre/client/dpop';

import { constraintsAllow, intersect, type Constraints } from '../src/identity/constraints.ts';
import { canonicalHtu, parseProof, thumbprint, verifyProof } from '../src/identity/dpop.ts';
import { checkPolicy, policyText, POLICY_FIELDS, type WorkloadProfile } from '../src/identity/workloads.ts';
import { propertySettings } from './properties.ts';

// Properties of docs/design/workload-access.md's PR 0 (section 12): what a
// proof signs, and the canonical forms both sides compute. Each is checked
// against what it must be, not against how the code gets there.

const ORIGIN = 'https://secrets.acme.example';
const NOW = 1_792_805_400;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const ENCODER = new TextEncoder();

const segment = gs.fromRegex('[A-Za-z0-9._~-]{1,8}', { fullmatch: true });
const headerName = gs.fromRegex('[a-z][a-z0-9-]{0,10}', { fullmatch: true }).filter((name) => !UNSIGNED_HEADERS.has(name));
const headerValue = gs.fromRegex('[ -~]{0,16}', { fullmatch: true }).map((value) => value.trim());
const query = gs.fromRegex('([a-z]{1,4}=[a-z0-9%]{0,6})(&[a-z]{1,4}=[a-z0-9]{0,6}){0,3}', { fullmatch: true });

type Request = { method: string; url: string; headers: [string, string][]; body: Uint8Array; token: string };

const request = gs.composite((tc): Request => {
  const path = tc.draw(gs.arrays(segment, { minSize: 1, maxSize: 4 })).join('/');
  const q = tc.draw(gs.optional(query));
  const names = [...new Set(tc.draw(gs.arrays(headerName, { maxSize: 5 })))];
  return {
    method: tc.draw(gs.sampledFrom(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])),
    url: `${ORIGIN}/use/${path}${q === null ? '' : `?${q}`}`,
    headers: names.map((name) => [name, tc.draw(headerValue)]),
    body: tc.draw(gs.binary({ maxSize: 64 })),
    token: `coffre_wl_${tc.draw(gs.fromRegex('[A-Za-z0-9_-]{43}', { fullmatch: true }))}`,
  };
});

async function proofFor(key: ProofKey, r: Request): Promise<string> {
  return createProof(key, { method: r.method, url: r.url, token: r.token, nonce: 'g1.epoch', content: { headers: r.headers, body: await bodyDigest(r.body) }, iat: NOW });
}

async function check(key: ProofKey, proof: string, r: Request) {
  return verifyProof(proof, { method: r.method, url: r.url, jkt: await thumbprint(key.jwk), token: r.token, content: { headers: new Headers(r.headers), body: await bodyDigest(r.body) }, now: NOW * 1000 });
}

const MUTATIONS = ['method', 'path', 'query', 'header', 'body', 'token', 'claim', 'signature'] as const;

const settings = propertySettings(48);
let key: ProofKey;
test.before(async () => {
  key = await generateProofKey();
});

test(`a proof verifies for its request, its signature twin with the same jti, and any one change to what it signs is refused, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const r = tc.draw(request);
  const proof = await proofFor(key, r);
  const verified = await check(key, proof, r);
  assert.ok(verified.ok, JSON.stringify(verified));

  const parsed = parseProof(proof);
  assert.ok(parsed.ok);
  const s = BigInt(`0x${Buffer.from(parsed.signature.slice(32)).toString('hex')}`);
  const twin = `${parsed.signingInput}.${base64url(Buffer.concat([Buffer.from(parsed.signature.slice(0, 32)), Buffer.from((N - s).toString(16).padStart(64, '0'), 'hex')]))}`;
  const twinVerified = await check(key, twin, r);
  assert.ok(twinVerified.ok && twinVerified.jti === verified.jti, 'the twin carries the one jti');

  const mutation = tc.draw(gs.sampledFrom(MUTATIONS));
  const changed: Request = { ...r, headers: r.headers.map(([name, value]) => [name, value]) };
  let sent = proof;
  switch (mutation) {
    case 'method':
      changed.method = r.method === 'GET' ? 'POST' : 'GET';
      break;
    case 'path':
      changed.url = r.url.replace('/use/', '/use/x');
      break;
    case 'query': {
      const url = new URL(r.url);
      url.search = url.search === '' ? '?a=1' : `${url.search}x`;
      changed.url = url.href;
      break;
    }
    case 'header':
      if (changed.headers.length === 0) changed.body = Uint8Array.of(...r.body, 1);
      else changed.headers[0]![1] = `${changed.headers[0]![1]}x`;
      break;
    case 'body':
      changed.body = r.body.length === 0 ? Uint8Array.of(0) : Uint8Array.from(r.body, (byte, i) => (i === 0 ? byte ^ 1 : byte));
      break;
    case 'token':
      changed.token = `${r.token.slice(0, -1)}${r.token.endsWith('A') ? 'B' : 'A'}`;
      break;
    case 'claim': {
      // Any claim changed after signing, whichever: the signature covers each.
      const claims = { ...parsed.claims } as Record<string, unknown>;
      const name = tc.draw(gs.sampledFrom(Object.keys(claims)));
      claims[name] = typeof claims[name] === 'number' ? (claims[name] as number) + 1 : `${String(claims[name]).slice(0, -1)}${String(claims[name]).endsWith('A') ? 'B' : 'A'}`;
      sent = `${parsed.signingInput.split('.')[0]}.${base64url(ENCODER.encode(JSON.stringify(claims)))}.${proof.split('.')[2]}`;
      break;
    }
    case 'signature': {
      const bytes = Uint8Array.from(parsed.signature);
      const at = tc.draw(gs.integers({ minValue: 0, maxValue: 63 }));
      bytes[at] = bytes[at]! ^ (1 << tc.draw(gs.integers({ minValue: 0, maxValue: 7 })));
      sent = `${parsed.signingInput}.${base64url(bytes)}`;
      break;
    }
  }
  const refused = await check(key, sent, changed);
  assert.ok(!refused.ok, `${mutation} was taken`);
}, settings));

test(`the thumbprint is the key's whatever order the proof lists its members in, seed ${settings.seed}`, () => hegel.testAsync(async (tc) => {
  const members = tc.draw(gs.composite((inner) => {
    const order = ['kty', 'crv', 'x', 'y'];
    for (let i = order.length - 1; i > 0; i--) {
      const j = inner.draw(gs.integers({ minValue: 0, maxValue: i }));
      [order[i], order[j]] = [order[j]!, order[i]!];
    }
    return order;
  }));
  const jwk = Object.fromEntries(members.map((name) => [name, key.jwk[name as keyof typeof key.jwk]]));
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk };
  const claims = { jti: base64url(new Uint8Array(16)), htm: 'GET', htu: `${ORIGIN}/use/x`, iat: NOW };
  const input = `${base64url(ENCODER.encode(JSON.stringify(header)))}.${base64url(ENCODER.encode(JSON.stringify(claims)))}`;
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, ENCODER.encode(input)));
  const verified = await verifyProof(`${input}.${base64url(signature)}`, { method: 'GET', url: claims.htu, jkt: await thumbprint(key.jwk), now: NOW * 1000 });
  assert.ok(verified.ok, JSON.stringify(verified));
}, propertySettings(16)));

const UNRESERVED = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'.split('').map((char) => char.charCodeAt(0)));
const pathPart = gs.oneOf(
  gs.fromRegex('[A-Za-z0-9._~!$&\'()*+,;=:@-]{1,4}', { fullmatch: true }),
  gs.integers({ minValue: 0, maxValue: 255 }).flatMap((code) => gs.booleans().map((upper) => `%${code.toString(16).padStart(2, '0')[upper ? 'toUpperCase' : 'toLowerCase']()}`)),
  gs.sampledFrom(['/', '//', '/./', '/../', '\\']),
);

test(`canonicalHtu is idempotent, drops the query, and keeps every escape but an unreserved character's, seed ${settings.seed}`, () => hegel.test((tc) => {
  const path = tc.draw(gs.arrays(pathPart, { maxSize: 12 })).join('');
  const host = tc.draw(gs.sampledFrom(['Secrets.Acme.Example', 'secrets.acme.example:443', 'SECRETS.acme.example:8443']));
  const input = `HTTPS://${host}/${path}?q=1#f`;
  const once = canonicalHtu(input);
  assert.equal(canonicalHtu(once), once, input);
  assert.ok(once.startsWith('https://secrets.acme.example'), once);
  assert.ok(!once.includes('?') && !once.includes('#') && !once.includes('\\') && !once.slice('https://'.length).includes('//'), once);
  // An escape left is an escape of what needs one, in upper case; an unreserved character is never escaped.
  for (const [, code] of once.matchAll(/%(..)/g)) {
    assert.match(code!, /^[0-9A-F]{2}$/);
    assert.ok(!UNRESERVED.has(parseInt(code!, 16)), `${code} escapes an unreserved character`);
  }
  // Every escape of a reserved character in the path survives.
  const resolved = new URL(input).pathname;
  const kept = [...resolved.matchAll(/%([0-9A-Fa-f]{2})/g)].map(([, code]) => code!.toUpperCase()).filter((code) => !UNRESERVED.has(parseInt(code, 16)));
  assert.deepEqual([...once.matchAll(/%([0-9A-F]{2})/g)].map(([, code]) => code), kept);
}, propertySettings(256)));

const ENVIRONMENTS = ['6b1c2d3e-4f50-4a6b-8c7d-8e9fa0b1c2d3', 'a0b1c2d3-e4f5-4061-8273-8495a6b7c8d9'];
const KEYS = ['0f0e0d0c-0b0a-4908-8706-050403020100', 'ffeeddcc-bbaa-4998-8776-554433221100', '12345678-9abc-4def-8123-456789abcdef'];

/** A valid policy for `profile`, as some caller might spell it: in any order, IDs in any case, lists repeated, defaults said or not. */
function spelled(tc: hegel.TestCase, profile: WorkloadProfile): Record<string, unknown> {
  const allowed = POLICY_FIELDS[profile];
  const policy: Record<string, unknown> = {};
  const caseOf = (id: string) => (tc.draw(gs.booleans()) ? id.toUpperCase() : id);
  const some = <T>(items: readonly T[]) => tc.draw(gs.arrays(gs.sampledFrom(items), { maxSize: 4 }));
  for (const field of allowed) {
    if (field !== 'audience' && field !== 'replicas' && !tc.draw(gs.booleans())) continue;
    switch (field) {
      case 'audience': policy.audience = tc.draw(gs.sampledFrom(['api://coffre-acme', 'https://vercel.com/acme'])); break;
      case 'keyAudience': policy.keyAudience = tc.draw(gs.booleans()); break;
      case 'reads': policy.reads = Object.fromEntries(some(ENVIRONMENTS).filter((id, i, all) => all.indexOf(id) === i).map((id) => [caseOf(id), {
        ...(tc.draw(gs.booleans()) ? { keys: tc.draw(gs.booleans()) ? '*' : some(KEYS).map(caseOf) } : {}),
        ...(tc.draw(gs.booleans()) ? { mints: some(['aws', 'github', 'r2']) } : {}),
      }])); break;
      case 'sources': policy.sources = some(['10.0.0.0/8', '2001:DB8::/32', '2001:db8:0:0::/32', '162.220.232.0/24']); break;
      case 'sessionHours': policy.sessionHours = tc.draw(gs.integers({ minValue: 1, maxValue: 168 })); break;
      case 'replicas': policy.replicas = tc.draw(gs.integers({ minValue: 1, maxValue: 64 })); break;
      case 'sessionDays': policy.sessionDays = tc.draw(gs.integers({ minValue: 1, maxValue: 90 })); break;
      case 'overlapMinutes': policy.overlapMinutes = tc.draw(gs.integers({ minValue: 1, maxValue: 60 })); break;
      case 'mintedBy': policy.mintedBy = tc.draw(gs.sampledFrom(['deploy', 'token:deploy'])); break;
      case 'approve': policy.approve = tc.draw(gs.booleans()); break;
      case 'onContention': policy.onContention = tc.draw(gs.sampledFrom(['freeze', 'alert'])); break;
      case 'unsignedUploads': policy.unsignedUploads = tc.draw(gs.booleans()); break;
    }
  }
  return Object.fromEntries(Object.entries(policy).sort(() => (tc.draw(gs.booleans()) ? 1 : -1)));
}

/** What a policy means, from any spelling of it: the model `checkPolicy` must agree with. */
function meaning(profile: WorkloadProfile, policy: Record<string, unknown>) {
  const reads = policy.reads === undefined ? {} : Object.fromEntries(Object.entries(policy.reads as Record<string, { keys?: string[] | '*'; mints?: string[] }>).map(([id, read]) => [id.toLowerCase(), {
    keys: read.keys === '*' ? '*' : [...new Set((read.keys ?? []).map((key) => key.toLowerCase()))].sort(),
    mints: [...new Set(read.mints ?? [])].sort(),
  }]).filter(([, read]) => (read as { keys: unknown }).keys === '*' || ((read as { keys: string[] }).keys.length > 0) || (read as { mints: string[] }).mints.length > 0));
  return {
    profile,
    audience: policy.audience ?? null,
    keyAudience: policy.keyAudience === true,
    reads,
    sources: [...new Set(((policy.sources ?? []) as string[]).map((source) => (source.toLowerCase().startsWith('2001:db8') ? '2001:db8::/32' : source)))].sort(),
    sessionHours: policy.sessionHours ?? 24,
    replicas: policy.replicas ?? null,
    sessionDays: policy.sessionDays ?? 30,
    overlapMinutes: policy.overlapMinutes ?? 15,
    mintedBy: policy.mintedBy === undefined ? null : String(policy.mintedBy).replace(/^(token:)?/, 'token:'),
    approve: policy.approve === true,
    onContention: policy.onContention ?? 'freeze',
    unsignedUploads: policy.unsignedUploads === true,
  };
}

test(`a policy has one spelling: two that mean the same are the same text, and the text checks as itself, seed ${settings.seed}`, () => hegel.test((tc) => {
  const profile = tc.draw(gs.sampledFrom(Object.keys(POLICY_FIELDS) as WorkloadProfile[]));
  const a = spelled(tc, profile);
  const b = spelled(tc, profile);
  const text = (policy: Record<string, unknown>) => policyText(checkPolicy(profile, policy, { service: 'token:api-prod' }));
  const [ta, tb] = [text(a), text(b)];
  assert.equal(ta === tb, JSON.stringify(meaning(profile, a)) === JSON.stringify(meaning(profile, b)), `${ta} / ${tb}`);
  assert.equal(text(JSON.parse(ta) as Record<string, unknown>), ta);
}, propertySettings(256)));

const CREDENTIALS = ['stripe', 'openai', 'dfns-key'];
const PLACES = ['market/prod', 'market/dev'];
const METHODS = ['GET', 'POST', 'DELETE'];
const PREFIXES = ['/', '/v1', '/v1/refunds', '/v1/refunds/re_1', '/v1/charges', '/v2'];

const constraints = gs.composite((tc): Constraints => {
  const list = (items: readonly string[]) => (tc.draw(gs.booleans()) ? [...new Set(tc.draw(gs.arrays(gs.sampledFrom(items), { maxSize: 3 })))].sort() : undefined);
  const result: { -readonly [K in keyof Constraints]: Constraints[K] } = {};
  const places = list(PLACES);
  const credentials = list(CREDENTIALS);
  const methods = list(METHODS);
  const paths = list(PREFIXES);
  if (places !== undefined) result.places = places;
  if (credentials !== undefined) result.credentials = credentials;
  if (methods !== undefined) result.methods = methods;
  if (paths !== undefined) result.paths = paths.filter((path) => !paths.some((other) => other !== path && (other === '/' || path.startsWith(`${other}/`))));
  return result;
});

const tricky = gs.sampledFrom(['refunds', 're_1', 'charges', 'v1', 'v2', '..', '.', '%2e%2e', '%2E', '.%2e', '%2f', '%2F', '%5c', '%252e', ';', '..;', 're%5F1', 'refundsX', '', '%7e']);
const upstream = gs.composite((tc) => `https://api.stripe.com/${tc.draw(gs.arrays(tricky, { maxSize: 5 })).join('/')}`);

const operation = gs.composite((tc) => ({
  place: tc.draw(gs.sampledFrom(PLACES)),
  credential: tc.draw(gs.sampledFrom(CREDENTIALS)),
  request: tc.draw(gs.optional(gs.record({ method: gs.sampledFrom(METHODS), url: upstream }))) ?? undefined,
}));

test(`a child's intersection allows nothing either side does not, seed ${settings.seed}`, () => hegel.test((tc) => {
  const [a, b, op] = [tc.draw(constraints), tc.draw(constraints), tc.draw(operation)];
  const both = intersect(a, b);
  if (constraintsAllow(both, op)) {
    assert.ok(constraintsAllow(a, op) && constraintsAllow(b, op), JSON.stringify({ a, b, both, op }));
  }
}, propertySettings(512)));

/**
 * The reference: the path the proxy is about to send, by segments, matched
 * whole against each prefix, with nothing an upstream might read otherwise.
 */
function reference(paths: readonly string[], url: string): boolean {
  const segments = new URL(url).pathname.split('/').slice(1);
  if (segments.some((part) => /%2e|%2f|%5c|%25|;/i.test(part))) return false;
  return paths.some((prefix) => {
    const want = prefix === '/' ? [] : prefix.split('/').slice(1);
    return want.every((part, i) => segments[i] === part);
  });
}

/** How an upstream that decodes escapes once, then resolves dot segments and drops `;` parameters (Tomcat), reads a path. */
function upstreamReads(url: string): string {
  const decoded = new URL(url).pathname.split('/').map((part) => decodeURIComponent(part).split(';')[0]).join('/');
  return new URL(decoded, 'https://api.stripe.com').pathname;
}

test(`constraintsAllow matches whole segments of the URL it sends, as the reference does, and nothing it allows reads otherwise upstream, seed ${settings.seed}`, () => hegel.test((tc) => {
  const paths = [...new Set(tc.draw(gs.arrays(gs.sampledFrom(PREFIXES.filter((prefix) => prefix !== '/')), { minSize: 1, maxSize: 2 })))];
  const url = tc.draw(upstream);
  const allowed = constraintsAllow({ paths, methods: ['POST'] }, { place: 'market/prod', credential: 'stripe', request: { method: 'POST', url } });
  assert.equal(allowed, reference(paths, url), url);
  if (allowed) {
    const read = upstreamReads(url);
    assert.ok(paths.some((prefix) => read === prefix || read.startsWith(`${prefix}/`)), `${url} reads as ${read} upstream`);
  }
}, propertySettings(512)));
