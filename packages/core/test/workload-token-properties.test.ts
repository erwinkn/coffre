import assert from 'node:assert/strict';
import { constants, createHash, createHmac, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { createServer } from 'node:http';
import test, { after, before } from 'node:test';
import * as hegel from '@hegeldev/hegel';
import * as gs from '@hegeldev/hegel/generators';
import { errors as jose } from 'jose';

import {
  AccessIdentityVerifier,
  decodeWorkloadToken,
  keySummaries,
  KeysInvalid,
  toPrincipal,
  uploadedKeys,
  verifyWorkloadToken,
  WorkloadTokenRefused,
  type WorkloadRefusal,
} from '@coffre/core/identity';
import { checkBinding, claimAt, differingClaims, type WorkloadProfile } from '@coffre/core/workloads';
import { propertySettings } from './properties.ts';

// The rules, transcribed from docs/design/oidc.md (sections 1, 3 and 8) and
// RFC 7515, 7517, 7518 and 7638, never computed by the code under test:
// a size of 8,192, a tolerance of 30 s, an age of an hour, 32 keys.
const MAX_TOKEN = 8192;
const TOLERANCE = 30;
const MAX_AGE = 3600;
const MAX_KEYS = 32;

// Keys come from the host's generator, once per run: an RSA key per case
// would cost more than the whole budget. Only which key signed what decides
// an outcome, never a key's bits, so a seed replays the same cases.
const rsa = (modulusLength = 2048) => generateKeyPairSync('rsa', { modulusLength });
const ec = (namedCurve = 'P-256') => generateKeyPairSync('ec', { namedCurve });
const POOL = { rsaA: rsa(), rsaB: rsa(), rsaX: rsa(), ecA: ec(), ecB: ec(), ecX: ec(), weak: rsa(1024), p384: ec('P-384') };
type KeyName = keyof typeof POOL;
type Jwk = JsonWebKey & { kid?: string };
const HONEST = ['rsaA', 'rsaB', 'ecA', 'ecB'] as const satisfies readonly KeyName[];
const publicJwk = (name: KeyName) => POOL[name].publicKey.export({ format: 'jwk' }) as Jwk;
const algOf = (name: KeyName) => (POOL[name].publicKey.asymmetricKeyType === 'rsa' ? 'RS256' : 'ES256');
const kidOf = (name: KeyName) => `kid-${name}`;

const ISSUER = 'https://kube.acme.internal/clusters/prod';
const AUDIENCE = 'https://secrets.acme.example';
const part = (text: string) => Buffer.from(text, 'utf8').toString('base64url');

// --- what a token is, read independently -------------------------------------

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** RFC 4648's base64url without padding; a length of 4n + 1 is no encoding. Unused trailing bits are ignored, as section 3.5 allows. */
function base64url(text: string): Buffer | null {
  if (text.length % 4 === 1 || [...text].some((char) => !BASE64URL.includes(char))) return null;
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of text) {
    value = (value << 6) | BASE64URL.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const finite = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
const nonempty = (value: unknown): value is string => typeof value === 'string' && value !== '';

/** A refusal the oracle expects: what is wrong, and the reasons that say it, null for any. */
type Defect = { what: string; reasons: readonly WorkloadRefusal[] | null };
type Verdict = { accept: true; claims: Record<string, unknown> } | { accept: false; defects: Defect[] } | { accept: 'either'; why: string };

/** Whether a JWK is one RFC 7517 lets verify `alg`, by its members alone. */
function mayVerify(jwk: Jwk, alg: string, kid: string | undefined): boolean {
  if (jwk.kty !== (alg === 'RS256' ? 'RSA' : 'EC')) return false;
  if (kid !== undefined && jwk.kid !== kid) return false;
  if (jwk.alg !== undefined && jwk.alg !== alg) return false;
  if (jwk.use !== undefined && jwk.use !== 'sig') return false;
  if (Array.isArray(jwk.key_ops) && !jwk.key_ops.includes('verify')) return false;
  return alg !== 'ES256' || jwk.crv === 'P-256';
}

function signs(jwk: Jwk, alg: string, input: string, signature: Buffer): boolean {
  try {
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    return verify('sha256', Buffer.from(input, 'ascii'), alg === 'ES256' ? { key, dsaEncoding: 'ieee-p1363' } : key, signature);
  } catch {
    return false;
  }
}

const weakRsa = (jwk: Jwk) => jwk.kty === 'RSA' && Buffer.from(jwk.n!, 'base64url').length * 8 < 2048;

/**
 * What section 3 says of a token, at `nowMs`. Times: `exp > t − 30`,
 * `nbf ≤ t + 30`, `iat ≤ t + 30` and `t − iat ≤ 3600`. jose, which checks
 * `exp` and `nbf`, reads t in whole seconds (RFC 7519's NumericDate), so
 * those two compare with t floored; `iat` with t exactly.
 */
function oracle(token: string, keys: Jwk[], expected: { nowMs: number; maxLifetime?: number }): Verdict {
  const malformed = (what: string, reasons: readonly WorkloadRefusal[] | null = ['malformed']): Verdict => ({ accept: false, defects: [{ what, reasons }] });
  if (token.length === 0 || token.length > MAX_TOKEN) return malformed('size');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((each) => each === '' || [...each].some((char) => !BASE64URL.includes(char)))) return malformed('not three base64url parts');
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const json = (text: string): Record<string, unknown> | null | 'not base64url' => {
    const bytes = base64url(text);
    if (bytes === null) return 'not base64url';
    try {
      const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
      return isObject(value) ? value : null;
    } catch {
      return null;
    }
  };
  const [header, claims] = [json(headerPart), json(payloadPart)];
  // A length no encoding has is refused, but which check notices first is jose's business.
  if (header === 'not base64url' || claims === 'not base64url') return malformed('a part is not base64url', null);
  if (header === null || claims === null) return malformed('a part is not a JSON object');
  if (!nonempty(claims.iss) || !nonempty(claims.sub) || !finite(claims.exp) || !finite(claims.iat)) return malformed('claim types');
  if (claims.nbf !== undefined && !finite(claims.nbf)) return malformed('nbf type');

  const defects: Defect[] = [];
  const crit = header.crit;
  // b64 is the one extension a JWS verifier knows (RFC 7797); a JWT never leaves its payload unencoded.
  if (crit !== undefined && !(Array.isArray(crit) && crit.length > 0 && crit.every((name) => name === 'b64') && header.b64 === true)) {
    defects.push({ what: 'crit', reasons: ['signature'] });
  }
  const alg = header.alg;
  let either: string | null = null;
  if (alg !== 'RS256' && alg !== 'ES256') {
    defects.push({ what: `alg ${JSON.stringify(alg)}`, reasons: ['signature'] });
  } else {
    // A kid that is not a string names no key.
    const kid = typeof header.kid === 'string' ? header.kid : undefined;
    const candidates = keys.filter((jwk) => mayVerify(jwk, alg, kid));
    const signature = base64url(signaturePart);
    const input = `${headerPart}.${payloadPart}`;
    if (candidates.length === 0) defects.push({ what: 'no key may verify', reasons: ['unknown_key'] });
    else if (signature === null || !candidates.some((jwk) => !weakRsa(jwk) && signs(jwk, alg, input, signature))) {
      defects.push({ what: 'signature', reasons: ['signature'] });
    } else if (candidates.some(weakRsa)) {
      // Section 3: RSA keys are at least 2048 bits. A smaller one listed beside the key that signed may refuse the token, fail closed.
      either = 'a key under 2048 bits may verify too';
    }
  }
  if (claims.iss !== ISSUER) defects.push({ what: 'iss', reasons: ['signature'] });
  const t = expected.nowMs / 1000;
  const whole = Math.floor(t);
  if (!((claims.exp as number) > whole - TOLERANCE)) defects.push({ what: 'exp', reasons: ['expired'] });
  if (claims.nbf !== undefined && !((claims.nbf as number) <= whole + TOLERANCE)) defects.push({ what: 'nbf', reasons: ['not_yet_valid'] });
  if (!(t - (claims.iat as number) <= MAX_AGE) || !((claims.iat as number) <= t + TOLERANCE)) defects.push({ what: 'iat', reasons: ['too_old'] });
  if (expected.maxLifetime !== undefined && !((claims.exp as number) - (claims.iat as number) <= expected.maxLifetime)) {
    defects.push({ what: 'lifetime', reasons: ['too_long'] });
  }
  const aud = claims.aud;
  if (!(aud === AUDIENCE || (Array.isArray(aud) && aud.length === 1 && aud[0] === AUDIENCE))) defects.push({ what: 'aud', reasons: ['audience'] });
  if (either !== null) {
    if (defects.length === 0) return { accept: 'either', why: either };
    // Refused all the same, but the small key may say so first.
    for (const defect of defects) defect.reasons = defect.reasons && [...defect.reasons, 'signature'];
  }
  if (defects.length > 0) return { accept: false, defects };
  return { accept: true, claims };
}

// --- tokens, honest and not --------------------------------------------------

type Signing =
  | { kind: 'key'; key: KeyName; as?: unknown }
  | { kind: 'hmac'; key: KeyName; secret: 'pem' | 'der' | 'jwk' | 'n' }
  | { kind: 'bytes'; bytes: Uint8Array };

function signature(input: string, signing: Signing, published: Jwk[]): string {
  const data = Buffer.from(input, 'ascii');
  if (signing.kind === 'bytes') return Buffer.from(signing.bytes).toString('base64url');
  const { publicKey, privateKey } = POOL[signing.key];
  if (signing.kind === 'key') {
    // As the header says, where the key can: RS512 and PS256 too, which only the allowlist refuses.
    if (publicKey.asymmetricKeyType === 'ec') return sign(signing.as === 'ES384' ? 'sha384' : 'sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    if (signing.as === 'PS256') return sign('sha256', data, { key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64url');
    return sign(signing.as === 'RS512' ? 'sha512' : 'sha256', data, privateKey).toString('base64url');
  }
  // Algorithm confusion: the verifying key's public bytes, in every spelling, as an HMAC secret.
  const jwk = published.find((each) => each.n === publicJwk(signing.key).n && each.x === publicJwk(signing.key).x) ?? publicJwk(signing.key);
  const secret = {
    pem: () => Buffer.from(publicKey.export({ type: 'spki', format: 'pem' })),
    der: () => publicKey.export({ type: 'spki', format: 'der' }),
    jwk: () => Buffer.from(JSON.stringify(jwk)),
    n: () => Buffer.from(jwk.n ?? jwk.x!, 'base64url'),
  }[signing.secret]();
  return createHmac('sha256', secret).update(data).digest('base64url');
}

// Claim values a token may carry instead of the right one, as raw JSON: 1e400 parses to Infinity.
const NUMBERS_WRONG = ['"1791028800"', '1e400', '-1e400', 'null', 'true', '[]', '{}', '"NaN"'];
const NUMBERS_ODD = ['-0', '1e308', '-1e308', '0.5', '9007199254740993'];
const CLAIM_EDITS: Record<string, readonly (string | null)[]> = {
  iss: [`"${ISSUER}/"`, `"${ISSUER.toUpperCase()}"`, `"${ISSUER.replace('kube', 'Kube')}"`, `" ${ISSUER}"`, '"https://evil.example"', '""', '7', 'null', `["${ISSUER}"]`, null],
  sub: ['""', '7', 'null', '["s"]', '{}', '"system:serviceaccount:ci:deploy"', null],
  aud: [
    `["${AUDIENCE}"]`, `["${AUDIENCE}","https://other.example"]`, `["https://other.example","${AUDIENCE}"]`, `["${AUDIENCE}","${AUDIENCE}"]`,
    '"https://other.example"', `"${AUDIENCE}/"`, `"${AUDIENCE.toUpperCase()}"`, '[]', 'null', '5', `{"aud":"${AUDIENCE}"}`, null,
  ],
  exp: [...NUMBERS_WRONG, ...NUMBERS_ODD, null],
  iat: [...NUMBERS_WRONG, ...NUMBERS_ODD, null],
  nbf: [...NUMBERS_WRONG, ...NUMBERS_ODD, null],
};

type TokenEdit = { edit: 'swap-payload' | 'swap-signature' | 'twin' | 'respell' | 'standard-base64' } | { edit: 'insert'; text: string; at: number };
type Mutation =
  | { kind: 'claim'; name: string; raw: string | null }
  | { kind: 'alg'; alg: unknown }
  | { kind: 'kid'; kid: unknown }
  | { kind: 'hmac'; secret: 'pem' | 'der' | 'jwk' | 'n' }
  | { kind: 'none'; bytes: Uint8Array }
  | { kind: 'embedded'; member: 'jwk' | 'jku' | 'x5u' | 'x5c' }
  | { kind: 'extra'; member: 'jwk' | 'jku' | 'x5u' | 'x5c' | 'typ' | 'cty' | 'b64' }
  | { kind: 'crit'; crit: unknown; b64: unknown }
  | { kind: 'signer'; key: KeyName }
  | { kind: 'set'; edit: 'enc' | 'use-sig' | 'alg' | 'key_ops' | 'verify-op' | 'drop' | 'rename' | 'duplicate' | 'weak' | 'p384' | 'outsider' | 'strip-kids' }
  | { kind: 'size'; target: number }
  | ({ kind: 'token' } & TokenEdit);

const claimEdit = gs.sampledFrom(Object.keys(CLAIM_EDITS)).flatMap((name) => gs.sampledFrom(CLAIM_EDITS[name]!).map((raw) => ({ kind: 'claim' as const, name, raw })));
const mutation = gs.oneOf<Mutation>(
  // Claims are where most of the edges are: three times as likely as each other kind.
  claimEdit, claimEdit, claimEdit,
  gs.sampledFrom<unknown>(['HS256', 'none', 'RS512', 'ES384', 'PS256', 'rs256', 'RS256', 'ES256', 'EdDSA', undefined, 5]).map((alg) => ({ kind: 'alg' as const, alg })),
  gs.oneOf<unknown>(
    gs.sampledFrom<unknown>([undefined, kidOf('rsaA'), kidOf('rsaB'), kidOf('ecA'), kidOf('ecB'), kidOf('rsaX'), kidOf('weak'), '', 5, null, ['kid-rsaA']]),
    gs.text({ maxSize: 8 }),
    gs.sampledFrom(['../keys/', '/etc/', 'kid-rsaA/../', 'https://evil.example/']).flatMap((prefix) => gs.sampledFrom(HONEST).map((name) => `${prefix}${kidOf(name)}`)),
  ).map((kid) => ({ kind: 'kid' as const, kid })),
  gs.sampledFrom(['pem', 'der', 'jwk', 'n'] as const).map((secret) => ({ kind: 'hmac' as const, secret })),
  gs.oneOf(gs.just(new Uint8Array()), gs.binary({ maxSize: 64 })).map((bytes) => ({ kind: 'none' as const, bytes })),
  // A key in the header, or a URL to one, beside an outsider's signature: never trusted.
  gs.sampledFrom(['jwk', 'jku', 'x5u', 'x5c'] as const).map((member) => ({ kind: 'embedded' as const, member })),
  // The same members beside an honest signature: ignored, so harmless.
  gs.sampledFrom(['jwk', 'jku', 'x5u', 'x5c', 'typ', 'cty', 'b64'] as const).map((member) => ({ kind: 'extra' as const, member })),
  gs.tuples(
    gs.sampledFrom<unknown>([[], ['b64'], ['x-nope'], ['b64', 'x-nope'], ['b64', 'b64'], 'b64', [5], ['']]),
    gs.sampledFrom<unknown>([undefined, true, false, 'true']),
  ).map(([crit, b64]) => ({ kind: 'crit' as const, crit, b64 })),
  gs.sampledFrom(Object.keys(POOL) as KeyName[]).map((key) => ({ kind: 'signer' as const, key })),
  gs.sampledFrom(['enc', 'use-sig', 'alg', 'key_ops', 'verify-op', 'drop', 'rename', 'duplicate', 'weak', 'p384', 'outsider', 'strip-kids'] as const).map((edit) => ({ kind: 'set' as const, edit })),
  gs.integers({ minValue: MAX_TOKEN - 3, maxValue: MAX_TOKEN + 3 }).map((target) => ({ kind: 'size' as const, target })),
  gs.oneOf<TokenEdit>(
    gs.sampledFrom(['swap-payload', 'swap-signature', 'twin', 'respell', 'standard-base64'] as const).map((edit) => ({ edit })),
    gs.tuples(gs.sampledFrom(['.', ' ', '\n', '=', '+', '/', '\t', '..', 'A', '==', 'é']), gs.integers({ minValue: 0, maxValue: 4000 })).map(([text, at]) => ({ edit: 'insert' as const, text, at })),
  ).map((edit) => ({ kind: 'token' as const, ...edit })),
);

// How far past an edge, either way: on it, a quarter second or a second off, or a minute; all exact in binary.
const DELTAS = [-60, -1, -0.75, -0.25, 0, 0.25, 0.75, 1, 60];

type TokenCase = { token: string; keys: Jwk[]; nowMs: number; maxLifetime?: number; mutations: Mutation[] };

/** A token and its issuer's set: `adversarial`, up to three things done to it; `claims`, an honest signature and claims at their edges. */
const tokenCase = (focus: 'adversarial' | 'claims') => gs.composite((tc): TokenCase => {
  const whole = tc.draw(gs.integers({ minValue: 1_600_000_000, maxValue: 2_000_000_000 }));
  const nowMs = whole * 1000 + tc.draw(gs.sampledFrom([0, 250, 500, 750]));
  const t = nowMs / 1000;
  const base = (clock: 'whole' | 't') => (clock === 'whole' ? whole : t);
  const maxLifetime = tc.draw(gs.booleans()) ? MAX_AGE : undefined;
  const signer = tc.draw(gs.sampledFrom(HONEST));
  const named = tc.draw(gs.booleans());

  // Issued just now, for five minutes, but for one time at its edges, or for claims, any of them.
  const edge = focus === 'adversarial' ? tc.draw(gs.sampledFrom(['none', 'iat', 'exp', 'lifetime', 'nbf'] as const)) : null;
  const edgy = (field: typeof edge) => (edge === null ? tc.draw(gs.sampledFrom([true, false, false])) : edge === field);
  const [edgyIat, edgyExp, edgyLifetime, edgyNbf] = [edgy('iat'), edgy('exp'), edgy('lifetime'), edgy('nbf')];
  const delta = () => tc.draw(gs.sampledFrom(DELTAS));
  const clock = () => base(tc.draw(gs.sampledFrom(['whole', 't'] as const)));
  // An hour old at most, and no further ahead than the tolerance.
  const iat = edgyIat ? (tc.draw(gs.booleans()) ? t - MAX_AGE : t + TOLERANCE) + delta() : t - 10;
  const exp = edgyExp ? clock() - TOLERANCE + delta() : edgyLifetime ? iat + MAX_AGE + delta() : t + 300;
  const nbf = edgyNbf ? (tc.draw(gs.booleans()) ? iat : clock() + TOLERANCE + delta()) : null;
  const payload: [string, string][] = [
    ['iss', JSON.stringify(ISSUER)],
    ['sub', JSON.stringify(tc.draw(gs.sampledFrom(['repo:acme/api:ref:refs/heads/main', 'system:serviceaccount:ci:deploy'])))],
    ['aud', JSON.stringify(AUDIENCE)],
    ['iat', JSON.stringify(iat)],
    ['exp', JSON.stringify(exp)],
  ];
  if (nbf !== null) payload.push(['nbf', JSON.stringify(nbf)]);
  if (tc.draw(gs.booleans())) payload.push(['kubernetes.io', JSON.stringify({ namespace: 'ci', serviceaccount: { name: 'deploy', uid: '4f1c' } })]);

  let keys: Jwk[] = HONEST.filter((name) => name === signer || tc.draw(gs.booleans())).map((name) => ({ ...publicJwk(name), ...(named ? { kid: kidOf(name) } : {}) }));
  const header: Record<string, unknown> = { alg: algOf(signer), ...(named && tc.draw(gs.booleans()) ? { kid: kidOf(signer) } : {}) };
  let signing: Signing = { kind: 'key', key: signer };
  const mine = (jwk: Jwk) => jwk.n === publicJwk(signer).n && jwk.x === publicJwk(signer).x;
  const outsider: KeyName = algOf(signer) === 'RS256' ? 'rsaX' : 'ecX';
  const edits: Extract<Mutation, { kind: 'token' }>[] = [];
  let target: number | null = null;

  const mutations: Mutation[] = focus === 'adversarial' ? tc.draw(gs.arrays(mutation, { maxSize: 3 })) : tc.draw(gs.arrays(claimEdit, { maxSize: 1 }));
  for (const m of mutations) {
    if (m.kind === 'claim') {
      const at = payload.findIndex(([name]) => name === m.name);
      if (m.raw === null) {
        if (at >= 0) payload.splice(at, 1);
      } else if (at >= 0) payload[at] = [m.name, m.raw];
      else payload.push([m.name, m.raw]);
    } else if (m.kind === 'alg') {
      header.alg = m.alg;
      if (signing.kind === 'key') signing = { ...signing, as: m.alg };
    }
    else if (m.kind === 'kid') header.kid = m.kid;
    else if (m.kind === 'hmac') {
      header.alg = 'HS256';
      signing = { kind: 'hmac', key: signer, secret: m.secret };
    } else if (m.kind === 'none') {
      header.alg = 'none';
      signing = { kind: 'bytes', bytes: m.bytes };
    } else if (m.kind === 'embedded') {
      signing = { kind: 'key', key: outsider };
      const jwk = publicJwk(outsider);
      header[m.member] = { jwk, jku: 'https://evil.example/jwks.json', x5u: 'https://evil.example/cert.pem', x5c: ['MIIB'] }[m.member];
    } else if (m.kind === 'extra') {
      header[m.member] = { jwk: publicJwk(signer), jku: 'https://evil.example/jwks.json', x5u: 'https://evil.example/cert.pem', x5c: ['MIIB'], typ: 'JWT', cty: 'JWT', b64: false }[m.member];
    } else if (m.kind === 'crit') {
      header.crit = m.crit;
      if (m.b64 !== undefined) header.b64 = m.b64;
    } else if (m.kind === 'signer') signing = { kind: 'key', key: m.key };
    else if (m.kind === 'set') {
      const index = keys.findIndex(mine);
      const edit = (change: (jwk: Jwk) => Jwk) => {
        if (index >= 0) keys[index] = change(keys[index]!);
      };
      if (m.edit === 'enc') edit((jwk) => ({ ...jwk, use: 'enc' }));
      if (m.edit === 'use-sig') edit((jwk) => ({ ...jwk, use: 'sig' }));
      if (m.edit === 'alg') edit((jwk) => ({ ...jwk, alg: jwk.kty === 'RSA' ? 'RS512' : 'ES384' }));
      if (m.edit === 'key_ops') edit((jwk) => ({ ...jwk, key_ops: ['encrypt'] }));
      if (m.edit === 'verify-op') edit((jwk) => ({ ...jwk, key_ops: ['verify'], alg: algOf(signer) }));
      if (m.edit === 'drop') keys = keys.filter((jwk) => !mine(jwk));
      if (m.edit === 'rename') edit((jwk) => ({ ...jwk, kid: 'renamed' }));
      if (m.edit === 'strip-kids') keys = keys.map(({ kid: _, ...jwk }) => jwk);
      // Another key of the same kind under the signer's kid.
      const twin: KeyName = { rsaA: 'rsaB', rsaB: 'rsaA', ecA: 'ecB', ecB: 'ecA' }[signer] as KeyName;
      if (m.edit === 'duplicate') keys.unshift({ ...publicJwk(twin), kid: kidOf(signer) });
      const extra = { weak: 'weak', p384: 'p384', outsider } as Record<string, KeyName>;
      if (m.edit in extra) keys.unshift({ ...publicJwk(extra[m.edit]!), ...(named ? { kid: kidOf(extra[m.edit]!) } : {}) });
    } else if (m.kind === 'size') target = m.target;
    else edits.push(m);
  }

  const payloadText = (entries: [string, string][]) => `{${entries.map(([name, raw]) => `${JSON.stringify(name)}:${raw}`).join(',')}}`;
  const build = (entries: [string, string][]) => {
    const input = `${part(JSON.stringify(header))}.${part(payloadText(entries))}`;
    return `${input}.${signature(input, signing, keys)}`;
  };
  if (target !== null) {
    // The shortest filler claim that brings the token to the target length or just past it; a signature's length depends on its key alone.
    const signed = build(payload);
    const length = (filler: number) => signed.length - part(payloadText(payload)).length + part(payloadText([...payload, ['pad', JSON.stringify('x'.repeat(filler))]])).length;
    let filler = Math.max(0, Math.floor(((target - length(0)) * 3) / 4) - 4);
    while (length(filler) < target) filler++;
    payload.push(['pad', JSON.stringify('x'.repeat(filler))]);
  }
  let token = build(payload);
  const other = () => build(payload.map(([name, raw]) => [name, name === 'sub' ? '"repo:acme/other:ref:refs/heads/main"' : raw]));
  for (const edit of edits) {
    const [h, p, s] = token.split('.');
    if (edit.edit === 'swap-payload') token = `${h}.${other().split('.')[1]}.${s}`;
    else if (edit.edit === 'swap-signature') token = `${h}.${p}.${other().split('.')[2]}`;
    else if (edit.edit === 'twin' && s !== undefined && Buffer.from(s, 'base64url').length === 64) {
      // ES256's other signature of the same claims: (r, n − s).
      const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
      const bytes = Buffer.from(s, 'base64url');
      const high = (n - BigInt(`0x${bytes.subarray(32).toString('hex')}`)).toString(16).padStart(64, '0');
      token = `${h}.${p}.${Buffer.concat([bytes.subarray(0, 32), Buffer.from(high, 'hex')]).toString('base64url')}`;
    } else if (edit.edit === 'respell' && s !== undefined && s.length > 0) {
      // The signature's last character with its unused low bits set: the same bytes, spelled another way.
      const last = BASE64URL.indexOf(s.at(-1)!);
      if (last >= 0) token = `${h}.${p}.${s.slice(0, -1)}${BASE64URL[last | 1]}`;
    } else if (edit.edit === 'standard-base64') {
      const standard = (text: string | undefined) => Buffer.from(text ?? '', 'base64url').toString('base64');
      token = `${standard(h)}.${standard(p)}.${standard(s)}`;
    } else if (edit.edit === 'insert') {
      const at = edit.at % (token.length + 1);
      token = `${token.slice(0, at)}${edit.text}${token.slice(at)}`;
    }
  }
  return { token, keys, nowMs, maxLifetime, mutations };
});

async function pipeline(token: string, keys: Jwk[], nowMs: number, maxLifetime?: number) {
  // As the exchange runs it: the shape first, then the signature, audience and times.
  try {
    const decoded = decodeWorkloadToken(token);
    const claims = await verifyWorkloadToken(token, { keys }, { issuer: ISSUER, audience: AUDIENCE, now: new Date(nowMs), maxLifetime });
    return { claims, decoded };
  } catch (error) {
    if (!(error instanceof WorkloadTokenRefused)) throw error;
    return { refused: error.reason };
  }
}

/** The case against the oracle: accepted exactly when it says, with the claims signed; refused for the one thing wrong, when one is. */
async function holds(tc: hegel.TestCase, generated: gs.Generator<TokenCase>) {
  const { token, keys, nowMs, maxLifetime, mutations } = tc.draw(generated);
  tc.note(JSON.stringify({ mutations, token, keys: keys.map(({ kty, kid, use, alg, crv }) => ({ kty, kid, use, alg, crv })), nowMs, maxLifetime }));
  const expected = oracle(token, keys, { nowMs, maxLifetime });
  const got = await pipeline(token, keys, nowMs, maxLifetime);
  tc.note(JSON.stringify({ expected, got: 'refused' in got ? got.refused : 'accepted' }));
  if (expected.accept === 'either') return;
  if (expected.accept) {
    assert.ok('claims' in got, `refused as ${'refused' in got ? got.refused : ''}, though valid`);
    assert.deepEqual(got.claims, expected.claims, 'the claims returned are the ones signed');
    assert.deepEqual(got.decoded.signingInputHash, createHash('sha256').update(token.split('.').slice(0, 2).join('.')).digest());
    return;
  }
  assert.ok('refused' in got, `accepted, though ${expected.defects.map(({ what }) => what).join(', ')}`);
  const [only] = expected.defects;
  if (expected.defects.length === 1 && only!.reasons !== null && got.refused !== undefined) {
    assert.ok(only!.reasons.includes(got.refused), `refused as ${got.refused}, for ${only!.what}`);
  }
}

const adversarial = tokenCase('adversarial');
const tokenSettings = propertySettings(300);

test(`a workload token is accepted exactly when well formed, signed by a key of the set that may verify it, from the issuer, for this instance alone and in time, and its claims are what was signed, seed ${tokenSettings.seed}`, () => hegel.testAsync((tc) => holds(tc, adversarial), tokenSettings));

const atEdges = tokenCase('claims');
// Cheap cases, and the edges are narrow: more of them, and fewer times more in a long run.
const edgeSettings = propertySettings(800, 25);

test(`an honestly signed token is accepted exactly when its times, issuer and audience are within section 3's bounds, to the second and the quarter second, seed ${edgeSettings.seed}`, () => hegel.testAsync((tc) => holds(tc, atEdges), edgeSettings));

// --- uploaded key sets ---------------------------------------------------------

// P-256 (SEC 2): y² = x³ − 3x + b over p.
const P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const unsigned = (bytes: Buffer) => (bytes.length === 0 ? 0n : BigInt(`0x${bytes.toString('hex')}`));
const onCurve = (x: bigint, y: bigint) => x < P && y < P && (y * y - (x * x * x - 3n * x + B)) % P === 0n;
const asBase64url = (value: bigint, leadingZero = false) => {
  const hex = value.toString(16);
  return Buffer.from(`${leadingZero ? '00' : ''}${hex.length % 2 ? '0' : ''}${hex}`, 'hex').toString('base64url');
};

/** An unsigned integer in its fewest bytes, base64url exactly (RFC 7518, section 6.3.1), or null. */
function jwkInteger(value: unknown): bigint | null {
  if (typeof value !== 'string') return null;
  const bytes = base64url(value);
  if (bytes === null || bytes.length === 0 || bytes[0] === 0 || bytes.toString('base64url') !== value) return null;
  return unsigned(bytes);
}
/** A P-256 coordinate: 32 bytes exactly, in their one spelling. */
function coordinate(value: unknown): bigint | null {
  if (typeof value !== 'string') return null;
  const bytes = base64url(value);
  return bytes !== null && bytes.length === 32 && bytes.toString('base64url') === value ? unsigned(bytes) : null;
}

/** RFC 7638: SHA-256 of the required members, in lexicographic order, with no whitespace. */
const thumbprint = (jwk: Record<string, unknown>) =>
  createHash('sha256')
    .update(jwk.kty === 'RSA' ? `{"e":"${jwk.e}","kty":"RSA","n":"${jwk.n}"}` : `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`)
    .digest('base64url');

const PRIVATE = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/** What section 8 keeps of an uploaded set, as the keys it keeps, each as kept, or null when it refuses the set. */
function keptKeys(value: unknown): Record<string, unknown>[] | null {
  if (!isObject(value) || !Array.isArray(value.keys) || value.keys.length > MAX_KEYS) return null;
  const kept: Record<string, unknown>[] = [];
  for (const jwk of value.keys as unknown[]) {
    if (!isObject(jwk) || PRIVATE.some((member) => Object.hasOwn(jwk, member))) return null;
    if (jwk.use === 'enc') continue;
    if (jwk.use !== undefined && jwk.use !== 'sig') return null;
    if (jwk.kid !== undefined && !(nonempty(jwk.kid) && jwk.kid.length <= 256)) return null;
    const named = { ...(jwk.kid === undefined ? {} : { kid: jwk.kid }), ...(jwk.use === undefined ? {} : { use: 'sig' }) };
    if (jwk.kty === 'RSA' && (jwk.alg === undefined || jwk.alg === 'RS256')) {
      const [n, e] = [jwkInteger(jwk.n), jwkInteger(jwk.e)];
      if (n === null || e === null || n < 2n ** 2047n || n % 2n === 0n || e % 2n === 0n || e < 65537n || e >= 2n ** 256n) return null;
      kept.push({ kty: 'RSA', ...named, alg: 'RS256', n: jwk.n, e: jwk.e });
    } else if (jwk.kty === 'EC' && jwk.crv === 'P-256' && (jwk.alg === undefined || jwk.alg === 'ES256')) {
      const [x, y] = [coordinate(jwk.x), coordinate(jwk.y)];
      if (x === null || y === null || !onCurve(x, y)) return null;
      kept.push({ kty: 'EC', ...named, alg: 'ES256', crv: 'P-256', x: jwk.x, y: jwk.y });
    } else return null;
  }
  const kids = kept.flatMap(({ kid }) => (kid === undefined ? [] : [kid]));
  return kept.length > 0 && new Set(kids).size === kids.length ? kept : null;
}

const RSA_EXPONENTS: Record<string, bigint> = {
  'e-1': 1n, 'e-3': 3n, 'e-65535': 65535n, 'e-65536': 65536n, 'e-65537': 65537n, 'e-65539': 65539n,
  'e-2^255+1': 2n ** 255n + 1n, 'e-2^256-1': 2n ** 256n - 1n, 'e-2^256+1': 2n ** 256n + 1n,
};
const ANY_KEY_CHANGES = [
  'kid-empty', 'kid-257', 'kid-256', 'kid-number', 'kid-text', 'use-enc', 'use-foo', 'use-number', 'RS512', 'ES384', 'other-alg', 'alg-none', 'd', 'k', 'oth', 'qi',
];
const RSA_CHANGES = [
  'weak', 'n-leading-zero', 'n-even', 'n-2047', 'n-2048', 'n-2041', 'n-short', 'n-padded', 'n-standard', 'n-number', ...Object.keys(RSA_EXPONENTS), 'e-leading-zero', 'no-e',
];
const EC_CHANGES = ['p384', 'x-padded', 'x-short', 'x-long', 'x-respelled', 'swap', 'mirror', 'x-p', 'y-null', 'crv'];

/** A key as an issuer publishes it, with members that change nothing, and half the time one thing changed: of any key, or of its kind. */
const uploadedJwk = gs.composite((tc): unknown => {
  const rsa = tc.draw(gs.booleans());
  const ofKind = gs.sampledFrom(rsa ? RSA_CHANGES : EC_CHANGES);
  const change = tc.draw(gs.booleans()) ? tc.draw(gs.oneOf(gs.sampledFrom(ANY_KEY_CHANGES), ofKind, ofKind)) : null;
  const name: KeyName = change === 'weak' || change === 'p384' ? change : tc.draw(gs.sampledFrom(rsa ? ['rsaA', 'rsaB', 'rsaX'] as const : ['ecA', 'ecB', 'ecX'] as const));
  const jwk: Record<string, unknown> = { ...publicJwk(name) };
  const kid = tc.draw(gs.sampledFrom(['own', 'own', 'none', 'k1'] as const));
  if (kid !== 'none') jwk.kid = kid === 'own' ? kidOf(name) : kid;
  if (tc.draw(gs.booleans())) jwk.use = 'sig';
  if (tc.draw(gs.booleans())) jwk.alg = rsa ? 'RS256' : 'ES256';
  for (const extra of tc.draw(gs.arrays(gs.sampledFrom(['x5c', 'key_ops', 'ext', 'x5t'] as const), { maxSize: 2, unique: true }))) {
    jwk[extra] = { x5c: ['MIIB'], key_ops: ['verify'], ext: true, x5t: 'AQAB' }[extra];
  }
  const n = Buffer.from((jwk.n ?? '') as string, 'base64url');
  const x = Buffer.from((jwk.x ?? '') as string, 'base64url');
  const leading = (bytes: Buffer, byte: number) => Buffer.concat([Buffer.from([byte]), bytes.subarray(1)]).toString('base64url');
  if (change !== null && change in RSA_EXPONENTS) jwk.e = asBase64url(RSA_EXPONENTS[change]!);
  switch (change) {
    case 'kid-empty': jwk.kid = ''; break;
    case 'kid-257': jwk.kid = 'k'.repeat(257); break;
    case 'kid-256': jwk.kid = 'k'.repeat(256); break;
    case 'kid-number': jwk.kid = 5; break;
    case 'kid-text': jwk.kid = tc.draw(gs.text({ maxSize: 6 })); break;
    case 'use-enc': jwk.use = 'enc'; break;
    case 'use-foo': jwk.use = 'foo'; break;
    case 'use-number': jwk.use = 5; break;
    case 'RS512': case 'ES384': jwk.alg = change; break;
    case 'other-alg': jwk.alg = rsa ? 'ES256' : 'RS256'; break;
    case 'alg-none': jwk.alg = 'none'; break;
    case 'd': case 'qi': jwk[change] = 'AQAB'; break;
    case 'k': jwk.k = 'c2VjcmV0'; break;
    case 'oth': jwk.oth = []; break;
    case 'n-leading-zero': if (rsa) jwk.n = Buffer.concat([Buffer.from([0]), n]).toString('base64url'); break;
    case 'n-even': if (rsa) jwk.n = Buffer.concat([n.subarray(0, -1), Buffer.from([n.at(-1)! & 0xfe])]).toString('base64url'); break;
    // 2047, 2048 and 2041 bits, in 256 bytes.
    case 'n-2047': if (rsa) jwk.n = leading(n, 0x7f); break;
    case 'n-2048': if (rsa) jwk.n = leading(n, 0x80); break;
    case 'n-2041': if (rsa) jwk.n = leading(n, 0x01); break;
    case 'n-short': if (rsa) jwk.n = n.subarray(1).toString('base64url'); break;
    case 'n-padded': if (rsa) jwk.n = `${jwk.n}=`; break;
    case 'n-standard': if (rsa) jwk.n = n.toString('base64'); break;
    case 'n-number': if (rsa) jwk.n = 5; break;
    case 'e-leading-zero': if (rsa) jwk.e = asBase64url(65537n, true); break;
    case 'no-e': if (rsa) delete jwk.e; break;
    case 'x-padded': if (!rsa) jwk.x = `${jwk.x}=`; break;
    case 'x-short': if (!rsa) jwk.x = x.subarray(1).toString('base64url'); break;
    case 'x-long': if (!rsa) jwk.x = Buffer.concat([Buffer.from([0]), x]).toString('base64url'); break;
    // The last character's unused bits set: the same bytes, spelled another way.
    case 'x-respelled': if (!rsa) jwk.x = `${(jwk.x as string).slice(0, -1)}${BASE64URL[BASE64URL.indexOf((jwk.x as string).at(-1)!) | 1]}`; break;
    case 'swap': if (!rsa) [jwk.x, jwk.y] = [jwk.y, jwk.x]; break;
    // The point's mirror, (x, p − y): on the curve, another key.
    case 'mirror': if (jwk.crv === 'P-256') jwk.y = Buffer.from((P - unsigned(Buffer.from(jwk.y as string, 'base64url'))).toString(16).padStart(64, '0'), 'hex').toString('base64url'); break;
    case 'x-p': if (!rsa) jwk.x = asBase64url(P); break;
    case 'y-null': if (!rsa) jwk.y = null; break;
    case 'crv': if (!rsa) jwk.crv = jwk.crv === 'P-256' ? 'P-384' : 'P-256'; break;
  }
  return jwk;
});

const uploadedSet = gs.oneOf(
  gs.arrays(uploadedJwk, { minSize: 1, maxSize: 3 }).map((keys) => ({ keys })),
  // Around the limit: copies of one key without a kid.
  gs.tuples(gs.sampledFrom(['rsaA', 'ecA'] as const), gs.integers({ minValue: MAX_KEYS - 1, maxValue: MAX_KEYS + 2 })).map(([name, count]) => {
    const { kid: _, ...jwk } = publicJwk(name) as Record<string, unknown>;
    return { keys: Array.from({ length: count }, () => ({ ...jwk })) };
  }),
  gs.sampledFrom([null, 'keys', 5, [], {}, { keys: 'x' }, { keys: {} }, { keys: null }, [publicJwk('rsaA')], { keys: [null] }, { keys: [[]] }, { keys: ['k'] }]),
);

const keySettings = propertySettings(400, 40);

test(`an uploaded key set keeps exactly the signing keys section 8 allows, in thumbprint order, and refuses any other set with KeysInvalid alone, seed ${keySettings.seed}`, () => hegel.testAsync(async (tc) => {
  const value = tc.draw(uploadedSet);
  tc.note(JSON.stringify(value));
  const expected = keptKeys(value);
  let result: Awaited<ReturnType<typeof uploadedKeys>>;
  try {
    result = await uploadedKeys(value);
  } catch (error) {
    if (!(error instanceof KeysInvalid)) throw error;
    assert.equal(expected, null, `refused: ${error.message}`);
    return;
  }
  assert.notEqual(expected, null, 'kept a set section 8 refuses');
  const kept = (JSON.parse(result.jwks) as { keys: Record<string, unknown>[] }).keys;
  const canonical = (keys: Record<string, unknown>[]) => keys.map((key) => JSON.stringify(Object.entries(key).sort(([a], [b]) => (a < b ? -1 : 1)))).sort();
  assert.deepEqual(canonical(kept), canonical(expected!), 'every signing key, with only the members that verify');
  const prints = kept.map(thumbprint);
  assert.deepEqual(prints, prints.toSorted(), 'in the order of their thumbprints');
  assert.equal(result.digest, createHash('sha256').update(result.jwks).digest('hex'));
  const summaries = kept.map((key, i) => ({ kid: key.kid ?? null, alg: key.kty === 'RSA' ? 'RS256' : 'ES256', thumbprint: prints[i] }));
  assert.deepEqual(result.keys, summaries);
  assert.deepEqual(keySummaries(result.jwks), summaries);
  // However listed, and its members however ordered: one digest.
  const listed = (value as { keys: Record<string, unknown>[] }).keys;
  const order = tc.draw(gs.arrays(gs.integers({ minValue: 0, maxValue: 1000 }), { minSize: listed.length, maxSize: listed.length }));
  const shuffled = listed.map((key, i) => [order[i]!, Object.fromEntries(Object.entries(key).reverse())] as const).sort(([a], [b]) => a - b).map(([, key]) => key);
  assert.equal((await uploadedKeys({ keys: shuffled })).jwks, result.jwks);
}, keySettings));

// --- bindings ------------------------------------------------------------------

const PROFILES: readonly WorkloadProfile[] = ['github', 'github-reusable', 'github-reusable-organization', 'gitlab', 'custom'];
// Section 1: the claim that says what started the run may list several values.
const EVENTS: Partial<Record<WorkloadProfile, { name: string; values: string[] }>> = {
  github: { name: 'event_name', values: ['push', 'workflow_dispatch', 'schedule', 'release', 'pull_request', 'workflow_run'] },
  'github-reusable': { name: 'event_name', values: ['push', 'workflow_dispatch', 'pull_request'] },
  'github-reusable-organization': { name: 'event_name', values: ['push', 'pull_request'] },
  gitlab: { name: 'pipeline_source', values: ['push', 'web', 'schedule'] },
};
const CLAIM_NAMES = [
  'repository_id', 'repository_owner_id', 'ref', 'workflow_ref', 'environment', 'sub', 'project_id', 'job_workflow_sha',
  'kubernetes.io.namespace', 'kubernetes.io.serviceaccount.uid', 'a.b', 'a.b.c', 'oidc.circleci.com/vcs-origin',
  'constructor', 'toString', '__proto__', 'hasOwnProperty', 'length', '0',
];
const VALUES = [
  'refs/heads/main', 'refs/heads/Main', 'refs/heads/main/x', 'refs/heads/*', 'main', '41532', '9919', 'production', 'Production', 'Staging EU',
  'acme/api/.github/workflows/ci.yml@refs/heads/main', 'system:serviceaccount:ci:deploy', 'ci', '4f1c', 'İstanbul', 'straße',
];

/** Sets an own property, `__proto__` included. */
const put = (object: Record<string, unknown>, key: string, value: unknown) => Object.defineProperty(object, key, { value, enumerable: true, writable: true, configurable: true });

/** Puts a value at a path of keys, making objects on the way; a key taken by something else leaves it be. */
function place(token: Record<string, unknown>, keys: string[], value: unknown) {
  let at = token;
  for (const key of keys.slice(0, -1)) {
    if (!Object.hasOwn(at, key)) put(at, key, {});
    const next = at[key];
    if (!isObject(next)) return;
    at = next;
  }
  if (!Object.hasOwn(at, keys.at(-1)!)) put(at, keys.at(-1)!, value);
}

const bindingCase = gs.composite((tc) => {
  const profile = tc.draw(gs.sampledFrom(PROFILES));
  const event = EVENTS[profile];
  const names = tc.draw(gs.arrays(gs.sampledFrom(event ? [...CLAIM_NAMES, event.name, event.name] : CLAIM_NAMES), { minSize: 1, maxSize: 5, unique: true }));
  const binding: Record<string, string | string[]> = {};
  const token: Record<string, unknown> = {};
  for (const name of names) {
    const value = name === event?.name
      ? tc.draw(gs.oneOf<string | string[]>(gs.sampledFrom(event.values), gs.arrays(gs.sampledFrom(event.values), { minSize: 1, maxSize: 3, unique: true })))
      : tc.draw(gs.sampledFrom(VALUES));
    put(binding, name, value);
    const one = typeof value === 'string' ? value : tc.draw(gs.sampledFrom(value));
    const how = tc.draw(gs.sampledFrom(['exact', 'exact', 'exact', 'upper', 'lower', 'prefix', 'suffix', 'slash', 'glob', 'space', 'number', 'list', 'object', 'null', 'missing', 'other'] as const));
    if (how === 'missing') continue;
    const carried = {
      exact: one, upper: one.toUpperCase(), lower: one.toLowerCase(), prefix: one.slice(0, -1), suffix: `${one}x`, slash: `${one}/`, glob: `${one.slice(0, -1)}*`,
      space: ` ${one}`, number: Number(one) || 41532, list: [one], object: { [name]: one }, null: null, other: tc.draw(gs.sampledFrom(VALUES)),
    }[how];
    // Where the token carries it: each dot a step into an object, or part of a key.
    const parts = name.split('.');
    const keys = (cuts: boolean[]) => parts.reduce<string[]>((at, each, i) => (i > 0 && !cuts[i - 1] ? [...at.slice(0, -1), `${at.at(-1)}.${each}`] : [...at, each]), []);
    const cuts = () => tc.draw(gs.arrays(gs.booleans(), { minSize: parts.length - 1, maxSize: parts.length - 1 }));
    place(token, keys(cuts()), carried);
    // Sometimes a second reading of the same name too, which makes it name nothing.
    if (parts.length > 1 && tc.draw(gs.integers({ minValue: 0, maxValue: 3 })) === 0) place(token, keys(cuts()), tc.draw(gs.sampledFrom([one, 'other'])));
  }
  // GitHub's pull requests, at refs/pull/<n>/merge, and their base branch.
  if (profile.startsWith('github') && tc.draw(gs.booleans())) {
    const ref = tc.draw(gs.sampledFrom(['refs/pull/3/merge', 'refs/heads/main', '']));
    put(token, 'event_name', tc.draw(gs.sampledFrom(['pull_request', 'pull_request', 'pull_request_target'])));
    put(token, 'ref', ref);
    put(token, 'base_ref', tc.draw(gs.sampledFrom(['main', 'Main', '', 'main/x', null])));
    put(token, 'workflow_ref', tc.draw(gs.sampledFrom([`acme/api/.github/workflows/ci.yml@${ref}`, 'acme/api/.github/workflows/ci.yml@refs/heads/main', `${ref}`, 5])));
  }
  // A token is JSON: what it says survives a round trip.
  return { profile, binding, token: JSON.parse(JSON.stringify(token)) as Record<string, unknown> };
});

/** Section 8: a name read every way its dots split it, naming a value only when exactly one reading reaches one. */
function read(claims: Record<string, unknown>, name: string): unknown {
  const parts = name.split('.');
  const found: unknown[] = [];
  for (let mask = 0; mask < 2 ** (parts.length - 1); mask++) {
    const keys = [parts[0]!];
    for (let i = 1; i < parts.length; i++) {
      if (mask & (1 << (i - 1))) keys.push(parts[i]!);
      else keys[keys.length - 1] += `.${parts[i]}`;
    }
    let at: unknown = claims;
    let reached = true;
    for (const key of keys) {
      if (!isObject(at) || !Object.hasOwn(at, key)) {
        reached = false;
        break;
      }
      at = at[key];
    }
    if (reached) found.push(at);
  }
  return found.length === 1 ? found[0] : undefined;
}

/** The names of a binding's claims a token does not satisfy, by sections 1 and 2 and the GitHub rules of workloads.ts. */
function unmet(profile: WorkloadProfile, binding: Record<string, string | string[]>, token: Record<string, unknown>): string[] {
  const github = profile.startsWith('github');
  let claims = token;
  const { event_name: event, ref, base_ref: base, workflow_ref: workflow } = token;
  if (github && event === 'pull_request' && typeof ref === 'string' && nonempty(base)) {
    // A pull request's run reads as one at the branch it merges into: its ref, and the ref its workflow_ref ends in.
    const at = `refs/heads/${base}`;
    const file = typeof workflow === 'string' && workflow.endsWith(`@${ref}`) ? `${workflow.slice(0, workflow.length - ref.length)}${at}` : workflow;
    claims = { ...token, ref: at, workflow_ref: file };
  }
  return Object.entries(binding).filter(([name, value]) => {
    const actual = read(claims, name);
    if (typeof actual !== 'string') return true;
    const values = typeof value === 'string' ? [value] : value;
    // GitHub's environment names are case-insensitive; every other claim matches exactly.
    if (github && name === 'environment') return !values.some((each) => each.toLowerCase() === actual.toLowerCase());
    return !values.includes(actual);
  }).map(([name]) => name);
}

const bindingSettings = propertySettings(400);

test(`a binding matches a token only on the claims it names, each read once and equal to its value or one of its values, seed ${bindingSettings.seed}`, () => hegel.test((tc) => {
  const { profile, binding, token } = tc.draw(bindingCase);
  tc.note(JSON.stringify({ profile, binding, token }));
  assert.deepEqual(differingClaims(profile, binding, token), unmet(profile, binding, token));
}, bindingSettings));

const pathKey = gs.sampledFrom(['a', 'b', 'a.b', 'b.c', 'kubernetes.io', 'io', 'c', '__proto__', 'constructor']);
const nested: gs.Generator<unknown> = gs.composite((tc) => {
  const depth = tc.draw(gs.integers({ minValue: 0, maxValue: 3 }));
  const leaf = () => tc.draw(gs.sampledFrom<unknown>(['v', 'w', 5, null, ['v'], true]));
  const object = (level: number): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    for (const key of tc.draw(gs.arrays(pathKey, { maxSize: 3, unique: true }))) put(out, key, level > 0 && tc.draw(gs.booleans()) ? object(level - 1) : leaf());
    return out;
  };
  return JSON.parse(JSON.stringify(object(depth))) as unknown;
});

const pathSettings = propertySettings(400);

test(`a claim name reads a value only when exactly one way of splitting it at its dots reaches one, seed ${pathSettings.seed}`, () => hegel.test((tc) => {
  const claims = tc.draw(nested) as Record<string, unknown>;
  const name = tc.draw(gs.arrays(gs.sampledFrom(['a', 'b', 'c', 'io', 'kubernetes', '__proto__', 'constructor']), { minSize: 1, maxSize: 5 })).join('.');
  tc.note(JSON.stringify({ claims, name }));
  assert.deepEqual(claimAt(claims, name), read(claims, name));
}, pathSettings));

const keptSettings = propertySettings(200);

test(`a binding that checks keeps every claim it was given, under its own name, seed ${keptSettings.seed}`, () => hegel.test((tc) => {
  const names = tc.draw(gs.arrays(gs.oneOf(gs.sampledFrom(CLAIM_NAMES), gs.fromRegex('[A-Za-z0-9_.:/-]{1,12}', { fullmatch: true })), { maxSize: 4, unique: true }));
  const claims: Record<string, unknown> = { sub: 'system:serviceaccount:ci:deploy' };
  for (const name of names) put(claims, name, tc.draw(gs.sampledFrom(VALUES)));
  tc.note(JSON.stringify(claims));
  let stored: Record<string, unknown>;
  try {
    stored = checkBinding({ profile: 'custom', issuer: 'https://kube.acme.example', claims }).claims;
  } catch {
    return;
  }
  assert.deepEqual(Object.keys(stored).sort(), Object.keys(claims).sort());
  for (const name of Object.keys(claims)) assert.equal(Object.hasOwn(stored, name) ? stored[name] : undefined, claims[name], name);
}, keptSettings));

// --- Cloudflare Access ---------------------------------------------------------

/** Who an Access token names, by verifier.ts: a service by its common_name, else a person by email and sub, lowercased. */
function principalOf(claims: Record<string, unknown>) {
  if (nonempty(claims.common_name)) return { type: 'service', id: claims.common_name, commonName: claims.common_name };
  if (nonempty(claims.email) && nonempty(claims.sub)) {
    const id = claims.email.toLowerCase();
    return { type: 'user', id, email: id, subject: claims.sub };
  }
  return null;
}

const identityClaims = gs.record({
  common_name: gs.sampledFrom([undefined, '', 'ci-deploy.access', 5, null]),
  email: gs.sampledFrom([undefined, '', 'Admin@Acme.example', 'bo@acme.example', 7, ['a@b.c']]),
  sub: gs.sampledFrom([undefined, '', '0c5f2a6e-uuid', 0]),
});

const ACCESS_ISSUER = 'https://acme.cloudflareaccess.com';
const ACCESS_AUDIENCE = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const ACCESS_KEYS: Jwk[] = [{ ...publicJwk('rsaA'), kid: 'access-rsa' }, { ...publicJwk('ecA'), kid: 'access-ec' }];
let jwks: ReturnType<typeof createServer>;
let jwksUrl: string;

before(async () => {
  jwks = createServer((_, response) => response.setHeader('content-type', 'application/json').end(JSON.stringify({ keys: ACCESS_KEYS })));
  await new Promise<void>((resolve) => jwks.listen(0, '127.0.0.1', resolve));
  jwksUrl = `http://127.0.0.1:${(jwks.address() as { port: number }).port}/cdn-cgi/access/certs`;
});
after(() => jwks.close());

const accessSettings = propertySettings(300);

test(`an Access assertion names a caller exactly when signed by the team's key with RS256 or ES256, from the team, for the application, in time, and naming someone, seed ${accessSettings.seed}`, async () => {
  const tolerance = [0, 30];
  const verifiers = tolerance.map((clockToleranceSeconds) => new AccessIdentityVerifier({ issuer: ACCESS_ISSUER, jwksUrl, audience: ACCESS_AUDIENCE, clockToleranceSeconds }));
  await hegel.testAsync(async (tc) => {
    const which = tc.draw(gs.integers({ minValue: 0, maxValue: 1 }));
    // An assertion as Access signs one, but for up to two things: each drawn from what it might be instead.
    const off = new Set(tc.draw(gs.arrays(gs.sampledFrom(['signer', 'alg', 'kid', 'header', 'iss', 'aud', 'exp', 'nbf', 'iat', 'identity', 'hmac'] as const), { maxSize: 2 })));
    const honest = <T>(field: Parameters<typeof off.has>[0], usual: readonly T[], others: readonly T[]): T => tc.draw(gs.sampledFrom(off.has(field) ? others : usual));
    const signer = honest('signer', ['rsaA', 'ecA'] as const, ['rsaX', 'ecB'] as const);
    const natural = algOf(signer);
    const header: Record<string, unknown> & { alg: string; kid?: string } = {
      alg: honest('alg', [natural], ['HS256', 'none', 'RS512', natural === 'RS256' ? 'ES256' : 'RS256']),
      kid: honest('kid', [undefined, natural === 'RS256' ? 'access-rsa' : 'access-ec'], ['elsewhere', natural === 'RS256' ? 'access-ec' : 'access-rsa']),
      ...honest<Record<string, unknown>>('header', [{}], [{ jwk: publicJwk(signer) }, { jku: `${jwksUrl}?evil` }, { crit: ['x-nope'], 'x-nope': 1 }]),
    };
    // Real time: each offset is five seconds or more from either tolerance's edges.
    const now = Date.now() / 1000;
    const at = (offset: number | string | undefined) => (typeof offset === 'number' ? Math.floor(now) + offset : offset);
    const exp = honest<number | string | undefined>('exp', [3600, 300], [undefined, -3600, -40, -20, -5, 'soon']);
    const nbf = honest<number | string | undefined>('nbf', [undefined, -20], [5, 20, 40, 3600, 'soon']);
    const iat = honest<number | string | undefined>('iat', [undefined, -5], [-86_400, 3600, 'soon']);
    const claims = Object.fromEntries(Object.entries({
      iss: honest('iss', [ACCESS_ISSUER], [`${ACCESS_ISSUER}/`, ACCESS_ISSUER.toUpperCase(), 'https://evil.cloudflareaccess.com']),
      aud: honest<unknown>('aud', [[ACCESS_AUDIENCE], ACCESS_AUDIENCE], [[ACCESS_AUDIENCE, 'other'], ['other'], 'other', [], undefined, `${ACCESS_AUDIENCE} `]),
      exp: at(exp), nbf: at(nbf), iat: at(iat),
      ...(off.has('identity') ? tc.draw(identityClaims) : tc.draw(gs.sampledFrom([{ sub: '0c5f2a6e-uuid', email: 'Admin@Acme.example' }, { sub: '', common_name: 'ci-deploy.access' }]))),
    }).filter(([, value]) => value !== undefined));
    const input = `${part(JSON.stringify(header))}.${part(JSON.stringify(claims))}`;
    const token = `${input}.${signature(input, off.has('hmac') ? { kind: 'hmac', key: signer, secret: tc.draw(gs.sampledFrom(['jwk', 'pem', 'der', 'n'] as const)) } : { kind: 'key', key: signer, as: header.alg }, ACCESS_KEYS)}`;
    tc.note(JSON.stringify({ header, claims, tolerance: tolerance[which] }));

    // RFC 7519 as jose reads it, with the times optional, and the audience any one of an array's.
    const tol = tolerance[which]!;
    const alg = header.alg;
    const signed = (alg === 'RS256' || alg === 'ES256') && !('crit' in header)
      && ACCESS_KEYS.some((jwk) => mayVerify(jwk, alg, header.kid) && signs(jwk, alg, input, Buffer.from(token.split('.')[2]!, 'base64url')));
    const aud = claims.aud;
    const timely = (exp === undefined || (typeof claims.exp === 'number' && claims.exp > now - tol))
      && (nbf === undefined || (typeof claims.nbf === 'number' && claims.nbf <= now + tol))
      && (iat === undefined || typeof claims.iat === 'number');
    const expected = signed && claims.iss === ACCESS_ISSUER && timely && (aud === ACCESS_AUDIENCE || (Array.isArray(aud) && aud.includes(ACCESS_AUDIENCE)))
      ? principalOf(claims)
      : null;
    // A refusal is the verifier's: a JOSE verdict on the token, or a token that names no one. A bug, or a key set it could
    // not fetch, is not one, and fails the test.
    const got = await verifiers[which]!.verify(token).catch((error: unknown) => {
      const fetching = error instanceof jose.JWKSTimeout || error instanceof jose.JWKSInvalid;
      if (fetching || !(error instanceof Error) || error instanceof TypeError || error instanceof RangeError || error instanceof ReferenceError) throw error;
      return null;
    });
    assert.deepEqual(got, expected);
  }, accessSettings);
});

const principalSettings = propertySettings(200);

test(`verified Access claims name a service by common_name, else a person by email and sub, and nobody otherwise, seed ${principalSettings.seed}`, () => hegel.test((tc) => {
  const claims = Object.fromEntries(Object.entries(tc.draw(identityClaims)).filter(([, value]) => value !== undefined));
  let got: unknown = null;
  try {
    got = toPrincipal(claims);
  } catch {
    // Refused: nobody.
  }
  assert.deepEqual(got, principalOf(claims));
}, principalSettings));
