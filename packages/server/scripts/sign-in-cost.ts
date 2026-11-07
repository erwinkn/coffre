/**
 * What a body sent before sign-in costs, by its size: the numbers
 * `SIGN_IN_BODY_BYTES` is computed from (`@coffre/core/schemas`).
 *
 *   node --conditions=coffre:source scripts/sign-in-cost.ts             with zod's eval-built fast paths, as on Node
 *   node --conditions=coffre:source scripts/sign-in-cost.ts --jitless   without, as on Workers, which forbids eval
 *
 * Each candidate is what a stranger's body of B bytes makes the app do
 * before anyone has signed in, at B = 4 KiB to 256 KiB (the key tries, 1 to
 * 32 KiB, where the bound is chosen):
 *
 * 1. A workload token that names no key (no `kid`), tried against each of
 *    a set's `MAX_KEYS` keys (`verifyWorkloadToken`'s `anyKey`), after
 *    `decodeWorkloadToken`: ES256, RS256 of 2,048 bits (what GitHub and
 *    GitLab publish) and of 4,096. Each try hashes the whole token again.
 * 2. Claim matching (`differingClaims`) of a B-byte token against realistic
 *    bindings, GitHub's, GitLab's and Kubernetes', one of names of five
 *    dots, the token's keys made so every split of each name is there.
 * 3. The body itself: `parseJsonBody` and `check` with each pre-sign-in
 *    route's schema, on the costliest shapes.
 * 4. An OAuth form: `URLSearchParams` and the one-pass duplicate check, on
 *    forms of `+`, `%41`, empty fields and many short fields.
 * 5. A passkey's answer: `verifyAssertion` and `verifyRegistration` of a
 *    response whose `clientDataJSON` fills the body.
 *
 * CPU is the process's own (`process.cpuUsage`, the thread pool's included,
 * where WebCrypto verifies), the median of nine samples, so a loaded machine
 * slows it less than wall time would. Each line fits a + b·B over the sizes,
 * and the key tries' fit, divided by `MAX_KEYS`, gives the cost of a try and
 * of a byte a try that `KEY_TRY_CPU_US` and `TOKEN_BYTE_CPU_NS` are taken
 * from; the bound is the largest power-of-two KiB at which `MAX_KEYS` tries
 * fit in what a request has left once a body is read
 * (`REQUEST_CPU_US − READ_CPU_US`).
 */
import { generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';

import type { BindingClaims, WorkloadProfile } from '@coffre/core/identity';
import { z } from 'zod';

if (process.argv.includes('--jitless')) z.config({ jitless: true });
const { decodeWorkloadToken, differingClaims, MAX_KEYS, verifyAssertion, verifyRegistration, verifyWorkloadToken } = await import('@coffre/core/identity');
const { countValues, MAX_BODY_NODES, READ_CPU_US, REQUEST_CPU_US, SIGN_IN_BODY_BYTES } = await import('@coffre/core/schemas');
const { SoftAuthenticator } = await import('@coffre/conformance/authenticator');
const { check, parseJsonBody } = await import('../src/http.ts');
const { SIGN_IN_SCHEMAS } = await import('../src/auth-routes.ts');

const KiB = 1024;
const SIZES = [4, 8, 16, 32, 64, 128, 256].map((k) => k * KiB);
/**
 * The key tries' sizes: the range the bound is chosen in, up to the power of two above it. Past 32 KiB a try costs
 * more than linearly (twice as much at 64 KiB as at 32), which a fit over 4 to 256 KiB would carry back down into it.
 */
const TRY_SIZES = [1, 4, 8, 16, 32].map((k) => k * KiB);
const BUDGET_MS = (REQUEST_CPU_US - READ_CPU_US) / 1000;

/** The median of nine samples of `run`, each `repeats` runs, in ms of the process's CPU a run. */
async function cpuMs(run: () => unknown, repeats: number): Promise<number> {
  const spent: number[] = [];
  for (let i = 0; i < 9; i += 1) {
    const start = process.cpuUsage();
    for (let r = 0; r < repeats; r += 1) await run();
    const used = process.cpuUsage(start);
    spent.push((used.user + used.system) / 1000 / repeats);
  }
  return spent.sort((a, b) => a - b)[4]!;
}

/** Least squares of ms over B: the fixed cost, and the cost a byte. */
function fit(points: readonly [number, number][]): { a: number; b: number } {
  const n = points.length;
  const mx = points.reduce((s, [x]) => s + x, 0) / n;
  const my = points.reduce((s, [, y]) => s + y, 0) / n;
  const b = points.reduce((s, [x, y]) => s + (x - mx) * (y - my), 0) / points.reduce((s, [x]) => s + (x - mx) ** 2, 0);
  return { a: my - b * mx, b };
}

const results: { what: string; a: number; b: number; tries: boolean }[] = [];
async function measure(what: string, run: (bytes: number) => Promise<() => unknown>, { repeats = 5, tries = false, sizes = SIZES } = {}): Promise<void> {
  const points: [number, number][] = [];
  const cells: string[] = [];
  for (const bytes of sizes) {
    const call = await run(bytes);
    await call();
    const ms = await cpuMs(call, repeats);
    points.push([bytes, ms]);
    cells.push(ms.toFixed(2).padStart(7));
  }
  const { a, b } = fit(points);
  results.push({ what, a, b, tries });
  const each = tries ? `; a try ${((a * 1000) / MAX_KEYS).toFixed(0)} µs + ${((b * 1e6) / MAX_KEYS).toFixed(1)} ns/B` : '';
  console.log(`  ${what.padEnd(46)}${cells.join('')}   ${(a * 1000).toFixed(0).padStart(5)} µs + ${(b * 1e6).toFixed(1).padStart(6)} ns/B${each}`);
}

const header = (title: string, sizes = SIZES) => console.log(`\n${title}\n  ${''.padEnd(46)}${sizes.map((s) => `${s / KiB} KiB`.padStart(7)).join('')}   fit`);
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const now = Math.floor(Date.now() / 1000);
const ISSUER = 'https://issuer.example';
const AUDIENCE = 'https://coffre.example';

/** A token of `bytes` bytes, signed by none of the keys and naming none (no `kid`), so every key is tried. */
function strangerToken(alg: 'ES256' | 'RS256', bytes: number, extra: Record<string, unknown> = {}): string {
  const head = b64({ alg, typ: 'JWT' });
  const claims = { iss: ISSUER, aud: AUDIENCE, sub: 'repo:acme/app:ref:refs/heads/main', iat: now, exp: now + 300, ...extra };
  const base = `${head}.${b64({ ...claims, pad: '' })}.${Buffer.from(randomBytes(alg === 'ES256' ? 64 : 256)).toString('base64url')}`;
  const pad = 'x'.repeat(Math.max(0, Math.floor(((bytes - base.length) * 3) / 4)));
  return `${head}.${b64({ ...claims, pad })}.${base.split('.')[2]}`;
}

function keySet(kind: 'ec' | 'rsa2048' | 'rsa4096'): { keys: Record<string, unknown>[] } {
  const keys = Array.from({ length: MAX_KEYS }, () => {
    const pair = kind === 'ec' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('rsa', { modulusLength: kind === 'rsa2048' ? 2048 : 4096 });
    return { ...(pair.publicKey as KeyObject).export({ format: 'jwk' }), alg: kind === 'ec' ? 'ES256' : 'RS256', use: 'sig' };
  });
  return { keys };
}

console.log(`${process.version}${process.argv.includes('--jitless') ? ', jitless' : ''}; budget ${BUDGET_MS} ms (REQUEST_CPU_US − READ_CPU_US), MAX_KEYS ${MAX_KEYS}, SIGN_IN_BODY_BYTES ${SIGN_IN_BODY_BYTES}`);

// 1. A token that names no key, decoded, then tried against every key of the set: what a stranger's token costs.
header(`1. a token naming no key, decoded and tried against ${MAX_KEYS} keys (ms)`, TRY_SIZES);
for (const [kind, alg] of [['ec', 'ES256'], ['rsa2048', 'RS256'], ['rsa4096', 'RS256']] as const) {
  const keys = keySet(kind);
  await measure(`${alg}, ${kind === 'ec' ? 'P-256' : `${kind.slice(3)}-bit`} keys`, async (bytes) => {
    const token = strangerToken(alg, bytes);
    return async () => {
      decodeWorkloadToken(token);
      await verifyWorkloadToken(token, keys as never, { issuer: ISSUER, audience: AUDIENCE, now: new Date() }).then(
        () => {
          throw new Error('a stranger token verified');
        },
        () => {},
      );
    };
  }, { repeats: 5, tries: true, sizes: TRY_SIZES });
}

// 2. Claim matching, after a token verifies, against bindings as they are made: a handful of names, up to five dots.
header('2. claim matching of a B-byte token, every binding below (ms)');
const BINDINGS: [WorkloadProfile, BindingClaims][] = [
  ['github', { repository: 'acme/app', ref: 'refs/heads/main', environment: 'production', job_workflow_ref: 'acme/app/.github/workflows/deploy.yml@refs/heads/main' }],
  ['gitlab', { project_path: 'acme/app', ref: 'main', ref_type: 'branch', namespace_path: 'acme' }],
  ['kubernetes', { 'kubernetes.io.namespace': 'prod', 'kubernetes.io.serviceaccount.name': 'app' }],
  ['oidc', { 'a.b.c.d.e.f': 'x', 'g.h.i.j.k.l': 'y', sub: 'z' }],
];
/** Every split of `name`'s parts, from `from` on, as nested keys, each reaching an object, so that no path ends early. */
function everySplit(parts: string[], from = 0): Record<string, unknown> {
  const at: Record<string, unknown> = {};
  for (let to = from + 1; to <= parts.length; to += 1) at[parts.slice(from, to).join('.')] = to === parts.length ? {} : everySplit(parts, to);
  return at;
}
await measure('4 bindings, 13 claims, every split present', async (bytes) => {
  const shaped: Record<string, unknown> = {};
  for (const [, claims] of BINDINGS) for (const name of Object.keys(claims)) Object.assign(shaped, everySplit(name.split('.')));
  // The rest of the token, as a verified one may be: up to the values a token's part holds (`MAX_BODY_NODES`), each a
  // key and a long string, which each lookup hashes past.
  const room = MAX_BODY_NODES - countValues(JSON.stringify(shaped)) - 1;
  const each = Math.max(1, Math.floor((bytes * 0.75 - JSON.stringify(shaped).length) / room) - 8);
  for (let i = 0; i < room; i += 1) shaped[`k${i}`] = 'x'.repeat(each);
  const token = JSON.parse(JSON.stringify(shaped)) as Record<string, unknown>;
  return () => {
    for (const [profile, claims] of BINDINGS) differingClaims(profile, claims, token);
  };
});

// 3. The body: its count and parse, then each pre-sign-in route's schema, on the costliest shapes that fit.
header('3. a body, parsed and validated by each pre-sign-in schema, the costliest (ms)');
const filler = (bytes: number, unit: string) => unit.repeat(Math.max(1, Math.floor((bytes - 32) / unit.length)));
const BODY_SHAPES: Record<string, (bytes: number) => string> = {
  'one long string': (bytes) => `{"token":"${'x'.repeat(bytes - 32)}","service":"s"}`,
  'escaped string': (bytes) => `{"token":"${filler(bytes, '\\u00e9')}","service":"s"}`,
  'values to the count': (bytes) => `{"proof":{"oidc":[${filler(bytes, '0,').slice(0, -1)}]},"service":"s"}`,
  'nesting': (bytes) => `{"response":${'['.repeat(Math.floor(bytes / 2) - 16)}${']'.repeat(Math.floor(bytes / 2) - 16)}}`,
};
for (const [shape, make] of Object.entries(BODY_SHAPES)) {
  await measure(shape, async (bytes) => {
    const text = make(bytes);
    return () => {
      let body: unknown;
      try {
        body = parseJsonBody(text);
      } catch {
        return;
      }
      for (const schema of Object.values(SIGN_IN_SCHEMAS)) check(schema, body);
    };
  });
}

// 4. An OAuth form (the token and revoke endpoints): `URLSearchParams`, then the one pass that finds a name twice.
header('4. an OAuth form, read and checked for a name given twice (ms)');
const FORMS: Record<string, (bytes: number) => string> = {
  'one field of +': (bytes) => `code=${'+'.repeat(bytes - 5)}`,
  'one field of %41': (bytes) => `code=${'%41'.repeat(Math.floor((bytes - 5) / 3))}`,
  'empty fields': (bytes) => '&'.repeat(bytes),
  'short distinct fields': (bytes) => Array.from({ length: Math.floor(bytes / 7) }, (_, i) => `f${i.toString(36)}=`).join('&').slice(0, bytes),
};
for (const [shape, make] of Object.entries(FORMS)) {
  await measure(shape, async (bytes) => {
    const text = make(bytes);
    return () => {
      const params = new URLSearchParams(text);
      const seen = new Set<string>();
      for (const name of params.keys()) {
        if (seen.has(name)) break;
        seen.add(name);
      }
    };
  });
}

// 5. A passkey's answer, the body's worth of it in what the verifier decodes and hashes.
header('5. a passkey answer filling the body (ms)');
const SITE = { origin: 'https://coffre.example', rpId: 'coffre.example' };
const challenge = new Uint8Array(32).fill(7);
const handle = new Uint8Array(16).fill(9);
const authenticator = await SoftAuthenticator.create('ES256');
authenticator.userHandle = handle;
const passkey = { credentialId: authenticator.credentialId, publicKey: await authenticator.publicKey(), algorithm: -7 as const, userHandle: handle };
await measure("assertion, clientDataJSON's extra member", async (bytes) => {
  const answer = await authenticator.assert({ ...SITE, challenge }, { clientData: { pad: 'x'.repeat(Math.floor((bytes * 3) / 4) - 200) } });
  return async () => {
    const result = await verifyAssertion(answer, { ...SITE, challenge, values: 1600, passkey });
    if (!result.ok) throw new Error(result.reason);
  };
});
await measure("registration, clientDataJSON's extra member", async (bytes) => {
  const answer = await authenticator.register({ ...SITE, challenge, userHandle: handle }, { clientData: { pad: 'x'.repeat(Math.floor((bytes * 3) / 4) - 400) } });
  return async () => {
    const result = await verifyRegistration(answer, { ...SITE, challenge, values: 1600 });
    if (!result.ok) throw new Error(result.reason);
  };
});

// The bound, as `SIGN_IN_BODY_BYTES` computes it from the constants beside it, then from what this run measured: the
// largest power-of-two KiB at which the dearest key tries fit, and what every candidate costs there.
const bound = (keyTryUs: number, byteNs: number) => 1024 * 2 ** Math.floor(Math.log2(((BUDGET_MS * 1000 - MAX_KEYS * keyTryUs) * 1000) / (MAX_KEYS * byteNs) / 1024));
const dearest = results.filter((r) => r.tries).sort((x, y) => y.a + y.b * 32 * KiB - (x.a + x.b * 32 * KiB))[0]!;
const [keyTryUs, byteNs] = [(dearest.a * 1000) / MAX_KEYS, (dearest.b * 1e6) / MAX_KEYS];
const measured = bound(keyTryUs, byteNs);
console.log(`\ndearest tries: ${dearest.what}, ${keyTryUs.toFixed(0)} µs + ${byteNs.toFixed(1)} ns/B a try`);
console.log(`within ${BUDGET_MS} ms: B ≤ ${(((BUDGET_MS * 1000 - MAX_KEYS * keyTryUs) * 1000) / (MAX_KEYS * byteNs) / 1000).toFixed(1)} kB, so ${measured / KiB} KiB measured here; ${SIGN_IN_BODY_BYTES / KiB} KiB from the constants`);
for (const { what, a, b } of results) console.log(`  ${(a + b * SIGN_IN_BODY_BYTES).toFixed(2).padStart(6)} ms at ${SIGN_IN_BODY_BYTES / KiB} KiB  ${what}`);
