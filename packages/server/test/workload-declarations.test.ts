import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { deriveKey, generateToken, github, hashToken, signin, tokenHint } from '@coffre/core/identity';
import { eq } from 'drizzle-orm';

import { credentials, enrollments, serviceBindings } from './db/tables.ts';
import { authMac, checkAuthRow } from '../src/auth-rows.ts';
import { serveApi } from '../src/api/router.ts';
import { routes } from '../src/api/routes.ts';
import { PERSONAL_TOKEN_ROUTES } from '../src/api/personal-tokens.ts';
import { ISSUING_ROUTES, WORKLOAD_ROUTES } from '../src/api/workload-routes.ts';
import { PROOFS } from '../src/api/workloads.ts';
import { ROUTE_SCOPES } from '../src/mcp/scopes.ts';
import { resolveConfig } from '../src/config.ts';
import { createRuntime, type CoffreRuntime } from '../src/runtime.ts';
import { processLimits } from '../src/workloads/limits.ts';
import { answer, type Pages } from './start-fixture.ts';
import { contextFor, holdSomething, openTestDatabase, resetDatabase, testDeps, type FixtureDeps } from './api-fixture.ts';

/** A sign-in row's MAC as section 11 and auth-rows.ts's tuple say it, computed apart from `authMac`. */
function independentMac(kind: string, values: unknown[]): Buffer {
  return createHmac('sha256', deriveKey(deps.chainKey, 'signin-rows/v1')).update(JSON.stringify(['coffre.auth.v2', kind, ...values])).digest();
}

// What docs/design/workload-access.md's PR 0 declares, before the changes
// that serve it: every route answers 501 past sign-in, the new tokens are
// never bearers, and the rows' MAC kinds cover what binds them.

const ORIGIN = 'https://secrets.acme.example';
const ROOT = 'admin@acme.example';
const SERVICE = 'api-prod';
const MEMBER = `token:${SERVICE}`;
const ID = '00000000-0000-4000-8000-000000000000';

let db: Awaited<ReturnType<typeof openTestDatabase>>;
let deps: FixtureDeps;
let runtime: CoffreRuntime;
const ui = {} as Pages;

before(async () => {
  db = await openTestDatabase();
});

after(async () => {
  await db.close();
});

beforeEach(async () => {
  await resetDatabase(db.owner);
  deps = testDeps(db.runtime, [ROOT]);
  const limits = processLimits({ perSource: 1000, total: 1000 });
  const config = resolveConfig({
    publicUrl: ORIGIN,
    vault: deps.vault,
    auth: signin({ providers: [github({ clientId: 'a', clientSecret: 'b' })], workloads: { limits } }),
    auditChainKey: deps.chainKey.toString('base64'),
  });
  runtime = createRuntime(config, deps.db, deps.vault, { json: async () => ({}) });
  assert.equal((await deps.vault.admit({ actor: `user:${ROOT}`, principal: MEMBER })).ok, true);
});

test("each route of the design is declared in the API and answers 501, naming the change that serves it, once the caller is let in", async () => {
  const declared: [string, string, unknown, RegExp][] = [
    ['GET', `/api/members/${MEMBER}/bindings/${ID}/enrollments`, undefined, /PR 3/],
    ['POST', `/api/members/${MEMBER}/bindings/${ID}/enrollments`, {}, /PR 3/],
    ['POST', `/api/members/${MEMBER}/bindings/${ID}/enrollments/${ID}/promote`, { now: true }, /PR 3/],
    ['POST', `/api/members/${MEMBER}/tokens/${ID}/approve`, undefined, /PR 3/],
    ['GET', '/api/freezes', undefined, /PR 4/],
    ['POST', '/api/freezes', { target: MEMBER, reason: 'leaked' }, /PR 4/],
    ['DELETE', `/api/freezes/${encodeURIComponent(`credential:${ID}/stripe`)}`, undefined, /PR 4/],
  ];
  const ctx = await contextFor(deps, ROOT);
  for (const [method, path, body, change] of declared) {
    const response = await serveApi(new Request(`${ORIGIN}${path}`, { method, ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }) }), ctx);
    const answered = (await response.json()) as { error: string; message: string };
    assert.equal(response.status, 501, `${method} ${path}: ${JSON.stringify(answered)}`);
    assert.equal(answered.error, 'not_implemented');
    assert.match(answered.message, change);
  }
  // Their inputs are checked first, as any route's: a promote's flag, a freeze's reason, an enrollment's ID.
  const refused: [string, string, unknown][] = [
    ['POST', `/api/members/${MEMBER}/bindings/${ID}/enrollments/${ID}/promote`, { now: 'yes' }],
    ['POST', '/api/freezes', { target: MEMBER }],
    ['POST', `/api/members/${MEMBER}/bindings/${ID}/enrollments/not-an-id/promote`, {}],
  ];
  for (const [method, path, body] of refused) {
    const response = await serveApi(new Request(`${ORIGIN}${path}`, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }), ctx);
    assert.equal(response.status, 400, `${method} ${path}`);
  }
  // Every map of the API has said whether each reaches it: a personal token and MCP never mint, promote, approve or freeze.
  for (const key of Object.keys(routes) as (keyof typeof routes)[]) {
    assert.equal(typeof WORKLOAD_ROUTES[key], 'boolean', key);
    assert.equal(typeof PERSONAL_TOKEN_ROUTES[key], 'boolean', key);
    assert.ok(key in ROUTE_SCOPES, key);
  }
  for (const key of ['POST /members/:member/bindings/:id/enrollments', 'POST /freezes', 'DELETE /freezes/:target', 'POST /members/:member/tokens/:id/approve'] as const) {
    assert.equal(PERSONAL_TOKEN_ROUTES[key], false, key);
    assert.equal(ROUTE_SCOPES[key], null, key);
  }
  // A session reaches what a service token does, its handlers deciding, but issues nothing and changes no access; what a person does stays theirs.
  for (const key of ['GET /personal/:project', 'PATCH /secrets/:project/:environment', 'DELETE /members/:member/tokens/:id'] as const) {
    assert.equal(WORKLOAD_ROUTES[key], true, key);
  }
  for (const key of [
    'POST /handles', 'POST /members/:member/tokens/:id/approve', 'POST /freezes', 'DELETE /freezes/:target', 'POST /oauth/authorizations',
    'POST /members/:member/tokens', 'POST /members/:member/bindings', 'POST /members/:member/bindings/:id/enrollments', 'PATCH /access/:member',
  ] as const) {
    assert.equal(WORKLOAD_ROUTES[key], false, key);
  }
  for (const key of ISSUING_ROUTES) assert.equal(WORKLOAD_ROUTES[key], false, key);
  assert.deepEqual(Object.keys(PROOFS), ['oidc']);
});

test("a workload's narrowing is declared beside /api/auth/oidc, and answers 501", async () => {
  for (const [path, change] of [['/api/auth/workload/narrow', /PR 4/]] as const) {
    const response = await answer(new Request(`${ORIGIN}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }), runtime, ui, '203.0.113.9');
    assert.equal(response.status, 501, path);
    assert.match(((await response.json()) as { message: string }).message, change);
    assert.equal((await answer(new Request(`${ORIGIN}${path}`), runtime, ui, '203.0.113.9')).status, 405, `${path} takes a POST`);
  }
});

test("a workload's session and an enrollment code are never bearer credentials", async () => {
  for (const [kind, reason] of [['workload', 'workload'], ['enrollment', 'enrollment']] as const) {
    const token = generateToken(kind);
    const response = await answer(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${token}` } }), runtime, ui, '203.0.113.9');
    const body = (await response.json()) as { error: string; reason?: string };
    assert.deepEqual([response.status, body.error, body.reason], [401, 'unauthenticated', reason]);
  }
});

test("a workload's session is a MAC kind of its own, over what binds it; a binding's policy and an enrollment code are covered too", async () => {
  await holdSomething(db.owner, deps.vault, MEMBER, `user:${ROOT}`);
  const made = await runtime.workloads!.bind(await contextFor(deps, ROOT), SERVICE, {
    profile: 'custom', issuer: 'https://cluster.acme.example', claims: { sub: 'system:serviceaccount:api:api' }, label: null, replaces: [],
    jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0', kid: 'k', alg: 'ES256', use: 'sig' }] },
  }, { dryRun: false });
  assert.ok('binding' in made);
  const bindingId = made.binding.id;
  const [binding] = await db.owner.select().from(serviceBindings).where(eq(serviceBindings.id, bindingId));
  assert.equal(binding!.policy, null, 'a binding this release makes is a bearer binding');

  const code = generateToken('enrollment');
  const enrollment = {
    id: crypto.randomUUID(), bindingId, codeHash: hashToken(code), codeHint: tokenHint(code), scope: '[]',
    createdAt: new Date(), createdBy: `user:${ROOT}`, createdWith: null, expiresAt: new Date(Date.now() + 86_400_000),
  };
  await db.owner.insert(enrollments).values({ ...enrollment, authMac: authMac(deps.chainKey, 'enrollments', enrollment) });
  const [stored] = await db.owner.select().from(enrollments);
  assert.ok(checkAuthRow(deps.chainKey, 'enrollments', stored!));
  // The tuple as section 11 spells it, encoded here on its own: kind `enrollments`, its seven fields once each.
  assert.deepEqual(stored!.authMac, independentMac('enrollments', [enrollment.id, bindingId, enrollment.codeHash.toString('hex'), '[]', `user:${ROOT}`, null, enrollment.expiresAt.getTime()]));
  for (const [field, value] of [['scope', '[{"projectId":"p","environmentId":null,"role":"owner"}]'], ['expiresAt', new Date(Date.now() + 90 * 86_400_000)], ['bindingId', crypto.randomUUID()], ['createdWith', crypto.randomUUID()]] as const) {
    assert.ok(!checkAuthRow(deps.chainKey, 'enrollments', { ...stored!, [field]: value }), `an enrollment's ${field} is under its MAC`);
  }
  const hinted = { ...stored!, codeHint: 'coffre_enr_…zzzz' };
  assert.ok(checkAuthRow(deps.chainKey, 'enrollments', hinted), 'its hint is not');

  const token = generateToken('workload');
  const session = {
    id: crypto.randomUUID(), kind: 'workload', tokenHash: hashToken(token), tokenHint: 'coffre_wl_…abcd', generation: 1, principal: MEMBER,
    identityId: null, scope: null, places: null, label: null, createdAt: new Date(), createdBy: `binding:${bindingId}`, expiresAt: new Date(Date.now() + 3_600_000),
    lastUsedAt: null, lastUsedIp: null, revokedAt: null, revokedBy: null,
    jkt: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', notAfter: new Date(Date.now() + 86_400_000), ancestors: null, constraints: null,
    enrollmentId: enrollment.id, approvedAt: null, approvedBy: null,
  };
  await db.owner.insert(credentials).values({ ...session, authMac: authMac(deps.chainKey, 'credentials', session) });
  const [row] = await db.owner.select().from(credentials).where(eq(credentials.id, session.id));
  assert.ok(checkAuthRow(deps.chainKey, 'credentials', row!));
  // Today's credential fields, then createdBy, scope, places, jkt, notAfter, ancestors, constraints, enrollmentId, approvedAt, approvedBy.
  assert.deepEqual(row!.authMac, independentMac('workload_credentials', [
    session.id, session.tokenHash.toString('hex'), 'workload', MEMBER, 1, null, session.expiresAt.getTime(), null,
    session.createdBy, null, null, session.jkt, session.notAfter.getTime(), null, null, enrollment.id, null, null,
  ]));
  const changes: [string, unknown][] = [
    ['jkt', 'AAAAXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'], ['notAfter', new Date(Date.now() + 7 * 86_400_000)], ['ancestors', `["${ID}"]`],
    ['constraints', '{}'], ['enrollmentId', null], ['approvedAt', new Date()], ['approvedBy', `user:${ROOT}`], ['scope', '[]'], ['places', '[]'],
    ['createdBy', `user:${ROOT}`], ['expiresAt', new Date(Date.now() + 7_200_000)], ['revokedAt', new Date()],
  ];
  for (const [field, value] of changes) {
    assert.ok(!checkAuthRow(deps.chainKey, 'credentials', { ...row!, [field]: value }), `a session's ${field} is under its MAC`);
  }
  // Nor does it check as any other kind: the same fields under another kind's MAC fail it.
  assert.ok(!checkAuthRow(deps.chainKey, 'credentials', { ...row!, kind: 'service' }));
  const used = { ...row!, lastUsedAt: new Date(), lastUsedIp: '203.0.113.9' };
  assert.ok(checkAuthRow(deps.chainKey, 'credentials', used), 'its last use is not');
  // Its token reads as no one on the bearer path, its row notwithstanding.
  const response = await answer(new Request(`${ORIGIN}/api/me`, { headers: { authorization: `Bearer ${token}` } }), runtime, ui, '203.0.113.9');
  assert.equal(response.status, 401);
});
