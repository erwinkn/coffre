// A platform's proof held to a service's bindings, as the vault decides it
// on its own rows and clock (src/identity/proofs.ts, aws.ts): each step of
// 0.14.7's exchange and sign-in, now a pure function.
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  assumedRole, canonicalClaims, checkPolicy, hardEnd, matchAwsAnswer, matchIdToken, oldestMatching, policyText, readIdToken, runClaims, sessionRefusal, signatureRefusal, timesRefusal,
  type DecodedToken, type ProofBinding, type ProofFor, type VerifiedUnder,
} from '@coffre/core/identity';
import { exportJWK, FlattenedSign, generateKeyPair, SignJWT, type JWK } from 'jose';

const NOW = Date.UTC(2026, 10, 14, 12);
const at = (seconds: number) => Math.floor(NOW / 1000) + seconds;
const ORIGIN = 'https://secrets.acme.example';
const JKT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
const GITHUB = 'https://token.actions.githubusercontent.com';
const FETCHED: VerifiedUnder = { issuer: GITHUB, jwksUri: `${GITHUB}/.well-known/jwks` };
const RUN: ProofFor = { kind: 'run' };
const SESSION: ProofFor = { kind: 'session', jkt: JKT };

const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
/** A token as the app hands it over, its signature verified already: decoding checks none. */
const token = (claims: Record<string, unknown>): DecodedToken => {
  const read = readIdToken(`${part({ alg: 'RS256', kid: 'k1' })}.${part({ iss: GITHUB, sub: 'repo:acme/api:ref:refs/heads/main', aud: ORIGIN, iat: at(-10), exp: at(290), ...claims })}.c2ln`);
  assert.ok(!('refused' in read));
  return read;
};

const MAIN = { repository_owner_id: '9919', repository_id: '41532', workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/heads/main', ref: 'refs/heads/main', event_name: 'push' };
let made = 0;
/** A binding's row, made in the order of the calls: each one newer than the last. */
const binding = (more: Partial<ProofBinding> & { claimed?: Record<string, string | string[]>; rules?: Record<string, unknown> } = {}): ProofBinding => {
  const { claimed, rules, ...rest } = more;
  made += 1;
  return {
    id: `00000000-0000-4000-8000-${String(made).padStart(12, '0')}`, profile: 'github', issuer: GITHUB, jwksUri: FETCHED.jwksUri, jwks: null,
    claims: canonicalClaims(claimed ?? MAIN), policy: rules === undefined ? null : policyText(checkPolicy((rest.profile ?? 'github') as never, rules, { service: 'token:deploy' })),
    createdAt: new Date(Date.UTC(2026, 0, 1) + made * 1000), ...rest,
  };
};
const match = (claims: Record<string, unknown>, bindings: ProofBinding[], wanted: ProofFor = RUN, under = FETCHED, now = NOW) => {
  const found = matchIdToken(token(claims), bindings, { under, publicUrl: ORIGIN, wanted, now });
  return 'refused' in found ? found.refused : found;
};

test('a CI run trades its token at the oldest binding whose every claim it carries, of the service, its issuer and the keys it was verified under', () => {
  const [march, may, other] = [binding(), binding({ claimed: { ...MAIN, ref: 'refs/heads/main', event_name: ['push', 'pull_request'] } }), binding({ claimed: { ...MAIN, repository_id: '1' } })];
  const found = match(MAIN, [may, other, march]);
  assert.ok(typeof found !== 'string');
  assert.equal(found.binding, march);
  // Spent by what was signed, which one spelling of it has; the claims as the token says them.
  assert.deepEqual([found.spends, found.claims.repository_id, found.policy], [token(MAIN).signingInputHash, '41532', null]);
  assert.equal(oldestMatching([may, march], MAIN), march);
  // Of a pull request into main, by the branch it merges into: May's alone takes it.
  assert.equal((match({ ...MAIN, event_name: 'pull_request', ref: 'refs/pull/7/merge', base_ref: 'main', workflow_ref: 'acme/api/.github/workflows/ci.yml@refs/pull/7/merge' }, [march, may]) as { binding: ProofBinding }).binding, may);
  assert.equal(match({ ...MAIN, repository_id: '2' }, [march, may, other]), 'no_match');
  // A binding of another issuer, or under other keys than the app verified with, takes nothing; nor a token of another issuer than the keys'.
  assert.equal(match(MAIN, [binding({ issuer: 'https://gitlab.com' })]), 'no_match');
  assert.equal(match(MAIN, [binding({ jwksUri: 'https://elsewhere.example/jwks' })]), 'no_match');
  assert.equal(match({ ...MAIN, iss: 'https://gitlab.com' }, [march]), 'no_match');
  assert.equal(match(MAIN, [march], RUN, { ...FETCHED, issuer: 'https://gitlab.com' }), 'no_match');
  // A workload's binding, policy and all, makes sessions: a CI run's token is never bought there. Nor one whose claims do not read.
  assert.equal(match(MAIN, [binding({ rules: {} })]), 'no_match');
  assert.equal(match(MAIN, [binding({ claims: 'not json' }), binding({ claims: '[]' })]), 'no_match');
  assert.equal(match(MAIN, []), 'no_match');
});

test("a CI run's token is for this instance alone, within its times on the vault's clock, each bound to the second", () => {
  const bound = [binding()];
  assert.equal(typeof match({ ...MAIN, aud: [ORIGIN] }, bound), 'object');
  assert.equal(match({ ...MAIN, aud: 'https://other.example' }, bound), 'audience');
  assert.equal(match({ ...MAIN, aud: [ORIGIN, 'https://other.example'] }, bound), 'audience');
  assert.equal(match({ ...MAIN, aud: `${ORIGIN}#jkt=${JKT}` }, bound), 'audience');
  assert.equal(match({ ...MAIN, aud: undefined }, bound), 'audience');
  assert.equal(typeof match({ ...MAIN, exp: at(-29) }, bound), 'object');
  assert.equal(match({ ...MAIN, exp: at(-30) }, bound), 'expired');
  // `nbf` holds to jose's whole second, `exp` to the millisecond: a fractional one ends within its second.
  assert.equal(typeof match({ ...MAIN, exp: at(-30) + 0.5 }, bound, RUN, FETCHED, NOW + 499), 'object');
  assert.equal(match({ ...MAIN, exp: at(-30) + 0.5 }, bound, RUN, FETCHED, NOW + 500), 'expired');
  assert.equal(match({ ...MAIN, nbf: at(30) + 0.5 }, bound, RUN, FETCHED, NOW + 999), 'too_old');
  assert.equal(typeof match({ ...MAIN, iat: at(-3600) }, bound), 'object');
  assert.equal(match({ ...MAIN, iat: at(-3601) }, bound), 'too_old');
  assert.equal(typeof match({ ...MAIN, iat: at(30) }, bound), 'object');
  assert.equal(match({ ...MAIN, iat: at(31) }, bound), 'too_old');
  assert.equal(typeof match({ ...MAIN, nbf: at(30) }, bound), 'object');
  assert.equal(match({ ...MAIN, nbf: at(31) }, bound), 'too_old');
  // The clock is the one given: the same token an hour later is past its time.
  assert.equal(match(MAIN, bound, RUN, FETCHED, NOW + 3_600_000), 'expired');
  // Under keys a binding carries, nothing to ask whether a token still stands: it lives an hour at most.
  const carried = { issuer: 'https://cluster.acme.internal', jwksUri: `sha256:${'a'.repeat(64)}` };
  const custom = [binding({ profile: 'custom', issuer: carried.issuer, jwksUri: carried.jwksUri, jwks: '{"keys":[]}', claimed: { sub: 'ci' } })];
  assert.equal(typeof match({ iss: carried.issuer, sub: 'ci', exp: at(3590) }, custom, RUN, carried), 'object');
  assert.equal(match({ iss: carried.issuer, sub: 'ci', exp: at(3591) }, custom, RUN, carried), 'too_old');
  assert.deepEqual(timesRefusal(token({ exp: at(7200) }).claims, NOW), null);
  assert.deepEqual(timesRefusal(token({ iat: at(-7200) }).claims, NOW, { maxAge: null }), null);
});

test("a session's token names its key in the audience where its platform lets the caller choose one, and is spent unless it does", () => {
  const keyed = binding({ rules: {} });
  assert.deepEqual(JSON.parse(keyed.policy!), { keyAudience: true });
  for (const aud of [`${ORIGIN}#jkt=${JKT}`, `${ORIGIN}?jkt=${JKT}`, [`${ORIGIN}#jkt=${JKT}`]]) {
    const found = match({ ...MAIN, aud }, [keyed], SESSION);
    assert.ok(typeof found !== 'string', JSON.stringify(aud));
    // It works for this key alone, so it is never spent, and its own exp does not end the session.
    assert.deepEqual([found.binding, found.spends], [keyed, null]);
  }
  assert.equal(match({ ...MAIN, aud: ORIGIN }, [keyed], SESSION), 'audience');
  assert.equal(match({ ...MAIN, aud: `${ORIGIN}#jkt=another` }, [keyed], SESSION), 'audience');
  assert.equal(match({ ...MAIN, aud: `${ORIGIN}#jkt=${JKT}` }, [keyed], { kind: 'session', jkt: 'another' }), 'audience');
  // A bearer binding issues no session; a binding whose policy does not read issues nothing.
  assert.equal(match({ ...MAIN, aud: `${ORIGIN}#jkt=${JKT}` }, [binding()], SESSION), 'no_match');
  assert.equal(match({ ...MAIN, aud: `${ORIGIN}#jkt=${JKT}` }, [binding({ policy: '{' }), binding({ policy: '[]' })], SESSION), 'no_match');

  // A cluster's token names this instance and no key: spent once.
  const cluster = { issuer: 'https://cluster.acme.internal', jwksUri: `sha256:${'b'.repeat(64)}` };
  const sa = { sub: 'system:serviceaccount:ingest:api', 'kubernetes.io.serviceaccount.uid': '8f2d6a1e-5b3c-4e7f-9a0b-1c2d3e4f5a6b' };
  const kubernetes = binding({ profile: 'kubernetes', ...cluster, jwks: '{"keys":[]}', claimed: sa, rules: {} });
  const pod = { iss: cluster.issuer, sub: sa.sub, 'kubernetes.io': { namespace: 'ingest', serviceaccount: { name: 'api', uid: sa['kubernetes.io.serviceaccount.uid'] }, pod: { name: 'api-7c9f' } } };
  const found = match(pod, [kubernetes], SESSION, cluster);
  assert.ok(typeof found !== 'string', found as string);
  assert.deepEqual(found.spends, token(pod).signingInputHash);
  // The token says the account twice; where they differ it is no cluster's.
  assert.equal(match({ ...pod, 'kubernetes.io': { ...pod['kubernetes.io'], namespace: 'other' } }, [kubernetes], SESSION, cluster), 'malformed');
});

test('a managed identity repeats its token for hours: never spent, any age, its own exp its end; another platform beside it an hour old at most', () => {
  const tenant = '72f988bf-86f1-41af-91ab-2d7cd011db47';
  const azureUnder = { issuer: `https://sts.windows.net/${tenant}/`, jwksUri: `https://login.microsoftonline.com/${tenant}/discovery/keys` };
  const oid = '4c1d3b2a-9f8e-4d7c-b6a5-0123456789ab';
  const azure = binding({ profile: 'azure', ...azureUnder, claimed: { tid: tenant, oid }, rules: { audience: 'api://coffre-acme' } });
  const identity = { iss: azureUnder.issuer, sub: oid, tid: tenant, oid, ver: '1.0', aud: 'api://coffre-acme', iat: at(-5 * 3600), exp: at(3 * 3600) };
  const found = match(identity, [azure], SESSION, azureUnder);
  assert.ok(typeof found !== 'string', found as string);
  assert.equal(found.spends, null);
  assert.equal(hardEnd(azure, found.policy!, NOW, identity.exp), identity.exp * 1000);
  assert.equal(match({ ...identity, ver: '2.0' }, [azure], SESSION, azureUnder), 'malformed');
  // A token for an audience none takes is held to this instance's, and its times first: an hour old at most, as 0.14 checked them.
  assert.equal(match({ ...identity, aud: ORIGIN }, [azure], SESSION, azureUnder), 'too_old');
  assert.equal(match({ ...identity, aud: ORIGIN, iat: at(-60) }, [azure], SESSION, azureUnder), 'audience');
  // A custom binding on the same issuer takes this instance's URL: a token for it, five hours old, is matched there and refused too old.
  const custom = binding({ profile: 'custom', ...azureUnder, claimed: { sub: oid }, rules: {} });
  assert.equal(match({ ...identity, aud: ORIGIN }, [azure, custom], SESSION, azureUnder), 'too_old');
  assert.equal(typeof match({ ...identity, aud: ORIGIN, iat: at(-60) }, [azure, custom], SESSION, azureUnder), 'object');
  // An Entra resource may be this instance's URL itself: both take the token, and the older, a custom one, matches. Not five hours old.
  const own = binding({ profile: 'azure', ...azureUnder, claimed: { tid: tenant, oid }, rules: { audience: ORIGIN } });
  assert.equal(match({ ...identity, aud: ORIGIN }, [own, custom], SESSION, azureUnder), 'too_old');
  assert.equal((match({ ...identity, aud: ORIGIN, iat: at(-60) }, [own, custom], SESSION, azureUnder) as { binding: ProofBinding }).binding, custom);
  assert.equal((match({ ...identity, aud: ORIGIN }, [own], SESSION, azureUnder) as { binding: ProofBinding }).binding, own);
});

test("a session's hard end is the earliest of its binding's hours and, unless its token names the key, the token's own end", () => {
  const policy = (rules: Record<string, unknown>, profile = 'custom') => checkPolicy(profile as never, rules, { service: 'token:deploy' });
  const custom = { profile: 'custom' };
  assert.equal(hardEnd(custom, policy({}), NOW, null), NOW + 24 * 3_600_000);
  assert.equal(hardEnd(custom, policy({ sessionHours: 2 }), NOW, at(3 * 3600)), NOW + 2 * 3_600_000);
  assert.equal(hardEnd(custom, policy({ sessionHours: 2 }), NOW, at(600)), at(600) * 1000);
  assert.equal(hardEnd(custom, policy({ keyAudience: true }), NOW, at(600)), NOW + 24 * 3_600_000);
  // An aws proof is no token: its binding's hours alone. A profile whose policy has no hours: a day.
  assert.equal(hardEnd({ profile: 'aws' }, policy({ sessionHours: 5 }, 'aws'), NOW, null), NOW + 5 * 3_600_000);
  assert.equal(hardEnd({ profile: 'enrollment' }, policy({ replicas: 2 }, 'enrollment'), NOW, at(600)), at(600) * 1000);
  assert.equal(hardEnd({ profile: 'cloudflare' }, policy({}, 'cloudflare'), NOW, null), NOW + 24 * 3_600_000);
});

test("a session is refused at its sign-in outside its binding's sources, from nowhere the app could tell, or listing reads where the deployment lets none", () => {
  const sources = checkPolicy('custom', { sources: ['203.0.113.0/24', '2001:db8::/32'] }, { service: 'token:deploy' });
  assert.equal(sessionRefusal(sources, '203.0.113.9', { noReads: false }), null);
  assert.equal(sessionRefusal(sources, '2001:db8::7', { noReads: false }), null);
  assert.equal(sessionRefusal(sources, '198.51.100.1', { noReads: false }), 'no_match');
  assert.equal(sessionRefusal(sources, null, { noReads: false }), 'no_match');
  assert.equal(sessionRefusal({}, null, { noReads: true }), null);
  const reads = checkPolicy('custom', { reads: { '1b4e28ba-2fa1-41d2-883f-0016d3cca427': { keys: '*' } } }, { service: 'token:deploy' });
  assert.deepEqual([sessionRefusal(reads, null, { noReads: true }), sessionRefusal(reads, null, { noReads: false })], ['no_match', null]);
});

test('a signature is verified under the keys a binding carries: unknown_signer for a key they lack, malformed for anything else', async () => {
  const keyed = async (alg: 'RS256' | 'ES256', kid?: string) => {
    const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
    const jwk: JWK = { ...(await exportJWK(publicKey)), alg, ...(kid === undefined ? {} : { kid }) };
    const sign = (header: Record<string, unknown> = {}) => new SignJWT({ iss: 'i', sub: 's', aud: ORIGIN, iat: at(0), exp: at(60) }).setProtectedHeader({ alg, ...(kid === undefined ? {} : { kid }), ...header }).sign(privateKey);
    return { jwk, sign, key: privateKey };
  };
  const [a, b] = [await keyed('RS256', 'a'), await keyed('ES256', 'b')];
  const set = JSON.stringify({ keys: [a.jwk, b.jwk] });
  assert.equal(await signatureRefusal(await a.sign(), set), null);
  assert.equal(await signatureRefusal(await b.sign(), set), null);
  assert.equal(await signatureRefusal(await a.sign({ kid: 'rotated' }), set), 'unknown_signer');
  // Another key under a kid the set holds: no key of its signed it.
  const impostor = await keyed('RS256', 'a');
  assert.equal(await signatureRefusal(await impostor.sign(), set), 'malformed');
  // No kid, and two keys it could be: each is tried.
  const [c, d] = [await keyed('RS256'), await keyed('RS256')];
  const unnamed = JSON.stringify({ keys: [c.jwk, d.jwk] });
  assert.equal(await signatureRefusal(await d.sign(), unnamed), null);
  assert.equal(await signatureRefusal(await (await keyed('RS256')).sign(), unnamed), 'malformed');
  const hs = await new SignJWT({ sub: 's' }).setProtectedHeader({ alg: 'HS256', kid: 'a' }).sign(new TextEncoder().encode('a'.repeat(32)));
  assert.equal(await signatureRefusal(hs, set), 'malformed');
  assert.equal(await signatureRefusal('a.b.c', set), 'malformed');
  // Signed over an unencoded payload (RFC 7797): jose verifies it, but its payload is no claims object, whatever it decodes to.
  const raw = part({ iss: 'i', sub: 's', aud: ORIGIN, iat: at(0), exp: at(60) });
  const unencoded = await new FlattenedSign(new TextEncoder().encode(raw)).setProtectedHeader({ alg: 'RS256', kid: 'a', b64: false, crit: ['b64'] }).sign(a.key);
  const detached = `${unencoded.protected}.${raw}.${unencoded.signature}`;
  assert.equal(await signatureRefusal(detached, set), 'malformed');
  assert.deepEqual(readIdToken(detached), { refused: 'malformed' });
  assert.equal(await signatureRefusal(await a.sign(), 'not json'), 'malformed');
});

test("AWS's answer is matched to the oldest aws binding naming its role's account and unique ID; a root, a user or an answer that disagrees with itself, never", () => {
  const ACCOUNT = '671742253563';
  const ROLE = { account: ACCOUNT, arn: `arn:aws:sts::${ACCOUNT}:assumed-role/ingest-task/ingest-fn`, userId: 'AROAZ3EXAMPLE7QXYZAB:ingest-fn' };
  const aws = (claims: Record<string, string>, rules: Record<string, unknown> | null = {}) => binding({ profile: 'aws', issuer: 'urn:coffre:aws', jwksUri: 'urn:coffre:aws', claimed: claims, ...(rules === null ? {} : { rules }) });
  const [first, second] = [aws({ account: ACCOUNT, role_id: 'AROAZ3EXAMPLE7QXYZAB' }), aws({ account: ACCOUNT, role_id: 'AROAZ3EXAMPLE7QXYZAB' })];
  const found = matchAwsAnswer(ROLE, [second, first]);
  assert.ok(!('refused' in found));
  assert.deepEqual([found.binding, found.claims], [first, { account: ACCOUNT, role_id: 'AROAZ3EXAMPLE7QXYZAB', arn: ROLE.arn, session: 'ingest-fn' }]);
  const refused = (answer: typeof ROLE, bindings = [first]) => (matchAwsAnswer(answer, bindings) as { refused: string }).refused;
  assert.equal(refused({ ...ROLE, userId: 'AROAZ3EXAMPLENEWROLE:ingest-fn' }), 'no_match', 'a role made again under the same name');
  assert.equal(refused({ ...ROLE, arn: `arn:aws:iam::${ACCOUNT}:root` }), 'no_match');
  assert.equal(refused({ ...ROLE, arn: `arn:aws:sts::${ACCOUNT}:federated-user/bob` }), 'no_match');
  assert.equal(refused({ ...ROLE, arn: `arn:aws:iam::${ACCOUNT}:user/bob`, userId: 'AIDAZ3EXAMPLEUSER001' }), 'no_match');
  assert.equal(refused({ ...ROLE, arn: ROLE.arn.replace('arn:aws:', 'arn:aws-cn:') }), 'no_match');
  assert.equal(refused({ ...ROLE, account: '000000000000' }), 'malformed');
  assert.equal(refused({ ...ROLE, userId: 'AROAZ3EXAMPLE7QXYZAB:another' }), 'malformed');
  assert.equal(refused({ ...ROLE, account: 'acme' }), 'malformed');
  // No aws binding with a policy, or none under coffre's URN: nothing to match.
  assert.equal(refused(ROLE, []), 'no_match');
  assert.equal(refused(ROLE, [aws({ account: ACCOUNT, role_id: 'AROAZ3EXAMPLE7QXYZAB' }, null)]), 'no_match');
  assert.equal(refused(ROLE, [{ ...first, issuer: 'urn:coffre:enrollment' }]), 'no_match');
  assert.ok('roleId' in assumedRole(ROLE));
});

test("a run's claims are 0.14's list, each a string of 256 characters at most or a finite number, nested ones read where a binding would", () => {
  const claims = token({ ...MAIN, run_id: 7001, run_attempt: Infinity, actor: 'a'.repeat(300), secret: 'never', 'kubernetes.io': { pod: { name: 'api-7c9f' } } }).claims;
  assert.deepEqual(runClaims(claims), {
    sub: 'repo:acme/api:ref:refs/heads/main', actor: 'a'.repeat(256), event_name: 'push', ref: 'refs/heads/main', repository_id: '41532', run_id: 7001,
    workflow_ref: MAIN.workflow_ref, 'kubernetes.io.pod.name': 'api-7c9f',
  });
});

test('a token that is no compact JWS, or whose claims are not of their types, is malformed before any binding is read', () => {
  for (const wrong of ['', 'a.b', `${part({})}.${part({ iss: GITHUB })}.c2ln`, `${part({})}.${part({ iss: GITHUB, sub: 's', iat: 'now', exp: at(60) })}.c2ln`, 'x'.repeat(9000)]) {
    assert.deepEqual(readIdToken(wrong), { refused: 'malformed' });
  }
});
