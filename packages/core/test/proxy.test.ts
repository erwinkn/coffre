// Proxy definitions as the vault keeps them (0.16, T186; docs/design/proxy-ui.md, sections 1, 5 and 7): each
// definition checked at save and kept in one canonical shape, the keys its templates name read by one parser, and
// what an Owner may not point a definition at.
import test from 'node:test';
import assert from 'node:assert/strict';

import { canonicalDefinition, definitionKeys, privateHost, proxyDefinitionProblem, RELEASE, VAULT_METHODS, versioned, type ProxyDefinition, type VaultEntry } from '../src/vault.ts';

const ROUTE = {
  kind: 'route',
  name: 'openai',
  upstream: 'https://api.openai.com/v1',
  inject: [{ kind: 'header', name: 'Authorization', template: 'Bearer {OPENAI_API_KEY}' }],
  allow: [{ methods: ['POST'], path: '/chat/completions' }, { methods: ['GET'], path: '/models/**' }],
};

test('a route is kept in one shape: every field there, a header named in lowercase, no limit and no egress as null', () => {
  assert.deepEqual(canonicalDefinition(ROUTE), {
    kind: 'route', name: 'openai', upstream: 'https://api.openai.com/v1',
    inject: [{ kind: 'header', name: 'authorization', template: 'Bearer {OPENAI_API_KEY}' }],
    allow: [{ methods: ['POST'], path: '/chat/completions' }, { methods: ['GET'], path: '/models/**' }],
    limit: { perMinute: null, perDay: null }, placeholder: null, egress: null,
  });
  // Methods in the list's order, whatever order they were written in.
  assert.deepEqual((canonicalDefinition({ ...ROUTE, allow: [{ methods: ['POST', 'GET'], path: '/a' }] }) as Extract<ProxyDefinition, { kind: 'route' }>).allow, [{ methods: ['GET', 'POST'], path: '/a' }]);
});

test('the keys a definition sends: each template key once, sorted; a signer, verifier or tunnel its one key', () => {
  const sigv4 = canonicalDefinition({
    kind: 'route', name: 's3', upstream: 'https://s3.eu-west-3.amazonaws.com',
    inject: [{ kind: 'header', name: 'x-tenant', template: '{TENANT}' }, { kind: 'sigv4', accessKeyId: '{AWS_ACCESS_KEY_ID}', secretAccessKey: '{AWS_SECRET_ACCESS_KEY}', sessionToken: null, region: 'eu-west-3', service: 's3' }],
  });
  assert.deepEqual(definitionKeys(sigv4), ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'TENANT']);
  assert.deepEqual(definitionKeys(canonicalDefinition({ kind: 'route', name: 'twilio', upstream: 'https://api.twilio.com', inject: [{ kind: 'basic', user: '{SID}', password: '{SID}:{TOKEN}' }] })), ['SID', 'TOKEN']);
  assert.deepEqual(definitionKeys(canonicalDefinition({ kind: 'signer', name: 'dfns', signer: { kind: 'private-key', key: 'DFNS_KEY' } })), ['DFNS_KEY']);
  assert.deepEqual(definitionKeys(canonicalDefinition({ kind: 'verifier', name: 'yousign', hmac: { key: 'YOUSIGN_SECRET', encoding: 'hex', prefix: 'sha256=', maxBytes: null } })), ['YOUSIGN_SECRET']);
  assert.deepEqual(definitionKeys(canonicalDefinition({ kind: 'tunnel', name: 'replica', key: 'REPLICA_URL', hosts: ['db.acme.example'], network: null })), ['REPLICA_URL']);
});

test('what no UI definition may be: each refused with its reason', () => {
  const cases: [string, unknown, RegExp][] = [
    ['a name with capitals', { ...ROUTE, name: 'OpenAI' }, /lowercase letter/],
    ['a name with a slash', { ...ROUTE, name: 'a/b' }, /lowercase letter/],
    ['a 33-character name', { ...ROUTE, name: `a${'b'.repeat(32)}` }, /up to 31/],
    ['an unknown field', { ...ROUTE, regex: '.*' }, /no field "regex"/],
    ['plain http', { ...ROUTE, upstream: 'http://api.openai.com' }, /https/],
    ['a user in the upstream', { ...ROUTE, upstream: 'https://me:pw@api.openai.com' }, /no user/],
    ['localhost', { ...ROUTE, upstream: 'https://localhost:8443' }, /private/],
    ['the metadata service', { ...ROUTE, upstream: 'https://169.254.169.254/latest' }, /private/],
    ['a private address', { ...ROUTE, upstream: 'https://10.0.1.5' }, /private/],
    ['IPv4 written as IPv6', { ...ROUTE, upstream: 'https://[::ffff:a00:105]' }, /private/],
    ['a single-label name', { ...ROUTE, upstream: 'https://intranet' }, /single-label/],
    ['a rule with no key', { ...ROUTE, inject: [{ kind: 'header', name: 'x-api', template: 'static' }] }, /names no key/],
    ['no rule at all', { ...ROUTE, inject: [] }, /list of 1 to 8/],
    ['one header twice, in two cases', { ...ROUTE, inject: [{ kind: 'header', name: 'X-Key', template: '{A}' }, { kind: 'header', name: 'x-key', template: '{B}' }] }, /set twice/],
    ['a parameter twice, in two cases', { ...ROUTE, inject: [{ kind: 'query', name: 'secret', template: '{A}' }, { kind: 'query', name: 'SECRET', template: '{B}' }] }, /set twice/],
    ['a field twice, as a parser reads it', { ...ROUTE, inject: [{ kind: 'json', name: 'refresh_token', template: '{A}' }, { kind: 'json', name: 'refresh.token', template: '{B}' }] }, /set twice/],
    ['a field name with a space', { ...ROUTE, inject: [{ kind: 'json', name: 'secret token', template: '{A}' }] }, /field's name/],
    ['a parameter name with a space', { ...ROUTE, inject: [{ kind: 'query', name: 'api key', template: '{A}' }] }, /parameter's name/],
    ['a form beside JSON', { ...ROUTE, inject: [{ kind: 'form', name: 'a', template: '{A}' }, { kind: 'json', name: 'b', template: '{B}' }] }, /never both/],
    ['basic beside authorization', { ...ROUTE, inject: [{ kind: 'basic', user: '{A}', password: '' }, { kind: 'header', name: 'authorization', template: '{B}' }] }, /authorization/],
    ['sigv4 not last', { ...ROUTE, inject: [{ kind: 'sigv4', accessKeyId: '{A}', secretAccessKey: '{B}', sessionToken: null, region: 'eu-west-3', service: 's3' }, { kind: 'header', name: 'x-t', template: '{C}' }] }, /goes last/],
    ['an x-amz- header beside sigv4', { ...ROUTE, inject: [{ kind: 'header', name: 'x-amz-date', template: '{C}' }, { kind: 'sigv4', accessKeyId: '{A}', secretAccessKey: '{B}', sessionToken: null, region: 'eu-west-3', service: 's3' }] }, /x-amz-/],
    ['a partial glob', { ...ROUTE, allow: [{ methods: [], path: '/doc*' }] }, /whole segments/],
    ['** before the end', { ...ROUTE, allow: [{ methods: [], path: '/a/**/b' }] }, /last only/],
    ['a dot segment', { ...ROUTE, allow: [{ methods: [], path: '/a/../b' }] }, /dot segment/],
    ['an encoded dot segment', { ...ROUTE, allow: [{ methods: [], path: '/a/%2e%2e/b' }] }, /dot segment/],
    ['an encoded slash', { ...ROUTE, allow: [{ methods: [], path: '/a%2fb' }] }, /slash/],
    ['an empty segment', { ...ROUTE, allow: [{ methods: [], path: '/a//b' }] }, /is empty/],
    ['a trailing slash', { ...ROUTE, allow: [{ methods: [], path: '/companies/' }] }, /\/companies\/\*\*/],
    // What the proxy's matcher refuses, as a server behind may read it as another path (readPattern, section 7).
    ['a segment encoded twice', { ...ROUTE, allow: [{ methods: [], path: '/tenants/%2561/*' }] }, /decodes twice/],
    ['a ; parameter', { ...ROUTE, allow: [{ methods: [], path: '/a;v1/*' }] }, /Tomcat/],
    ['a trailing dot', { ...ROUTE, allow: [{ methods: [], path: '/a./*' }] }, /Windows/],
    ['one path twice, encoded and not', { ...ROUTE, allow: [{ methods: ['GET'], path: '/a' }, { methods: ['GET'], path: '/%61' }] }, /each allow entry once/],
    ['a method off the list', { ...ROUTE, allow: [{ methods: ['TRACE'], path: '/a' }] }, /methods are from/],
    ['an entry twice', { ...ROUTE, allow: [{ methods: ['GET'], path: '/a' }, { methods: ['GET'], path: '/a' }] }, /each allow entry once/],
    ['a limit of 0', { ...ROUTE, limit: { perMinute: 0 } }, /at least 1/],
    ['a placeholder with no rule to shape', { ...ROUTE, inject: [{ kind: 'basic', user: '{A}', password: '{B}' }], placeholder: { kind: 'prefix', prefix: 'sk_' } }, /placeholder shapes/],
    ['a tunnel to a private host', { kind: 'tunnel', name: 'db', key: 'DB_URL', hosts: ['10.0.1.5'], network: null }, /private/],
    ['a key name with a dash', { kind: 'signer', name: 's', signer: { kind: 'private-key', key: 'MY-KEY' } }, /names a key/],
  ];
  for (const [what, value, reason] of cases) assert.match(proxyDefinitionProblem(value) ?? 'accepted', reason, what);
});

test('insecureUpstreams lets a local fake in; a network code declares lets a tunnel reach its private hosts', () => {
  assert.equal(proxyDefinitionProblem({ ...ROUTE, upstream: 'http://127.0.0.1:8080' }, { insecureUpstreams: true }), null);
  assert.equal(proxyDefinitionProblem({ kind: 'tunnel', name: 'db', key: 'DB_URL', hosts: ['10.0.1.5'], network: 'replica' }), null);
  assert.equal(privateHost('db.acme.example'), false);
  assert.equal(privateHost('[fe80::1]'), true);
});

test('a definition decodes its path segments once: a pattern takes what an encoded path names, never what decodes twice', () => {
  assert.equal(proxyDefinitionProblem({ ...ROUTE, allow: [{ methods: [], path: '/companies/a%20b' }] }), null);
  assert.equal(proxyDefinitionProblem({ ...ROUTE, allow: [{ methods: [], path: '/companies/*/documents/**' }] }), null);
  assert.equal(proxyDefinitionProblem({ ...ROUTE, allow: [{ methods: [], path: '/' }] }), null);
});

test('no allow list takes every request, an empty one none: each kept as written, as the proxy reads them (section 7)', () => {
  const allow = (value: unknown) => (canonicalDefinition({ ...ROUTE, allow: value }) as Extract<ProxyDefinition, { kind: 'route' }>).allow;
  assert.equal(allow(undefined), null);
  assert.equal(allow(null), null);
  assert.deepEqual(allow([]), []);
  assert.notDeepEqual(canonicalDefinition({ ...ROUTE, allow: undefined }), canonicalDefinition({ ...ROUTE, allow: [] }));
});

test('the version gate: each method one call on this release, and an answer on another, or none, refused before any handler sees it', async () => {
  const asked: unknown[] = [];
  let answering = RELEASE;
  const entry: VaultEntry = {
    call: async (release, method, args) => {
      asked.push({ release, method, args });
      return answering === '' ? (undefined as never) : { release: answering, result: method === 'access' ? { principal: args[0] } : null };
    },
  };
  const vault = versioned(entry);
  assert.equal(versioned(entry), vault, 'the same vault for the same entry: the app keeps one per isolate, whatever a request makes');
  assert.deepEqual(Object.keys(vault).sort(), [...VAULT_METHODS].sort());
  assert.deepEqual(await vault.access('user:ada@acme.example'), { principal: 'user:ada@acme.example' });
  assert.deepEqual(asked, [{ release: RELEASE, method: 'access', args: ['user:ada@acme.example'] }]);
  answering = '9.9.9';
  await assert.rejects(vault.about(), (error: Error & { code?: string }) => error.code === 'deploying' && /release 9\.9\.9/.test(error.message));
  answering = '';
  await assert.rejects(vault.settings(), (error: Error & { code?: string }) => error.code === 'deploying');
  // Another release asked of the same entry: a vault of its own, which names it.
  answering = '9.9.9';
  assert.equal(await versioned(entry, '9.9.9').checkpoint(), null);
});
