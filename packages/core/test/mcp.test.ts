import test from 'node:test';
import assert from 'node:assert/strict';

import { github, signin, type RateLimiter } from '@coffre/core/identity';
import {
  ClientInvalid,
  clientFromDocument,
  clientName,
  grantedScopes,
  isClientIdUrl,
  parseScopes,
  redirectHost,
  redirectKind,
  redirectMatches,
  registrationRedirects,
  scopeString,
} from '@coffre/core/mcp';

test('scopes: Browse always, in catalogue order, offline_access dropped, the unknown named', () => {
  assert.deepEqual(parseScopes(undefined), { scopes: ['browse'], unknown: [] });
  assert.deepEqual(parseScopes('manage-access  write offline_access'), { scopes: ['browse', 'write', 'manage-access'], unknown: [] });
  assert.deepEqual(parseScopes('browse admin'), { scopes: ['browse'], unknown: ['admin'] });
  assert.equal(scopeString(['read-values', 'browse']), 'browse read-values');
  assert.deepEqual(grantedScopes(['browse', 'write', 'read-values'], ['read-values', 'manage-access']), ['browse', 'read-values']);
  assert.deepEqual(grantedScopes(['browse', 'write'], []), ['browse'], 'Browse cannot be unticked');
});

test('redirects: HTTPS, or HTTP on loopback; never a custom scheme', () => {
  assert.equal(redirectKind('https://claude.ai/api/mcp/auth_callback'), 'https');
  for (const loopback of ['http://localhost/callback', 'http://127.0.0.1:33418/', 'http://[::1]:9/cb']) assert.equal(redirectKind(loopback), 'loopback');
  for (const refused of ['cursor://anysphere.cursor-mcp/oauth/callback', 'http://app.example/cb', 'https://u:p@app.example/cb', 'https://app.example/cb#x', 'not a url']) {
    assert.throws(() => redirectKind(refused), ClientInvalid, refused);
  }
  assert.equal(redirectHost('http://127.0.0.1:5/cb'), 'localhost');
  assert.equal(redirectHost('https://claude.ai/api/mcp/auth_callback'), 'claude.ai');
});

test('redirects match as parsed URLs; loopback on any port, everything else exactly', () => {
  assert.equal(redirectMatches('http://localhost/callback', 'http://localhost:3118/callback'), true, "Claude Code's ephemeral port");
  assert.equal(redirectMatches('http://127.0.0.1:33418/', 'http://127.0.0.1:33418'), true, "VS Code's, with and without the slash");
  assert.equal(redirectMatches('http://localhost/callback', 'http://127.0.0.1:3118/callback'), false, 'another host');
  assert.equal(redirectMatches('http://localhost/callback', 'http://localhost:3118/other'), false, 'another path');
  assert.equal(redirectMatches('https://claude.ai/api/mcp/auth_callback', 'https://claude.ai/api/mcp/auth_callback'), true);
  assert.equal(redirectMatches('https://claude.ai/api/mcp/auth_callback', 'https://claude.ai:8443/api/mcp/auth_callback'), false);
  assert.equal(redirectMatches('https://claude.ai/cb', 'https://claude.ai/cb?x=1'), false);
});

test("a client ID is a document's HTTPS URL with a path", () => {
  assert.equal(isClientIdUrl('https://claude.ai/oauth/claude-code-client-metadata', { allowLoopback: false }), true);
  for (const refused of ['https://claude.ai/', 'https://claude.ai', 'https://claude.ai/c?x=1', 'https://claude.ai/c#x', 'http://claude.ai/c', 'https://claude.ai/a/../c']) {
    assert.equal(isClientIdUrl(refused, { allowLoopback: false }), false, refused);
  }
  assert.equal(isClientIdUrl('http://127.0.0.1:8081/client.json', { allowLoopback: false }), false);
  assert.equal(isClientIdUrl('http://127.0.0.1:8081/client.json', { allowLoopback: true }), true);
});

test("a client's document names itself, a public client, and redirects on its own host", () => {
  const id = 'https://vscode.dev/oauth/client-metadata.json';
  const client = clientFromDocument(id, {
    client_id: id,
    client_name: 'Visual Studio Code',
    redirect_uris: ['https://vscode.dev/redirect', 'http://127.0.0.1:33418/'],
    token_endpoint_auth_method: 'none',
  });
  assert.deepEqual(client, { clientId: id, name: 'Visual Studio Code', host: 'vscode.dev', redirectUris: ['https://vscode.dev/redirect', 'http://127.0.0.1:33418/'], registration: 'cimd' });
  const refused = [
    { client_id: 'https://elsewhere.example/c.json', redirect_uris: ['https://vscode.dev/redirect'] },
    { client_id: id, redirect_uris: ['https://evil.example/cb'] },
    { client_id: id, redirect_uris: [] },
    { client_id: id, redirect_uris: ['cursor://x'] },
    { client_id: id, redirect_uris: ['https://vscode.dev/redirect'], token_endpoint_auth_method: 'private_key_jwt' },
    [id],
  ];
  for (const document of refused) assert.throws(() => clientFromDocument(id, document), ClientInvalid, JSON.stringify(document));
  assert.equal(clientName('  Cla‮ude\u0007 ', 'host'), 'Claude', 'no control or bidirectional characters');
  assert.equal(clientName(undefined, 'vscode.dev'), 'vscode.dev');
});

test('a registration keeps what coffre accepts and drops the rest, unless nothing is left', () => {
  assert.deepEqual(registrationRedirects(['http://localhost:8787/callback', 'cursor://anysphere.cursor-mcp/oauth/callback']), {
    kept: ['http://localhost:8787/callback'],
    dropped: ['cursor://anysphere.cursor-mcp/oauth/callback'],
  });
  assert.throws(() => registrationRedirects(['cursor://only']), ClientInvalid);
  assert.throws(() => registrationRedirects([]), ClientInvalid);
  assert.throws(() => registrationRedirects('https://a.example/cb'), ClientInvalid);
});

test('signin({ mcp }) needs its three limits, and loopback clients only on a loopback instance', () => {
  const limiter: RateLimiter = { limit: async () => ({ success: true }) };
  const limits = { perSource: limiter, perConnection: limiter, total: limiter };
  const providers = [github({ clientId: 'id', clientSecret: 'secret' })];
  const on = signin({ providers, mcp: { limits } }).resolve('https://secrets.acme.example');
  assert.equal(on.mode === 'signin' && on.signin.mcp?.allowLoopback, false);
  const none = signin({ providers }).resolve('https://secrets.acme.example');
  assert.equal(none.mode === 'signin' && none.signin.mcp, null);
  assert.throws(() => signin({ providers, mcp: { limits: { perSource: limiter, total: limiter } as never } }), /mcp needs its limits/);
  assert.throws(
    () => signin({ providers, mcp: { limits, allowLoopbackClientsForDevelopment: true } }).resolve('https://secrets.acme.example'),
    /allowLoopbackClientsForDevelopment is for an instance on loopback/,
  );
  const local = signin({ providers, mcp: { limits, allowLoopbackClientsForDevelopment: true } }).resolve('http://127.0.0.1:3000');
  assert.equal(local.mode === 'signin' && local.signin.mcp?.allowLoopback, true);
});
