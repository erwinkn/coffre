// What the packed @coffre/client must do on every Node it declares
// (`engines`): load, from `import` and from `require`, and make calls. Run by
// scripts/consumer-test.sh, with each Node in turn, from a directory where the
// client's tarball is unpacked under node_modules, nothing else installed:
//
//   node client-smoke.cjs
//
// It is CommonJS to try `require` as a CommonJS app (Equisafe's backend) does.
// `require` of an ES module is on by default from Node 20.19 and 22.12;
// before, the client loads through `import` alone and `require` must say so.
'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');

const mustRequire = process.features.require_module === true;

async function main() {
  const seen = [];
  const server = http.createServer((request, response) => {
    seen.push(`${request.method} ${request.url} ${request.headers['x-test'] ?? ''}`.trim());
    const denied = request.url === '/api/me' && request.headers['x-test'] !== 'yes';
    response.writeHead(denied ? 403 : 200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(denied ? { error: 'forbidden', message: 'nope', reason: 'no_grant' } : { providers: ['github'], email: 'me@acme.example' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;

  try {
    const imported = await import('@coffre/client');
    const modules = [['import', imported]];
    if (mustRequire) {
      modules.push(['require', require('@coffre/client')]);
    } else {
      assert.throws(() => require('@coffre/client'), { code: 'ERR_REQUIRE_ESM' });
    }

    for (const [how, { createClient, CoffreError }] of modules) {
      assert.equal(typeof createClient, 'function', how);
      const client = createClient({ url, headers: () => ({ 'x-test': 'yes' }) });
      assert.deepEqual(await client.auth(), { providers: ['github'], email: 'me@acme.example' }, how);
      assert.equal((await client.me()).email, 'me@acme.example', how);

      // A refusal is a CoffreError carrying the API's own words.
      const denied = createClient({ url });
      await assert.rejects(denied.me(), (error) => error instanceof CoffreError && error.status === 403 && error.reason === 'no_grant', how);
    }

    // The other entries load too, and a call through the credential entry.
    const routes = await import('@coffre/client/routes');
    assert.equal(typeof routes, 'object');
    const { credential } = await import('@coffre/client/credential');
    const proxied = credential('api', { COFFRE_CREDENTIALS: JSON.stringify({ api: `${url}proxy/api` }), COFFRE_HANDLE: 'h' });
    assert.equal((await (await proxied.fetch('/auth', { headers: { 'x-test': 'yes' } })).json()).email, 'me@acme.example');

    // A workload's proof, with WebCrypto alone: a key that never exports, and a signature its own public key checks.
    const dpop = await import('@coffre/client/dpop');
    const key = await dpop.generateProofKey();
    await assert.rejects(crypto.subtle.exportKey('jwk', key.privateKey));
    const proof = await dpop.createProof(key, { method: 'POST', url: `${url}use/api/x?y=1`, token: 'coffre_wl_x', content: { headers: { 'content-type': 'text/plain' }, body: await dpop.bodyDigest('hi') } });
    const [head, payload, signature] = proof.split('.');
    const publicKey = await crypto.subtle.importKey('jwk', key.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, dpop.fromBase64url(signature), new TextEncoder().encode(`${head}.${payload}`)));
    assert.equal((await dpop.thumbprint(key.jwk)).length, 43);

    assert.ok(seen.includes('GET /api/auth yes'), seen.join('\n'));
  } finally {
    server.close();
  }
  console.log(`  node ${process.versions.node}: import${mustRequire ? ' and require' : ' (require refused, as before 20.19/22.12)'} ok`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
