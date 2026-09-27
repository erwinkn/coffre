import assert from 'node:assert/strict';

const [baseUrl, expectedRuntime] = process.argv.slice(2);
if (!baseUrl || !expectedRuntime) {
  throw new Error('usage: node verify.mjs <base-url> <worker|node>');
}

const api = await fetch(`${baseUrl}/api/spike`);
assert.equal(api.status, 200);
assert.deepEqual(await api.json(), {
  ok: true,
  owner: 'consumer',
  runtime: expectedRuntime,
});

const page = await fetch(`${baseUrl}/login`);
assert.equal(page.status, 200);
assert.match(page.headers.get('content-type') ?? '', /^text\/html/);
const html = await page.text();
assert.match(html, /<h1[^>]*>Sign in to coffre<\/h1>/);

const policy = page.headers.get('content-security-policy') ?? '';
const policyNonce = /'nonce-([^']+)'/.exec(policy)?.[1];
assert.ok(policyNonce, 'CSP contains a nonce');
assert.equal(
  page.headers.get('x-ssr-spike-request-nonce'),
  policyNonce,
  'consumer request context nonce reached the CSP header',
);

const scriptTags = [...html.matchAll(/<script\b[^>]*>/g)].map(([tag]) => tag);
assert.ok(scriptTags.length > 0, 'SSR emitted scripts');
for (const tag of scriptTags) {
  assert.ok(
    tag.includes(`nonce="${policyNonce}"`) || tag.includes(`nonce='${policyNonce}'`),
    `script has the request context nonce: ${tag}`,
  );
}

const assetUrls = new Set(
  [...html.matchAll(/(?:src|href)=["'](\/assets\/[^"']+)["']/g)].map((match) => match[1]),
);
assert.ok(assetUrls.size >= 2, 'SSR emitted client asset URLs');

for (const assetUrl of assetUrls) {
  const asset = await fetch(`${baseUrl}${assetUrl}`);
  assert.equal(asset.status, 200, assetUrl);
  if (assetUrl.endsWith('.css')) {
    const css = await asset.text();
    const fontUrls = [...css.matchAll(/url\(([^)]+\.woff2)\)/g)].map((match) => match[1]);
    assert.ok(fontUrls.length > 0, 'CSS references packaged fonts');
    for (const fontUrl of fontUrls) {
      const font = await fetch(new URL(fontUrl, `${baseUrl}${assetUrl}`));
      assert.equal(font.status, 200, font.url);
    }
  }
}

console.log(
  JSON.stringify({
    runtime: expectedRuntime,
    apiOwner: 'consumer',
    scriptsWithMatchingNonce: scriptTags.length,
    assetsChecked: assetUrls.size,
  }),
);
