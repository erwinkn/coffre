// A presigned URL's path is held to the same rule as a request's through its credential, `climbs`: a segment a server
// reads as a dot segment (`..;x`, `..%20`, `..%00`), or one decoded twice (`%252e%252e`), never takes it out of the
// credential's `paths`. Through the plugin's route with a fake coffre: no database, refused before anything opens.
import assert from 'node:assert/strict';
import test from 'node:test';

import type { PluginContext, UseAsked } from '../src/plugins.ts';
import { credentialProxy, sigv4 } from '../src/plugins/credential-proxy.ts';

const PUBLIC = 'https://coffre.example';
const HANDLE = `coffre_use_${'h'.repeat(43)}`;
const LATER = new Date(Date.now() + 3_600_000).toISOString();

const opened: string[] = [];
const plugin = credentialProxy({
  cacheSeconds: 0,
  credentials: { s3: { upstream: 'https://bucket.s3.example', paths: ['/public'], inject: sigv4({ accessKeyId: '{AK}', secretAccessKey: '{SK}', region: 'eu-west-1', service: 's3' }) } },
});
const coffre = {
  publicUrl: PUBLIC,
  workload: async () => null,
  handle: async () => ({ expiresAt: LATER, paths: ['market/dev'] }),
  use: async (_handle: unknown, asked: UseAsked) => {
    opened.push(...asked.keys);
    return { values: { AK: 'AKIAEXAMPLE', SK: 'secretkey' }, plain: [], expiresAt: LATER, environment: { path: 'market/dev', personal: false }, workload: null };
  },
} as unknown as PluginContext;

async function presign(path: string): Promise<{ status: number; body: string }> {
  const request = new Request(`${PUBLIC}/use/market/dev`, { method: 'POST', headers: { authorization: `Bearer ${HANDLE}`, 'content-type': 'application/json' }, body: JSON.stringify({ presign: { credential: 's3', path } }) });
  const answer = await plugin.routes!.fetch(request, coffre);
  return { status: answer.status, body: await answer.text() };
}

test("a presigned URL's path that climbs, as a request's would, is refused before anything opens", async () => {
  for (const path of ['/public/../private/x', '/public/..;x/private/x', '/public/..%20/private/x', '/public/%252e%252e/private/x', '/public/..%00/private/x', '/public/a%2fb', '/public/%c0%ae%c0%ae/x']) {
    const answer = await presign(path);
    assert.equal(answer.status, 400, `${path}: ${answer.body}`);
    assert.match(answer.body, /the path may not climb out of the credential's upstream/);
  }
  assert.equal((await presign('/private/x')).status, 403);
  assert.deepEqual(opened, []);
  const made = await presign('/public/report.pdf');
  assert.equal(made.status, 200, made.body);
  assert.match((JSON.parse(made.body) as { url: string }).url, /^https:\/\/bucket\.s3\.example\/public\/report\.pdf\?/);
});
