// The CLI's image, held to what it promises (scripts/test-image.sh builds
// it): `coffre` as its entrypoint, at the version it was built from; a user
// that is not root and cannot change the CLI; and `coffre serve`, on a
// read-only root and with no capabilities, signed in with an enrollment
// code from stdin, forwarding what the app sends its port to the fake
// coffre (test/workload-fake.ts), signed, and logging out when the
// container is stopped. The container shares the host's network, as a
// sidecar shares its pod's, and the fake listens on its loopback.
//
//   node --conditions=coffre:source packages/cli/scripts/image-smoke.ts <image> <version>
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';

import { fakeCoffre } from '../test/workload-fake.ts';

const [image, version] = process.argv.slice(2);
if (!image || !version) throw new Error('usage: image-smoke.ts <image> <version>');
const docker = (...args: string[]) => execFileSync('docker', args, { encoding: 'utf8' }).trim();

const config = JSON.parse(docker('image', 'inspect', image, '--format', '{{json .Config}}')) as { User: string; Entrypoint: string[] };
assert.deepEqual(config.Entrypoint, ['coffre']);
assert.equal(config.User, '65532:65532');
assert.equal(docker('run', '--rm', image, '--version'), version);
// The CLI's files are root's, and its user may not write them.
const main = '/usr/local/lib/node_modules/@coffre/cli/dist/main.js';
const probe = `const fs = require('node:fs'); let writable = true; try { fs.accessSync('${main}', fs.constants.W_OK) } catch { writable = false } console.log(process.getuid(), fs.statSync('${main}').uid, writable)`;
assert.equal(docker('run', '--rm', '--entrypoint', '/nodejs/bin/node', image, '-e', probe), '65532 0 false');
console.log(`${image}: coffre ${version}, as uid 65532, which cannot change it`);

const coffre = await fakeCoffre();
const name = `coffre-image-smoke-${randomBytes(4).toString('hex')}`;
const flags = ['--rm', '-i', '--name', name, '--network', 'host', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges'];
const serve = spawn('docker', ['run', ...flags, image, 'serve', '--url', coffre.url, '--service', 'api-prod', '--proof', 'enrollment', '--listen', '127.0.0.1:0'], { stdio: ['pipe', 'inherit', 'pipe'] });
const exited = once(serve, 'exit');
try {
  serve.stdin.end(`coffre_enr_${'k'.repeat(43)}`);
  let said = '';
  serve.stderr.setEncoding('utf8').on('data', (data: string) => (said += data));
  let listener: string | undefined;
  for (let i = 0; i < 600 && listener === undefined && serve.exitCode === null; i++) {
    listener = /(http:\/\/127\.0\.0\.1:\d+)\/use\/<credential>/.exec(said)?.[1];
    if (listener === undefined) await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.ok(listener, `coffre serve never listened: ${said}`);

  const response = await fetch(`${listener}/use/openai/models`, { headers: { authorization: 'Bearer coffre', accept: 'application/json' } });
  assert.equal(response.status, 200, await response.text());
  const sent = coffre.forwarded.at(-1);
  assert.equal(sent?.path, '/use/openai/models');
  assert.equal(sent.headers.authorization, undefined);

  docker('stop', name);
  const [code] = await exited;
  assert.equal(code, 0, said);
  assert.equal(coffre.log.at(-1), 'POST /api/auth/logout 200');
  console.log(`${image}: coffre serve forwarded a request signed, and logged out when stopped`);
} finally {
  if (serve.exitCode === null) execFileSync('docker', ['rm', '-f', name], { stdio: 'ignore' });
  await coffre.close();
}
