import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { chmodSync, mkdtempSync, mkdirSync, writeFileSync, statSync, rmSync, readFileSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const token = `coffre_cli_${'a'.repeat(43)}`;

for (const linked of [false, true]) {
  test(`login ${linked ? 'refuses a linked credentials file' : 'tightens existing credentials and directory permissions'}`, async (t) => {
    const home = mkdtempSync(join(tmpdir(), 'coffre-login-'));
    t.after(() => rmSync(home, { recursive: true, force: true }));
    const directory = join(home, '.coffre');
    const file = join(directory, 'credentials.json');
    const contents = '{"version":2,"current":null,"instances":{}}';
    mkdirSync(directory);
    chmodSync(directory, 0o755);
    if (linked) {
      writeFileSync(join(home, 'linked.json'), contents);
      symlinkSync(join(home, 'linked.json'), file);
    } else {
      writeFileSync(file, contents);
      chmodSync(file, 0o644);
    }
    const server = createServer((req, res) => {
      const body = req.url === '/api/auth' ? { signin: { providers: [] }, access: null }
        : req.url === '/api/auth/device' ? {
          device_code: 'device', user_code: 'BCDF-GHJK', verification_uri_complete: 'http://127.0.0.1/approve',
          interval: 1, expires_in: 60,
        }
        : req.url === '/api/auth/device/token' ? { access_token: token, expires_at: '2099-01-01T00:00:00Z' }
        : { principal: { type: 'user', id: 'admin@acme.example' }, registered: true, environments: [] };
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); }));
    const address = server.address();
    assert.ok(address !== null && typeof address !== 'string');
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COFFRE_')));
    const login = promisify(execFile)(process.execPath, [
      '--conditions=coffre:source', main, 'login', `http://127.0.0.1:${address.port}`, '--no-browser',
    ], { env: { ...env, HOME: home } });
    if (linked) {
      await assert.rejects(login, (error: Error & { stderr?: string }) => {
        assert.match(error.stderr ?? '', /cannot secure credentials.*symbolic link/);
        return true;
      });
      assert.equal(readFileSync(join(home, 'linked.json'), 'utf8'), contents);
    } else {
      await login;
      assert.equal(JSON.parse(readFileSync(file, 'utf8')).instances[`http://127.0.0.1:${address.port}`].token, token);
      assert.equal(statSync(file).mode & 0o777, 0o600);
      assert.equal(statSync(directory).mode & 0o777, 0o700);
    }
  });
}
