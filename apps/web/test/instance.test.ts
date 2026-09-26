import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { instanceConfig, parseInstance, parseJsonc } from '../instance.ts';

const DEPLOY = resolve(import.meta.dirname, '../../../deploy');

test('JSONC drops comments and trailing commas, and leaves strings alone', () => {
  assert.deepEqual(
    parseJsonc(`// heading
      {
        /* block */ "url": "https://coffre.example.com//x", // trailing
        "quote": "a \\"/* not a comment */\\" b",
        "comma": "stays,}",
        "list": [1, 2,],
      }`),
    {
      url: 'https://coffre.example.com//x',
      quote: 'a "/* not a comment */" b',
      comma: 'stays,}',
      list: [1, 2],
    },
  );
  assert.throws(() => parseJsonc('{ /* open'), /unterminated/);
  assert.throws(() => parseJsonc('{ "a": 1,, }'), SyntaxError);
});

const signin = {
  name: 'coffre',
  routes: [{ pattern: 'coffre.example.com', custom_domain: true }],
  vars: {
    COFFRE_AUTH_MODE: 'signin',
    COFFRE_PUBLIC_URL: 'https://coffre.example.com',
    COFFRE_SIGNIN_PROVIDERS: 'github',
    COFFRE_SIGNIN_GITHUB_CLIENT_ID: 'Ov23li',
  },
  secrets: { required: ['COFFRE_SIGNIN_GITHUB_CLIENT_SECRET', 'COFFRE_KEK_LOCAL'] },
};

test('an instance names where coffre runs, and nothing about its code', () => {
  assert.deepEqual(parseInstance({ $schema: 'x', ...signin }), signin);
  assert.deepEqual(parseInstance({ name: 'equisafe-coffre' }), { name: 'equisafe-coffre' });

  assert.throws(() => parseInstance({ ...signin, main: 'evil.js' }), /"main" is not an instance setting/);
  assert.throws(
    () => parseInstance({ ...signin, hyperdrive: [] }),
    /"hyperdrive" is not an instance setting/,
  );
  assert.throws(() => parseInstance({ ...signin, name: 'Coffre_' }), /Worker name/);
  assert.throws(() => parseInstance({ routes: [] }), /Worker name/);
});

test('an instance that sets its vars sets its secrets too, and keeps secrets out of vars', () => {
  const { secrets: _secrets, ...varsOnly } = signin;
  assert.throws(() => parseInstance(varsOnly), /go together/);

  const withVars = (vars: Record<string, string>) =>
    parseInstance({ ...signin, vars: { ...signin.vars, ...vars } });
  assert.throws(() => withVars({ COFFRE_AUTH_MODE: 'dev' }), /"cloudflare" or "signin"/);
  assert.throws(() => withVars({ COFFRE_KEK_LOCAL: 'a2V5' }), /must be a secret/);
  assert.throws(() => withVars({ COFFRE_SIGNIN_GITHUB_CLIENT_SECRET: 's' }), /must be a secret/);
  assert.throws(() => withVars({ COFFRE_ROOT_ADMINS: ' ' }), /COFFRE_ROOT_ADMINS is empty/);
  assert.throws(
    () =>
      parseInstance({ ...signin, secrets: { required: ['COFFRE_SIGNIN_GITHUB_CLIENT_ID'] } }),
    /both a var and a secret/,
  );
});

test("the hook replaces coffre's routes, vars and secrets rather than adding to them", () => {
  assert.equal(instanceConfig({}), undefined);

  const hook = instanceConfig({ COFFRE_INSTANCE: 'deploy/equisafe.jsonc' });
  assert.ok(hook);
  const config: Record<string, unknown> = {
    name: 'coffre',
    topLevelName: 'coffre',
    main: 'src/worker.ts',
    vars: { COFFRE_AUTH_MODE: 'cloudflare' },
  };
  hook(config);
  assert.equal(config.name, 'equisafe-coffre');
  assert.equal(config.topLevelName, 'equisafe-coffre');
  assert.equal(config.main, 'src/worker.ts');
  assert.deepEqual(config.vars, { COFFRE_AUTH_MODE: 'cloudflare' });
  assert.deepEqual(config.routes, [{ pattern: 'coffre.equisafe.dev', custom_domain: true }]);

  assert.throws(
    () => instanceConfig({ COFFRE_INSTANCE: 'deploy/nowhere.jsonc' }),
    /COFFRE_INSTANCE .*nowhere\.jsonc: ENOENT/,
  );
});

test('the checked-in instances are valid, once their blanks are filled in', () => {
  const files = readdirSync(DEPLOY).filter((file) => file.endsWith('.jsonc'));
  assert.ok(files.includes('equisafe.jsonc'));
  for (const file of files) {
    const instance = parseJsonc(readFileSync(join(DEPLOY, file), 'utf8')) as {
      vars?: Record<string, string>;
    };
    for (const key of Object.keys(instance.vars ?? {})) {
      instance.vars![key] ||= 'to fill in';
    }
    assert.doesNotThrow(() => parseInstance(instance), file);
  }
});
