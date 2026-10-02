import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateKeys, vaultKeyId } from '../src/keys.ts';
import { inTerminal, ptySkip, screens, visible } from './pty.ts';

const main = fileURLToPath(new URL('../src/main.ts', import.meta.url));
const NAMES = ['APP_KEY', 'VAULT_KEY_ID', 'VAULT_KEY'];
const VAULT_ID = /^vault-\d{4}-\d{2}-\d{2}-[a-z2-7]{6}$/;

/** `coffre keys` with no terminal: pipes all round, in an empty directory with no home. */
function coffreKeys(args: string[] = []) {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-keys-'));
  try {
    const result = spawnSync(process.execPath, ['--conditions=coffre:source', main, 'keys', ...args], {
      cwd: dir,
      env: { PATH: process.env.PATH, HOME: dir },
      encoding: 'utf8',
    });
    assert.deepEqual(readdirSync(dir), [], 'it writes no file');
    return result;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** What the vault and the server accept: 32 bytes, base64, and an id the vault takes. */
function assertUsable(keys: Record<string, string>): void {
  assert.deepEqual(Object.keys(keys), NAMES);
  assert.match(keys.VAULT_KEY_ID!, VAULT_ID);
  assert.match(keys.VAULT_KEY_ID!, /^[A-Za-z0-9._-]{1,64}$/, "the vault's rule for a key id");
  for (const name of ['APP_KEY', 'VAULT_KEY']) {
    const bytes = Buffer.from(keys[name]!, 'base64');
    assert.equal(bytes.length, 32, name);
    assert.equal(bytes.toString('base64'), keys[name], `${name} is canonical base64`);
  }
}

test('a vault ID is the day and six random characters, so that two made the same day differ', () => {
  assert.match(vaultKeyId(new Date('2026-10-02T12:00:00Z')), /^vault-2026-10-02-[a-z2-7]{6}$/);
  const ids = new Set(Array.from({ length: 200 }, () => vaultKeyId()));
  assert.equal(ids.size, 200);
  const keys = generateKeys();
  assertUsable({ ...keys });
  assert.notEqual(keys.APP_KEY, keys.VAULT_KEY);
});

test('coffre keys --json prints the keys for a script, with a warning on stderr that they are secret', () => {
  const run = coffreKeys(['--json']);
  assert.equal(run.status, 0, run.stderr);
  assertUsable(JSON.parse(run.stdout) as Record<string, string>);
  assert.match(run.stderr, /--json prints the app key and the vault key to stdout/);
});

test('coffre keys refuses to print its values without a terminal', () => {
  const run = coffreKeys();
  assert.equal(run.status, 1);
  assert.equal(run.stdout, '');
  assert.match(run.stderr, /coffre keys shows the values it makes on a screen of their own/);
  assert.match(run.stderr, /In a script, --json prints them to stdout instead/);
});

/** A clipboard tool that keeps what it was given, and how it was called: wl-copy and wl-paste, on a fake Wayland. */
function fakeClipboard() {
  const dir = mkdtempSync(join(tmpdir(), 'coffre-clipboard-'));
  const tool = (name: string, body: string) => {
    writeFileSync(join(dir, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(dir, name), 0o755);
  };
  tool('wl-copy', `printf '%s\\n' "$*" >> "${dir}/argv"\nif [ "$1" = --clear ]; then : > "${dir}/clipboard"; exit 0; fi\ncat > "${dir}/clipboard"`);
  tool('wl-paste', `cat "${dir}/clipboard"`);
  return {
    env: { PATH: `${dir}:${process.env.PATH}`, WAYLAND_DISPLAY: 'wayland-coffre-test', HOME: dir },
    clipboard: () => readFileSync(join(dir, 'clipboard'), 'utf8'),
    argv: () => readFileSync(join(dir, 'argv'), 'utf8'),
    remove: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test('on a terminal, the keys are shown on the alternate screen alone, and copy gives the value on stdin', { skip: ptySkip }, async () => {
  const fake = fakeClipboard();
  let copied = '';
  try {
    const { output, code } = await inTerminal(['keys'], fake.env, async (terminal) => {
      await terminal.waitFor('\x1b[?1049h');
      await terminal.waitFor('reveal all');
      terminal.send('c');
      await terminal.waitFor('Copied the app key');
      // Copied, not shown: the value went to the clipboard tool on its stdin, and never in its arguments.
      copied = fake.clipboard();
      assert.equal(Buffer.from(copied, 'base64').length, 32);
      assert.ok(!fake.argv().includes(copied));
      terminal.send('q');
      await terminal.waitFor('Have you saved all three values?');
      terminal.send('y');
      await terminal.waitFor('were shown once');
    });
    assert.equal(code, 0);
    assert.ok(!output.includes(copied), 'copied without ever being shown');
    const { main, alternate } = screens(output);
    assert.equal(output.split('\x1b[?1049h').length, 2, 'entered once');
    assert.equal(output.split('\x1b[?1049l').length, 2, 'left once');
    assert.match(visible(alternate), /App key/);
    assert.match(visible(main), /Vault ID\s+vault-\d{4}-\d{2}-\d{2}-[a-z2-7]{6}, not a secret/);
    assert.equal(fake.clipboard(), '', 'cleared on leaving, since it still held the key');
  } finally {
    fake.remove();
  }
});

test('revealed on the alternate screen, the keys never reach the main one', { skip: ptySkip }, async () => {
  const { output, code } = await inTerminal(['keys'], { PATH: process.env.PATH, HOME: tmpdir() }, async (terminal) => {
    await terminal.waitFor('reveal all');
    terminal.send('R');
    await terminal.waitFor('Vault key');
    // Ctrl-C asks, and a second leaves: never with a secret on the way out.
    terminal.send('\x03');
    await terminal.waitFor('Have you saved');
    terminal.send('\x03');
    await terminal.waitFor('were shown once');
  });
  assert.equal(code, 0);
  const { main, alternate } = screens(output);
  const shown = visible(alternate).match(/[A-Za-z0-9+/]{43}=/g) ?? [];
  assert.ok(new Set(shown).size >= 2, 'both keys revealed');
  for (const key of shown) assert.ok(!main.includes(key), 'a key on the main screen');
});
