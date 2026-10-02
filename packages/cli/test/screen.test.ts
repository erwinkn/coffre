import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';

import type { Clipboard } from '../src/clipboard.ts';
import { initialState, render, type Screen, showSecrets } from '../src/secrets.ts';
import { style, width } from '../src/tty.ts';

const KEY = 'K'.repeat(43) + '=';
const URL = 'postgresql://coffre_runtime:s3cret-password@db.example.com:5432/coffre?sslmode=verify-full';

const screen: Screen = {
  title: 'coffre setup',
  sections: [
    {
      title: 'App',
      values: [
        { label: 'App key', value: KEY, mask: 'all', about: "Signs the app's sessions." },
        { label: 'App database URL', value: URL, mask: 'password', about: "The app's own login." },
      ],
    },
    { title: 'Vault', values: [{ label: 'Vault ID', value: 'vault-2026-10-02-abcdef', mask: 'none', about: 'Names the vault key.' }] },
  ],
  guide: [
    {
      title: 'On Cloudflare Workers',
      lines: ['A Hyperdrive config:', { command: `wrangler hyperdrive create coffre --connection-string='${URL}'`, secret: true }],
    },
  ],
};

const plain = style(new PassThrough());

test('values are masked until revealed, one or all; a URL hides only its password, and an ID is never hidden', () => {
  const state = initialState();
  const text = () => render(screen, state, 120, 40, plain).join('\n');
  assert.ok(!text().includes(KEY));
  assert.ok(!text().includes('s3cret-password'));
  assert.match(text(), /postgresql:\/\/coffre_runtime:•+@db\.example\.com:5432\/coffre\?sslmode=verify-full/);
  assert.match(text(), /vault-2026-10-02-abcdef/);
  state.revealed.add('App key');
  assert.ok(text().includes(KEY) && !text().includes('s3cret-password'));
  state.revealAll = true;
  assert.ok(text().includes(URL));
});

test('on a small terminal the screen scrolls to keep the selection in sight, and no line overflows', () => {
  const state = initialState();
  state.selected.values = 2;
  const lines = render(screen, state, 50, 16, plain);
  assert.equal(lines.length, 16);
  for (const line of lines) assert.ok(width(line) <= 50, line);
  assert.match(lines.join('\n'), /Vault ID/);
  assert.match(lines.join('\n'), /↑ more/);
  assert.match(lines.join('\n'), /q done/, 'how to leave, on a line of its own if need be');
  state.confirming = true;
  assert.match(render(screen, state, 50, 16, plain).join('\n'), /Have you saved all three values\?[\s\S]*\(y\/N\)/);
});

test('the guide shows commands to copy, the password in them hidden too', () => {
  const state = initialState();
  state.view = 'guide';
  const text = render(screen, state, 200, 30, plain).join('\n');
  assert.match(text, /Where these go/);
  assert.match(text, /\$ wrangler hyperdrive create coffre --connection-string='postgresql:\/\/coffre_runtime:•+@/);
  assert.ok(!text.includes('s3cret-password'));
});

/** A terminal in memory: keys in, what is drawn out. */
function fakeTerminal() {
  const keys = Object.assign(new PassThrough(), { isTTY: true, setRawMode: () => {} });
  let drawn = '';
  const out = Object.assign(
    new Writable({
      write(chunk, _encoding, done) {
        drawn += String(chunk);
        done();
      },
    }),
    { isTTY: true, columns: 100, rows: 30 },
  );
  return { terminal: { keys, out }, drawn: () => drawn };
}

test('the keys: move, copy, the guide, and leaving only once the values are said to be saved', async () => {
  const { terminal, drawn } = fakeTerminal();
  const copies: string[] = [];
  const clipboard = { copy: async (text: string) => (copies.push(text), 'system'), settle: async () => {} } as unknown as Clipboard;
  const shown = showSecrets(terminal, screen, clipboard);
  const press = async (...keys: string[]) => {
    for (const key of keys) {
      terminal.keys.write(key);
      await new Promise((resolve) => setImmediate(resolve));
    }
  };
  await press('\x1b[B', 'c', '\t', 'c', 'w', '\r', 'w');
  assert.deepEqual(copies, [URL, 'vault-2026-10-02-abcdef', `wrangler hyperdrive create coffre --connection-string='${URL}'`]);
  assert.match(drawn(), /Copied the command/);
  await press('q');
  assert.match(drawn(), /Have you saved all three values\? They won't be shown again/);
  await press('n', 'q', 'y');
  await shown;
  assert.ok(drawn().startsWith('\x1b[?1049h'), 'the alternate screen first');
  assert.ok(drawn().endsWith('\x1b[?1049l'), 'and left last');
  assert.ok(!drawn().includes(KEY), 'never revealed, never drawn');
});
