import test from 'node:test';
import assert from 'node:assert/strict';

import { Clipboard, systemTool } from '../src/clipboard.ts';

test('the clipboard tool by platform and display, and none where there is no display', () => {
  assert.deepEqual(systemTool('darwin', {})?.copy, ['pbcopy']);
  assert.deepEqual(systemTool('linux', { WAYLAND_DISPLAY: 'wayland-0' })?.clear, ['wl-copy', '--clear']);
  assert.deepEqual(systemTool('linux', { DISPLAY: ':0' })?.paste, ['xclip', '-selection', 'clipboard', '-o']);
  assert.deepEqual(systemTool('linux', { WSL_DISTRO_NAME: 'Ubuntu' })?.copy, ['clip.exe']);
  assert.equal(systemTool('linux', {}), null);
});

test('a tool that exits without reading what it is given is no crash: its exit code decides', async () => {
  // As wl-copy --clear does. A megabyte fills the pipe, so the write fails every time.
  const board = new Clipboard(() => {}, () => {}, { copy: ['true'], clear: ['true'], paste: ['true'] });
  assert.equal(await board.copy('x'.repeat(1 << 20)), 'system');
  await board.settle();
});

test('without a system tool, the terminal copies, through OSC 52', async () => {
  const written: string[] = [];
  const board = new Clipboard((sequence) => written.push(sequence), () => {}, null);
  assert.equal(await board.copy('vault-2026-10-02-abcdef'), 'terminal');
  assert.deepEqual(written, [`\x1b]52;c;${Buffer.from('vault-2026-10-02-abcdef').toString('base64')}\x07`]);
});
