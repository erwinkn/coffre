// A matrix whose cell fails ends its file: its batch's other cells settle, every pool they opened is ended, and
// the process exits by itself, failed, rather than a cell refused a connection (53300) leaving its row's others running,
// their pools open past the failure, and the file's process idle until its 2-hour timeout.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** How long the batch may take to fail and its process to exit: its world made, its cells' connections opened, a second's sleep. */
const PROMPTLY_MS = 60_000;

test('a matrix cell that fails ends its file: the others settle, their pools end, and the process exits', async () => {
  const started = Date.now();
  // Run as a file of its own, not under this runner: its test's failure is its process's to report.
  const { NODE_TEST_CONTEXT: _, ...env } = process.env;
  const child = spawn(process.execPath, ['--conditions=coffre:source', fileURLToPath(new URL('failing-cells.ts', import.meta.url))], { stdio: ['ignore', 'pipe', 'pipe'], env });
  let output = '';
  child.stdout.on('data', (chunk: Buffer) => (output += chunk));
  child.stderr.on('data', (chunk: Buffer) => (output += chunk));
  const ended = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.once('exit', (code, signal) => resolve({ code, signal })));
  const late = setTimeout(() => child.kill('SIGKILL'), PROMPTLY_MS);
  const { code, signal } = await ended;
  clearTimeout(late);
  // Killed, it never exited: a pool, or a cell, was left open.
  assert.equal(signal, null, `the file did not exit within ${PROMPTLY_MS} ms of starting: a pool left open\n${output}`);
  assert.equal(code, 1, output);
  assert.match(output, /a cell failed/);
  assert.ok(Date.now() - started < PROMPTLY_MS);
});
