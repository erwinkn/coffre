import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const END = fileURLToPath(new URL('../src/end.ts', import.meta.url));

/** What a process that prints `report` to stderr and then ends with `message` writes to its pipes, and its exit code. */
async function ending(report: number, code: number, message: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const script = `import { end } from ${JSON.stringify(END)};
console.error('x'.repeat(${report}));
await end(${code}, ${JSON.stringify(message)});`;
  const child = spawn(process.execPath, ['--input-type=module', '--eval', script], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk: string) => (stderr += chunk));
  const exited = await new Promise<number | null>((done) => child.on('close', done));
  return { code: exited, stdout, stderr };
}

test('a run that ends after a report of megabytes writes all of it, then its summary, to a pipe', async () => {
  const report = 4 * 1024 * 1024;
  const ended = await ending(report, 1, 'NOT conformant: health');
  assert.equal(ended.code, 1);
  assert.equal(ended.stderr.length, report + '\nNOT conformant: health\n'.length);
  assert.ok(ended.stderr.endsWith('x\nNOT conformant: health\n'));
});

test('a conformant run says so on stdout and exits 0', async () => {
  const ended = await ending(0, 0, 'conformant');
  assert.deepEqual(ended, { code: 0, stdout: 'conformant\n', stderr: '\n' });
});
