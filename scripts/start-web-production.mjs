import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const webDirectory = resolve(repositoryRoot, 'apps/web');
const server = spawn(process.execPath, ['.output/server/index.mjs'], {
  cwd: webDirectory,
  env: process.env,
  stdio: ['inherit', 'pipe', 'pipe'],
});

let startupOutput = '';
let ready = false;
let forwardedSignal = null;

server.stdout.setEncoding('utf8');
server.stdout.on('data', (chunk) => {
  process.stdout.write(chunk);

  if (!ready) {
    startupOutput = `${startupOutput}${chunk}`.slice(-1024);
    ready = startupOutput.includes('Listening on:');
  }
});
server.stderr.pipe(process.stderr);

const forwardSignal = (signal) => {
  forwardedSignal = signal;
  server.kill(signal);
};
process.once('SIGINT', () => forwardSignal('SIGINT'));
process.once('SIGTERM', () => forwardSignal('SIGTERM'));

server.on('error', (error) => {
  console.error('Could not start the web production server:', error);
  process.exitCode = 1;
});

server.on('exit', (code, signal) => {
  if (forwardedSignal !== null) {
    process.exitCode = 0;
    return;
  }

  if (!ready && code === 0 && signal === null) {
    console.error('Web production server exited before confirming its listener.');
    process.exitCode = 1;
    return;
  }

  process.exitCode = code ?? 1;
});
