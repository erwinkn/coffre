import { build } from 'esbuild';
import { readdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
const files = (await readdir('tests', { recursive: true })).filter(f => f.endsWith('.test.ts') && (!process.argv[2] || f.startsWith(process.argv[2]))).map(f => `tests/${f}`);
await build({ entryPoints: files, outdir: '.test-build', outbase: '.', bundle: true, packages: 'external', platform: 'node', format: 'esm', target: 'node22', sourcemap: true });
const child = spawn(process.execPath, ['--test', ...files.map(f => `.test-build/${f.replace(/\.ts$/, '.js')}`)], { stdio: 'inherit', env: process.env });
child.on('exit', code => { process.exitCode = code ?? 1; });
