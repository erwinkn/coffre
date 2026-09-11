import { build } from 'esbuild';
import { mkdir } from 'node:fs/promises';
await mkdir('.local', { recursive: true, mode: 0o700 });
await build({ entryPoints: ['scripts/local-setup.ts'], outfile: '.local/setup.js', bundle: true, packages: 'external', platform: 'node', format: 'esm', target: 'node22' });
await import('../.local/setup.js');
