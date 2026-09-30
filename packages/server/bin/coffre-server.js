#!/usr/bin/env node
// `coffre-server`, as pnpm links it. A committed file rather than dist/bin.js
// itself, so that a fresh checkout links the command at install, before
// `pnpm build` has written dist/, instead of skipping it until the next install.
import { existsSync } from 'node:fs';

const bin = new URL('../dist/bin.js', import.meta.url);
if (!existsSync(bin)) {
  console.error('coffre-server: @coffre/server is not built; run `pnpm build` at the root of the coffre repository');
  process.exit(1);
}
await import(bin.href);
