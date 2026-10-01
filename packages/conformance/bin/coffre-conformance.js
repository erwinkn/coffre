#!/usr/bin/env node
// `coffre-conformance`, as pnpm links it. A committed file rather than
// dist/main.js itself, so that a fresh checkout links the command at install,
// before `pnpm build` has written dist/, instead of skipping it until the next
// install.
import { existsSync } from 'node:fs';

const main = new URL('../dist/main.js', import.meta.url);
if (!existsSync(main)) {
  console.error('coffre-conformance: @coffre/conformance is not built; run `pnpm build` at the root of the coffre repository');
  process.exit(1);
}
await import(main.href);
