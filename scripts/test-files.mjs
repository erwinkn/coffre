#!/usr/bin/env node
// The test files the suite runs (scripts/test-suite.sh), and the server's own
// `pnpm test`: every file its globs find, from the current directory, but
// those packages/server/tsconfig.json excludes, 0.14's files that do not build
// on 0.16 yet. A file the list names that no longer exists is an error, so the
// list cannot outlive what it lists, and so is finding no file. Its callers
// stop on its failure.
//
//   node scripts/test-files.mjs <glob>...
import { existsSync, globSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const server = 'packages/server';

// tsconfig.json is JSON with comments, here each on a line of its own.
const config = readFileSync(join(root, server, 'tsconfig.json'), 'utf8').replace(/^\s*\/\/.*$/gm, '');
const { exclude = [] } = JSON.parse(config);
const gone = exclude.filter((path) => !existsSync(join(root, server, path)));
if (gone.length > 0) {
  console.error(`${server}/tsconfig.json excludes files that do not exist: ${gone.join(', ')}`);
  process.exit(1);
}

const excluded = new Set(exclude.map((path) => join(root, server, path)));
const found = process.argv.slice(2).flatMap((pattern) => globSync(pattern, { exclude: (path) => path.endsWith('node_modules') }));
const files = [...new Set(found)].filter((path) => !excluded.has(resolve(path))).sort();
// No file at all is an error too: node --test given none would discover every test, the excluded too.
if (files.length === 0) {
  console.error(`no test file matches ${process.argv.slice(2).join(' ')}`);
  process.exit(1);
}
console.log(files.join('\n'));
