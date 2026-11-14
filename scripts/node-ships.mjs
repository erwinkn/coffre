#!/usr/bin/env node
// Whether this revision ships coffre on Node: whether `@coffre/server` exports
// `./node`. 0.16.0 ships for Workers only (D198; docs/design/0.16.md, "Node in
// 0.16.0"), so the checks that exercise only Node wait for that export, and the
// port to 0.16 turns them back on by restoring it, with no CI edit.
//
//   node scripts/node-ships.mjs [<what waits>]
//
// Prints `true` or `false`. With `false`, it says on stderr why <what waits>
// does not run, as a GitHub notice when it runs in GitHub Actions. Fails on
// anything else, so that a job keyed on it never skips by accident.
import { readFileSync } from 'node:fs';

const { exports } = JSON.parse(readFileSync(new URL('../packages/server/package.json', import.meta.url), 'utf8'));
if (exports === null || typeof exports !== 'object') throw new Error("@coffre/server's package.json has no exports map");
const ships = Object.hasOwn(exports, './node');
if (!ships) {
  const what = process.argv[2] ?? 'This Node check';
  const why = "not run: @coffre/server exports no ./node, since 0.16.0 ships for Workers only (D198: the signer on Node is not designed yet, and node.ts is 0.14's); it runs again once the Node port exports it (docs/design/0.16.md, \"Node in 0.16.0\")";
  console.error(process.env.GITHUB_ACTIONS === 'true' ? `::notice title=${what}::${why}` : `${what}: ${why}`);
}
console.log(String(ships));
