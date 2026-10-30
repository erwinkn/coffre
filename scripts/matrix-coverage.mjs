#!/usr/bin/env node
// Usage: node scripts/matrix-coverage.mjs <reports dir> <engine>...
//
// Holds a CI run's use-matrix shards to running every case exactly once (`Use matrices`, .github/workflows/validate.yml):
// on each engine named, every matrix of the checkout (`packages/*/test/*.matrix.ts`) reported by each of its shards, 1
// to n, from the same cases, which their slices partition. What each shard ran is what its matrices wrote
// (`scripts/matrix-shard.ts`), so a matrix that does not shard, or a shard that never learnt its slice, shows as a case
// run twice; one that never ran, as no report.
import { globSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const MATRICES = 'packages/*/test/*.matrix.ts';

/** Every report under `dir`, at any depth: CI downloads each shard's into a directory of its own. */
export function readReports(dir) {
  return readdirSync(dir, { recursive: true }).filter((name) => name.endsWith('.json')).map((name) => JSON.parse(readFileSync(join(dir, name), 'utf8')));
}

/** What is wrong with `reports` as the shards of `files` on each of `engines`: nothing, when every case ran once. */
export function coverage(reports, files, engines) {
  const problems = [];
  const expected = new Set(engines.flatMap((engine) => files.map((file) => `${engine} ${file}`)));
  for (const report of reports) {
    if (!expected.has(`${report.engine} ${report.file}`)) problems.push(`${report.engine} ${report.file}: a report of no matrix asked for (shard ${report.shard} of ${report.of})`);
  }
  for (const engine of engines) {
    for (const file of files) {
      const label = `${engine} ${file}`;
      const mine = reports.filter((report) => report.engine === engine && report.file === file);
      if (mine.length === 0) {
        problems.push(`${label}: no shard reported`);
        continue;
      }
      const of = new Set(mine.map((report) => report.of));
      if (of.size > 1) {
        problems.push(`${label}: shards of ${[...of].sort().join(' and ')}`);
        continue;
      }
      const [n] = of;
      const shards = mine.map((report) => report.shard).sort((a, b) => a - b);
      const want = Array.from({ length: n }, (_, i) => i + 1);
      if (shards.join(' ') !== want.join(' ')) {
        problems.push(`${label}: shards ${shards.join(', ')} reported, of ${n}`);
        continue;
      }
      const cases = mine[0].cases;
      if (mine.some((report) => JSON.stringify(report.cases) !== JSON.stringify(cases))) {
        problems.push(`${label}: its shards generated other cases`);
        continue;
      }
      if (new Set(cases).size !== cases.length) {
        problems.push(`${label}: two cases of one label`);
        continue;
      }
      const runs = new Map(cases.map((c) => [c, []]));
      for (const report of mine) {
        for (const c of report.ran) {
          if (!runs.has(c)) problems.push(`${label}: shard ${report.shard} ran ${c}, no case of the matrix`);
          else runs.get(c).push(report.shard);
        }
      }
      for (const [c, by] of runs) {
        if (by.length === 0) problems.push(`${label}: ${c} ran in no shard`);
        if (by.length > 1) problems.push(`${label}: ${c} ran in shards ${by.join(', ')}`);
      }
    }
  }
  return problems;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [dir, ...engines] = process.argv.slice(2);
  if (dir === undefined || engines.length === 0) {
    console.error('Usage: node scripts/matrix-coverage.mjs <reports dir> <engine>...');
    process.exit(2);
  }
  const files = globSync(MATRICES).sort();
  const reports = readReports(dir);
  const problems = coverage(reports, files, engines);
  for (const engine of engines) {
    for (const file of files) {
      const mine = reports.filter((report) => report.engine === engine && report.file === file).sort((a, b) => a.shard - b.shard);
      console.log(`${engine} ${file}: ${mine[0]?.cases.length ?? 0} cases, in ${mine.map((report) => `${report.ran.length}`).join(' + ') || 'no shard'}`);
    }
  }
  for (const problem of problems) console.error(problem);
  process.exit(problems.length === 0 ? 0 : 1);
}
