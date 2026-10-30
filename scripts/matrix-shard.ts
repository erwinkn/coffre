// The use matrices' cases, split across CI's shards (`pnpm test:matrices`, docs: AGENTS.md). `COFFRE_TEST_SHARD=<k>/<n>`
// runs the k-th of n shards: case i in generation order runs in shard i mod n + 1, so every shard takes a slice of every
// dimension, and costs about what the others do. Unset, every case runs. Each case is a world of its own, which no
// other case reads, so a shard runs its cases exactly as the whole matrix would, its setup and statistics its own.
//
// `COFFRE_TEST_SHARD_REPORT=<dir>` has each matrix write there which cases it ran, and of which:
// `scripts/matrix-coverage.mjs` holds a run's shards to running every case of every matrix exactly once.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

/** `<k>/<n>`, 1 <= k <= n; unset, the one shard of one. */
export function shardSpec(value: string | undefined): { shard: number; of: number } {
  if (value === undefined || value === '') return { shard: 1, of: 1 };
  const match = /^([1-9][0-9]*)\/([1-9][0-9]*)$/.exec(value);
  const [shard, of] = match === null ? [0, 0] : [Number(match[1]), Number(match[2])];
  if (shard < 1 || shard > of) throw new Error(`COFFRE_TEST_SHARD must be <k>/<n>, 1 <= k <= n, not ${JSON.stringify(value)}`);
  return { shard, of };
}

/** The cases of `shard` of `of`: every case whose index is shard - 1, mod `of`. */
export function sliceOf<T>(cases: readonly T[], { shard, of }: { shard: number; of: number }): T[] {
  return cases.filter((_, i) => i % of === shard - 1);
}

/**
 * The cases of the matrix `file` (its `import.meta.url`) this run asks, recorded under `COFFRE_TEST_SHARD_REPORT` by
 * `labelOf`, which names each case apart from every other of the matrix.
 */
export function shardOf<T>(file: string, cases: readonly T[], labelOf: (item: T) => string): T[] {
  const spec = shardSpec(process.env.COFFRE_TEST_SHARD);
  const ran = sliceOf(cases, spec);
  const dir = process.env.COFFRE_TEST_SHARD_REPORT;
  if (dir !== undefined && dir !== '') {
    const engine = process.env.COFFRE_TEST_ENGINE ?? 'postgres';
    const path = relative(root, fileURLToPath(file));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${engine}-${path.replaceAll('/', '_')}-${spec.shard}-of-${spec.of}.json`),
      JSON.stringify({ engine, file: path, ...spec, cases: cases.map(labelOf), ran: ran.map(labelOf) }));
  }
  return ran;
}
