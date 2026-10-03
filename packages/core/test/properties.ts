import { Database, type Settings } from '@hegeldev/hegel';

/** Fixed seeds and no example cache make local and CI runs explore the same cases. */
export function propertySettings(offset: number, cases: number): Partial<Settings> {
  const seedArgument = process.argv.find((arg) => arg.startsWith('--seed='));
  const seed = seedArgument ? Number(seedArgument.slice('--seed='.length)) : 20261003;
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffff_ffff) throw new Error('--seed must be an unsigned 32-bit integer');
  return { seed: (seed + offset) >>> 0, testCases: cases * (process.argv.includes('--long') ? 100 : 1), database: Database.disabled };
}
