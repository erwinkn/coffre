import { HealthCheck } from '@hegeldev/hegel';

/**
 * Fixed seeds and no example cache make local and CI runs explore the same cases.
 * TooSlow is off: it fails a property on the wall-clock time its cases take to
 * generate, which a loaded host stretches with no bug behind it (twice under the
 * gate's load, 2026-11-11). The cases and their checks stay the same.
 */
export function propertySettings(cases: number, longMultiplier = 100) {
  const seedArgument = process.argv.find((arg) => arg.startsWith('--seed='));
  const seed = seedArgument ? Number(seedArgument.slice('--seed='.length)) : 20261003;
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffff_ffff) throw new Error('--seed must be an unsigned 32-bit integer');
  return {
    seed,
    testCases: cases * (process.argv.includes('--long') ? longMultiplier : 1),
    database: { kind: 'disabled' as const },
    suppressHealthCheck: [HealthCheck.TooSlow],
  };
}
