/** Fixed seeds and no example cache make local and CI runs explore the same cases. */
export function propertySettings(cases: number, longMultiplier = 100) {
  const seedArgument = process.argv.find((arg) => arg.startsWith('--seed='));
  const seed = seedArgument ? Number(seedArgument.slice('--seed='.length)) : 20261003;
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffff_ffff) throw new Error('--seed must be an unsigned 32-bit integer');
  return { seed, testCases: cases * (process.argv.includes('--long') ? longMultiplier : 1), database: { kind: 'disabled' as const } };
}
