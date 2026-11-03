/**
 * JSON whose whole numbers may pass 2^53: an entry's `seq`, a change's
 * `number`, a member's `access_seq` (bigints all). `JSON.parse` would round
 * such a number to the nearest double, and a row's MAC or the log's head
 * would then fail on a digit the database never changed. Each number past
 * 2^53 comes back as its own text instead, which `BigInt` reads exactly.
 * Such a number has 16 digits or more: text without a run of 16 is read
 * plainly, at `JSON.parse`'s cost (a reviver on every value costs a use
 * 30 µs: measured, `use.postgres.ts`).
 */
export function exactly(text: string): unknown {
  if (!/\d{16}/.test(text)) return JSON.parse(text);
  return JSON.parse(text, (_key, value: unknown, context?: { source?: string }) => {
    if (!unsafe(value)) return value;
    // A runtime without JSON.parse's source text (Node 24 and workerd have it): never a number misread.
    if (context?.source === undefined) throw new Error('a whole number past 2^53, which this runtime cannot read exactly');
    return context.source;
  });
}

/** Whether `value` is a number `JSON.parse` may have rounded: a whole one past 2^53. */
export const unsafe = (value: unknown): boolean => typeof value === 'number' && !Number.isSafeInteger(value);
