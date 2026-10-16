import type { SecretKey } from '@coffre/client';

/**
 * How an environment's table is ordered: by name, as listed, or by when
 * each value was written, ascending the oldest first.
 */
export type Sort = { by: 'key' | 'written'; descending: boolean };

/**
 * The keys in `sort`'s order, from the listing's, by name. By age, those
 * without a value come last either way, and keys written together keep
 * their names' order.
 */
export function sortKeys(entries: SecretKey[], sort: Sort): SecretKey[] {
  if (sort.by === 'key') return sort.descending ? [...entries].reverse() : entries;
  const direction = sort.descending ? -1 : 1;
  return [...entries].sort((a, b) => {
    if (a.updatedAt === b.updatedAt) return 0;
    if (a.updatedAt === null) return 1;
    if (b.updatedAt === null) return -1;
    return a.updatedAt < b.updatedAt ? -direction : direction;
  });
}
