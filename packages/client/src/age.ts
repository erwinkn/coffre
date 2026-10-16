import type { SecretKey } from './api.ts';

const DAY = 86_400_000;

/**
 * Whole days since a key's value was written (`updatedAt`, a reference's
 * source's): 0 on the day it was. Null while it reads no value.
 */
export function ageInDays(entry: Pick<SecretKey, 'updatedAt'>, now: number = Date.now()): number | null {
  return entry.updatedAt === null ? null : Math.max(0, Math.floor((now - Date.parse(entry.updatedAt)) / DAY));
}

/**
 * Whether a key's value has gone unchanged for more than `days` whole days:
 * against the deployment's `rotateAfterDays`, due for rotation. An archived
 * key, which nothing reads, and a key with no value never are.
 */
export function olderThan(entry: Pick<SecretKey, 'archived' | 'updatedAt'>, days: number, now: number = Date.now()): boolean {
  const age = ageInDays(entry, now);
  return !entry.archived && age !== null && age > days;
}
