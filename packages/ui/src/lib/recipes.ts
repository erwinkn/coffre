import type { SecretKey } from '@coffre/client';
import type { Generation } from '@coffre/core/recipe';

/**
 * A listed key's recipe, as far as the page may act on it: a key pair's
 * only while the list holds both its halves, live, each saying the same of
 * the pair. The server lists a pair by that rule; this holds the page to it
 * between a change shown at once and the list read back, while a value
 * typed over one half, or an archive, has not reached the other half yet.
 */
export function liveGeneration(entry: SecretKey, entries: readonly SecretKey[]): Generation | null {
  const { generated } = entry;
  if (generated === null || generated.pair === undefined) return generated;
  const { pair, recipe } = generated;
  const holds = (key: string) =>
    entries.some(
      (each) =>
        each.key === key &&
        !each.archived &&
        each.generated?.recipe === recipe &&
        each.generated.pair?.private === pair.private &&
        each.generated.pair.public === pair.public,
    );
  return holds(pair.private) && holds(pair.public) ? generated : null;
}

/**
 * The list after keys were renamed, `from` to `to`: each pair names its
 * halves as they are now, in both halves, as the server lists them.
 */
export function renamePairs(entries: readonly SecretKey[], renames: ReadonlyMap<string, string>): SecretKey[] {
  if (renames.size === 0) return [...entries];
  const now = (key: string) => renames.get(key) ?? key;
  return entries.map((entry) =>
    entry.generated?.pair === undefined
      ? entry
      : {
          ...entry,
          generated: {
            ...entry.generated,
            pair: { private: now(entry.generated.pair.private), public: now(entry.generated.pair.public) },
          },
        },
  );
}
