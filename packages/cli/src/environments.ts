// The environments `coffre run` and `coffre export` read together, as one:
// each key comes from one of them, never from whichever was read last.
import { UsageError } from './manage.ts';

/** The environments named, `market/prod auth/prod`, each checked, none twice. */
export function environmentPaths(positionals: readonly string[]): string[] {
  if (positionals.length === 0) throw new UsageError('name an environment: <project>/<environment>');
  for (const [i, path] of positionals.entries()) {
    const parts = path.split('/');
    if (parts.length !== 2 || parts.some((part) => part === '')) throw new UsageError(`expected <project>/<environment>, not "${path}"`);
    if (positionals.indexOf(path) !== i) throw new UsageError(`${path} is named twice`);
  }
  return [...positionals];
}

/**
 * The keys two of the environments both define, by the pair, said in a
 * line without a value: `deploy/prod and auth/prod both define API_URL and
 * TOKEN`. Null when each key is in one environment only.
 */
export function clash(environments: readonly (readonly [path: string, keys: Iterable<string>])[]): string | null {
  const first = new Map<string, string>();
  const shared = new Map<string, string[]>();
  for (const [path, keys] of environments) {
    for (const key of keys) {
      const at = first.get(key);
      if (at === undefined) {
        first.set(key, path);
        continue;
      }
      const pair = `${at} and ${path}`;
      shared.set(pair, [...(shared.get(pair) ?? []), key]);
    }
  }
  if (shared.size === 0) return null;
  return [...shared].map(([pair, keys]) => `${pair} both define ${listOf(keys.sort())}`).join('; ');
}

/** `a`, `a and b`, `a, b and c`. */
export function listOf(items: readonly string[]): string {
  return items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
}
