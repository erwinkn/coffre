import { readFileSync } from 'node:fs';

/** ITF's big integers, maps, sets, tuples and variants, as plain values, each variable under its own name. */
function plain(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(plain);
  if (value === null || typeof value !== 'object') return value;
  const v = value as Record<string, unknown>;
  if ('#bigint' in v) return Number(v['#bigint']);
  if ('#map' in v) return Object.fromEntries((v['#map'] as [string, unknown][]).map(([key, item]) => [key, plain(item)]));
  if ('#set' in v) return (v['#set'] as unknown[]).map(plain);
  if ('#tup' in v) return (v['#tup'] as unknown[]).map(plain);
  if ('tag' in v && 'value' in v) return v.tag === 'Some' ? plain(v.value) : v.tag === 'None' ? undefined : v.tag;
  return Object.fromEntries(Object.entries(v).map(([key, item]) => [key.split('::').at(-1)!, plain(item)]));
}

/** The states of one run Quint's simulator wrote (`--mbt --out-itf`): each with the action taken to reach it, and what it picked. */
export function statesOf<State>(file: string): State[] {
  return (JSON.parse(readFileSync(file, 'utf8')) as { states: unknown[] }).states.map(plain) as State[];
}
