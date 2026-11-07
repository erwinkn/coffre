/**
 * What a request body costs before its route runs, at worst: the numbers
 * `MAX_BODY_NODES` is computed from (`src/http.ts`).
 *
 *   node --conditions=coffre:source --expose-gc scripts/body-cost.ts             with zod's eval-built fast paths, as on Node
 *   node --conditions=coffre:source --expose-gc scripts/body-cost.ts --jitless   without, as on Workers, which forbids eval
 *
 * 1. Reading: `parseJsonBody` (the value count, then `JSON.parse` of what
 *    it lets through) of a body of `API_BODY_BYTES`, in the shapes that
 *    cost most, and the heap a parsed one holds (with `--expose-gc`).
 * 2. Validation: `check` with every route's schema, on bodies of
 *    `MAX_BODY_NODES` values in every worst shape, alone and under each
 *    field a route reads a map or a list from: the cost per value of the
 *    costliest.
 *
 * CPU is the thread's own (`process.cpuUsage`), the median of five runs, so
 * a loaded machine slows it less than wall time would.
 */
import { z } from 'zod';

if (process.argv.includes('--jitless')) z.config({ jitless: true });
const { routes } = await import('../src/api/routes.ts');
const { API_BODY_BYTES, check, MAX_BODY_NODES, parseJsonBody } = await import('../src/http.ts');

function cpuMs(run: () => void, times = 5): number {
  const spent: number[] = [];
  for (let i = 0; i < times; i += 1) {
    const start = process.cpuUsage();
    run();
    const used = process.cpuUsage(start);
    spent.push((used.user + used.system) / 1000);
  }
  return spent.sort((a, b) => a - b)[Math.floor(times / 2)]!;
}

const gc = (globalThis as { gc?: () => void }).gc;
/** The heap a body's parsed value holds, or null for one refused before it is parsed. */
function heldBytes(text: string): number | null {
  gc?.();
  const before = process.memoryUsage().heapUsed;
  let value: unknown;
  try {
    value = parseJsonBody(text);
  } catch {
    return null;
  }
  gc?.();
  const held = process.memoryUsage().heapUsed - before;
  if (value === undefined) throw new Error('unreachable');
  return held;
}

/** `{ "K0": <value>, … }`, as many entries as fit in `max` bytes or `count`. */
function map(value: string, { count = Infinity, max = API_BODY_BYTES } = {}): string {
  const parts: string[] = [];
  let size = 2;
  for (let i = 0; i < count; i += 1) {
    const part = `"K${i}":${value}`;
    if (size + part.length + 1 > max) break;
    parts.push(part);
    size += part.length + 1;
  }
  return `{${parts.join(',')}}`;
}
function list(value: string, { count = Infinity, max = API_BODY_BYTES } = {}): string {
  const n = Math.min(count, Math.floor((max - 2) / (value.length + 1)));
  return `[${Array.from({ length: n }, () => value).join(',')}]`;
}

console.log(`${process.version}${process.argv.includes('--jitless') ? ', jitless' : ''}; API_BODY_BYTES ${API_BODY_BYTES}, MAX_BODY_NODES ${MAX_BODY_NODES}`);

// 1. Reading a mebibyte, refused or not: the count stops it before any schema.
console.log('\nreading a body of API_BODY_BYTES: the count, then JSON.parse');
const big: Record<string, string> = {
  'list of 0': list('0'),
  'map of 0': map('0'),
  'map of long strings': map(`"${'x'.repeat(4000)}"`),
  'one string': `{"v":"${'x'.repeat(API_BODY_BYTES - 8)}"}`,
  'deep': '['.repeat(API_BODY_BYTES / 2 - 1) + ']'.repeat(API_BODY_BYTES / 2 - 1),
};
let readWorst = 0;
for (const [shape, text] of Object.entries(big)) {
  const ms = cpuMs(() => {
    try {
      parseJsonBody(text);
    } catch {
      // Refused by the count: what it costs is the point.
    }
  });
  readWorst = Math.max(readWorst, ms);
  const held = heldBytes(text);
  console.log(`  ${shape.padEnd(20)} ${String(text.length).padStart(8)} B  ${ms.toFixed(2).padStart(6)} ms  ${held === null ? 'refused before it is parsed' : `parsed, holds ${(held / text.length).toFixed(1)}x its size`}`);
}
console.log(`  worst: ${readWorst.toFixed(2)} ms`);

// 2. Validating MAX_BODY_NODES values: the root and its entries, or a field and its entries.
console.log(`\nvalidating ${MAX_BODY_NODES} values: each route's schema, the costliest shapes`);
const n = MAX_BODY_NODES - 2;
const shapes: Record<string, string> = {
  'map of 0': map('0', { count: n }),
  'map of true': map('true', { count: n }),
  'map of "v"': map('"v"', { count: n }),
  'map of {x:0}': map('{"x":0}', { count: Math.floor(n / 2) }),
  'map of {role}': map('{"role":"developer"}', { count: Math.floor(n / 2) }),
  'map of {value,sens}': map('{"value":"v","sensitivity":"secret"}', { count: Math.floor(n / 3) }),
  'list of 0': list('0', { count: n }),
  'list of "a"': list('"a"', { count: n }),
};
const fields = [null, 'keys', 'scope', 'claims', 'policy', 'access', 'items', 'response', 'arguments', 'paths', 'permissions', 'serviceAccounts', 'jwks'];
const costs: { ms: number; what: string }[] = [];
for (const [name, def] of Object.entries(routes) as [string, { input?: z.ZodType }][]) {
  if (def.input === undefined) continue;
  for (const [shape, text] of Object.entries(shapes)) {
    for (const field of fields) {
      let body: unknown;
      try {
        body = parseJsonBody(field === null ? text : `{"${field}":${text}}`);
      } catch {
        continue;
      }
      // A first look, then the costly ones measured.
      if (cpuMs(() => check(def.input!, body), 1) < 0.5) continue;
      costs.push({ ms: cpuMs(() => check(def.input!, body)), what: `${name} ${field ?? ''} ${shape}` });
    }
  }
}
costs.sort((a, b) => b.ms - a.ms);
for (const { ms, what } of costs.slice(0, 8)) {
  console.log(`  ${ms.toFixed(1).padStart(6)} ms  ${((ms * 1000) / MAX_BODY_NODES).toFixed(2).padStart(5)} µs a value  ${what}`);
}
const worst = costs[0];
if (worst !== undefined) {
  console.log(`  worst: ${((worst.ms * 1000) / MAX_BODY_NODES).toFixed(2)} µs a value; with the read, ${(readWorst + worst.ms).toFixed(1)} ms`);
}
