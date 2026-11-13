// show.mjs <trace.itf.json>: one line per step, what was taken and what moved.
import { readFileSync } from 'node:fs';
const plain = (v) => Array.isArray(v) ? v.map(plain) : v === null || typeof v !== 'object' ? v
  : '#bigint' in v ? Number(v['#bigint']) : '#map' in v ? Object.fromEntries(v['#map'].map(([k, x]) => [JSON.stringify(plain(k)), plain(x)]))
  : '#set' in v ? v['#set'].map(plain).sort() : '#tup' in v ? v['#tup'].map(plain)
  : 'tag' in v && 'value' in v ? (v.tag === 'Some' ? plain(v.value) : v.tag === 'None' ? undefined : v.tag)
  : Object.fromEntries(Object.entries(v).map(([k, x]) => [k.split('::').at(-1), plain(x)]));
const t = JSON.parse(readFileSync(process.argv[2], 'utf8')).states.map(plain);
let prev = {};
for (const s of t) {
  const picks = Object.entries(s.nondetPicks ?? {}).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${v}`).join(' ');
  const flat = {};
  for (const [k, v] of Object.entries(s)) if (v && typeof v === 'object' && !Array.isArray(v) && !k.includes('ondet')) for (const [f, x] of Object.entries(v)) flat[`${k}.${f}`] = JSON.stringify(x);
  const moved = Object.entries(flat).filter(([k, v]) => prev[k] !== v).map(([k, v]) => `${k}=${v}`).join('  ');
  console.log(`${String(s.actionTaken).padEnd(9)} ${picks.padEnd(24)} ${moved}`.slice(0, 600));
  prev = flat;
}
