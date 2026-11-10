// The history sweep's comparison (R48; docs/history-sweep.md): two Postgres logs of the sweep's run, at a size and at
// ten times it, each holding auto_explain's plan of every statement the runtime logins ran, and the sweep's marks
// between its request paths. Each statement, by its text (each run's database is another, and a query identifier
// hashes its tables' OIDs), with its literals left out, read so many pages (shared buffers hit or
// read) at most per run of a measured path, so many times: one that reads more at the larger size, or runs more
// often, is one whose cost grows with history. Prints each that grows, and exits 1 when one does.
//
//   node scripts/history-sweep.mjs <small.log> <large.log>
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MARK = /\/\* sweep:(.*?) \*\/ SELECT 1/;

/**
 * Each plan auto_explain logged in `text` (a server log on stderr, `log_format = json`), in order: the backend that
 * ran it, its query's text, and the pages it read.
 */
export function plansOf(text) {
  const plans = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const logged = /\[(\d+)\] LOG:\s+duration: [\d.]+ ms\s+plan:\s*$/.exec(lines[i]);
    if (logged === null) continue;
    const body = [];
    while (i + 1 < lines.length && lines[i + 1].startsWith('\t')) body.push(lines[++i].slice(1));
    let plan;
    try {
      plan = JSON.parse(body.join('\n').replace(/"Query Identifier": (-?\d+)/, '"Query Identifier": "$1"'));
    } catch {
      continue;
    }
    const top = plan.Plan ?? {};
    plans.push({ backend: logged[1], text: String(plan['Query Text'] ?? ''), pages: (top['Shared Hit Blocks'] ?? 0) + (top['Shared Read Blocks'] ?? 0) });
  }
  return plans;
}

/** A statement's text as the two runs share it: its spaces collapsed, its strings and numbers (not `$1`) left out. */
export function shapeOf(text) {
  return text.replace(/\s+/g, ' ').trim().replace(/'(?:[^']|'')*'/g, "'?'").replace(/(?<![\w$.])\d+(?:\.\d+)?(?![\w.])/g, '?');
}

/**
 * The statements of the measured paths, by their shape (`shapeOf`): the most pages one run of it read, how many times
 * it ran, the paths it ran in and its text. A statement ran between the mark of its path and the next. The pages of
 * a statement's first run on a backend are its own only when it never ran there again: a function's statements are
 * planned in its call's execution, and a backend's first plan of one reads the catalog (`prune_bulk`'s first call on
 * a session, 1,295 pages on an empty database as on a grown one, 18 after).
 */
export function statementsOf(plans) {
  const statements = new Map();
  const ran = new Set();
  let path = null;
  for (const plan of plans) {
    const marked = MARK.exec(plan.text);
    if (marked !== null) {
      path = marked[1].startsWith('measured:') ? marked[1].slice('measured:'.length) : null;
      continue;
    }
    // A backend's first run of a statement in the warm round too, which the measured round then runs warm.
    const shape = shapeOf(plan.text);
    const first = !ran.has(`${plan.backend} ${shape}`);
    ran.add(`${plan.backend} ${shape}`);
    if (path === null) continue;
    const seen = statements.get(shape) ?? { pages: 0, cold: 0, warm: false, runs: 0, paths: new Set(), text: plan.text.replace(/\s+/g, ' ').trim() };
    if (first) seen.cold = Math.max(seen.cold, plan.pages);
    else seen.pages = seen.warm ? Math.max(seen.pages, plan.pages) : plan.pages;
    seen.warm ||= !first;
    seen.runs += 1;
    seen.paths.add(path);
    statements.set(shape, seen);
  }
  for (const seen of statements.values()) if (!seen.warm) seen.pages = seen.cold;
  return statements;
}

/**
 * Each statement that grows from `small` to `large`: reads at least twice the pages and eight more (a flat
 * statement gains an index level at most, a page for each index it steps down, and its rows), or runs at least twice
 * as often (a statement asked once for each entry of a history). One the larger run alone ran is listed too: a path
 * that took another branch there, whose statements the smaller never measured.
 */
export function growing(small, large) {
  const grown = [];
  for (const [id, at] of large) {
    const before = small.get(id);
    if (before === undefined) {
      grown.push({ id, why: 'new', before: null, after: at });
      continue;
    }
    const pages = at.pages >= 2 * before.pages && at.pages - before.pages >= 8;
    const runs = at.runs >= 2 * before.runs && at.runs - before.runs >= 2;
    if (pages || runs) grown.push({ id, why: pages ? 'pages' : 'runs', before, after: at });
  }
  return grown.sort((a, b) => b.after.pages - a.after.pages);
}

function report(grown) {
  for (const { id, why, before, after } of grown) {
    const was = before === null ? 'not run' : `${before.pages} pages, ${before.runs} runs`;
    console.log(`${why === 'new' ? 'NEW ' : 'GROWS'} ${was} -> ${after.pages} pages, ${after.runs} runs`);
    console.log(`      ${after.text.slice(0, 240)}`);
    console.log(`      in: ${[...after.paths].slice(0, 4).join('; ')}${after.paths.size > 4 ? `; and ${after.paths.size - 4} more` : ''}`);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [smallLog, largeLog] = process.argv.slice(2);
  if (smallLog === undefined || largeLog === undefined) {
    console.error('usage: node scripts/history-sweep.mjs <small.log> <large.log>');
    process.exit(2);
  }
  const [small, large] = [smallLog, largeLog].map((file) => statementsOf(plansOf(readFileSync(file, 'utf8'))));
  if (small.size === 0 || large.size === 0) {
    console.error(`no plans in ${small.size === 0 ? smallLog : largeLog}: was auto_explain on for the runtime logins?`);
    process.exit(2);
  }
  const grown = growing(small, large);
  const flagged = grown.filter(({ why }) => why !== 'new');
  console.log(`${large.size} statements measured; ${flagged.length} grow with history, ${grown.length - flagged.length} ran at the larger size alone`);
  report(grown);
  process.exit(flagged.length === 0 ? 0 : 1);
}
