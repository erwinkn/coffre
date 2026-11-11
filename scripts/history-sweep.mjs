// The history sweep's comparison (R48; docs/history-sweep.md): two Postgres logs of the sweep's run, at a size and at
// ten times it, each holding auto_explain's plan of every statement the runtime logins ran, and the sweep's marks
// between its request paths. Each statement of each measured path, by the path and the statement's text (each run's
// database is another, and a query identifier hashes its tables' OIDs), with its literals left out, read so many
// pages (shared buffers hit or read) at most per run, so many times: one that reads more at the larger size, or runs
// more often, is one whose cost grows with history. Prints each that grows, and exits 1 when one does.
//
//   node scripts/history-sweep.mjs <small.log> <large.log>
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MARK = /\/\* sweep:(.*?) \*\/ SELECT 1/;

/**
 * Each plan auto_explain logged in `text` (a server log on stderr, `log_format = json`), in order: the backend that
 * ran it, its query's text, and the pages it read. One whose JSON does not parse (a line cut or interleaved) is left
 * out here, and `unparsed` counts it, which fails the sweep: left out silently, a statement of it would be in neither
 * run's map, and read as clean (Fable r1 of #559).
 */
export function plansOf(text) {
  return logged(text).flatMap(({ backend, plan }) => {
    if (plan === null) return [];
    const top = plan.Plan ?? {};
    return [{ backend, text: String(plan['Query Text'] ?? ''), pages: (top['Shared Hit Blocks'] ?? 0) + (top['Shared Read Blocks'] ?? 0) }];
  });
}

/** How many of the plans logged in `text` do not parse (`plansOf`). */
export function unparsed(text) {
  return logged(text).filter(({ plan }) => plan === null).length;
}

/** Each plan auto_explain logged in `text`: its backend, and its JSON parsed, or null when it does not parse. */
function logged(text) {
  const found = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const header = /\[(\d+)\] LOG:\s+duration: [\d.]+ ms\s+plan:\s*$/.exec(lines[i]);
    if (header === null) continue;
    const body = [];
    while (i + 1 < lines.length && lines[i + 1].startsWith('\t')) body.push(lines[++i].slice(1));
    let plan = null;
    try {
      plan = JSON.parse(body.join('\n').replace(/"Query Identifier": (-?\d+)/, '"Query Identifier": "$1"'));
    } catch {
      plan = null;
    }
    found.push({ backend: header[1], plan });
  }
  return found;
}

/**
 * A statement's text as the two runs share it: its spaces collapsed, its strings and numbers left out, and each list of
 * parameters (`$1`, or `$3, $4, $5` for an `IN` of three) one `$?`, so that an `IN` as long as a page's rows is one
 * statement however long, and its runs after the first on a backend are warm ones (review r3 of #559).
 */
export function shapeOf(text) {
  return text.replace(/\s+/g, ' ').trim().replace(/'(?:[^']|'')*'/g, "'?'").replace(/\$\d+(?:\s*,\s*\$\d+)*/g, '$?')
    .replace(/(?<![\w$.])\d+(?:\.\d+)?(?![\w.])/g, '?');
}

/**
 * The statements of each measured path, by the path and the statement's shape (`shapeOf`): the most pages one run of
 * it read there, how many times it ran there, and its text. A statement ran between the mark of its path and the next.
 * By path, not by shape alone: a statement many paths share (a member's access, read by every route) is as many
 * statements, so that one path's walk is not hidden under another's larger, flat run of it (review r2 of #559). Its pages
 * are those of its warm runs alone, never of a backend's first run of it, which reads the catalog too, as much at
 * either size or more (`prune_bulk`'s first call on a session, 1,295 pages on an empty database as on a grown one,
 * 18 after): `cold` keeps those apart, and a path whose runs of a statement were all first runs is `warm: false`, which
 * `unwarmed` reports rather than compare (review r3 of #559: by path, a first run on a backend another path warmed).
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
    const id = `${path}\u0000${shape}`;
    const seen = statements.get(id) ?? { path, pages: 0, cold: 0, warm: false, runs: 0, text: plan.text.replace(/\s+/g, ' ').trim() };
    if (first) seen.cold = Math.max(seen.cold, plan.pages);
    else seen.pages = Math.max(seen.pages, plan.pages);
    seen.warm ||= !first;
    seen.runs += 1;
    statements.set(id, seen);
  }
  return statements;
}

/**
 * Each statement that grows from `small` to `large`: reads at least twice the pages and eight more (a flat
 * statement gains an index level at most, a page for each index it steps down, and its rows), or runs at least twice
 * as often (a statement asked once for each entry of a history). One the larger run alone ran is listed too: a path
 * that took another branch there, whose statements the smaller never measured. One without a warm run at either size is
 * `unwarmed`'s, not compared here.
 */
export function growing(small, large) {
  const grown = [];
  for (const [id, at] of large) {
    const before = small.get(id);
    if (before === undefined) {
      grown.push({ id, why: 'new', before: null, after: at });
      continue;
    }
    if (!before.warm || !at.warm) continue;
    const pages = at.pages >= 2 * before.pages && at.pages - before.pages >= 8;
    const runs = at.runs >= 2 * before.runs && at.runs - before.runs >= 2;
    if (pages || runs) grown.push({ id, why: pages ? 'pages' : 'runs', before, after: at });
  }
  return grown.sort((a, b) => b.after.pages - a.after.pages);
}

/** The statements `small` ran that `large` did not: a path that stopped short at the larger size, its plans never logged. */
export function vanished(small, large) {
  return [...small].filter(([id]) => !large.has(id)).map(([id, at]) => ({ id, at }));
}

/**
 * The statements a path ran at both sizes with no warm run at one of them or both: their pages there are a backend's
 * first run's, the catalog's with them, so the sweep cannot say whether they grew, and fails rather than pass them.
 */
export function unwarmed(small, large) {
  return [...large].filter(([id, at]) => small.has(id) && !(small.get(id).warm && at.warm))
    .map(([id, at]) => ({ id, at, small: small.get(id).warm, large: at.warm }));
}

/** What each path answered in a run's output (`sweep outcomes`, history.sweep.ts), or null when it printed none. */
export function outcomesOf(text) {
  const line = text.split('\n').filter((one) => one.includes('sweep outcomes ')).at(-1);
  return line === undefined ? null : JSON.parse(line.slice(line.indexOf('sweep outcomes ') + 'sweep outcomes '.length));
}

/** The paths that answered otherwise at the two sizes, or ran at one alone. */
export function changedOutcomes(small, large) {
  return [...new Set([...Object.keys(small), ...Object.keys(large)])].filter((name) => small[name] !== large[name])
    .map((name) => ({ name, small: small[name] ?? 'not run', large: large[name] ?? 'not run' }));
}

/** The statements the server cancelled in a log (a statement or lock timeout, or a cancel): plans auto_explain never logs. */
export function cancelled(text) {
  return text.split('\n').filter((line) => /ERROR:\s+canceling statement/.test(line));
}

function report(grown) {
  for (const { id, why, before, after } of grown) {
    const was = before === null ? 'not run' : `${before.pages} pages, ${before.runs} runs`;
    console.log(`${why === 'new' ? 'NEW ' : 'GROWS'} ${was} -> ${after.pages} pages, ${after.runs} runs`);
    console.log(`      ${after.text.slice(0, 240)}`);
    console.log(`      in: ${after.path}`);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [smallLog, largeLog, smallOut, largeOut] = process.argv.slice(2);
  if (smallLog === undefined || largeLog === undefined || (smallOut === undefined) !== (largeOut === undefined)) {
    console.error('usage: node scripts/history-sweep.mjs <small.log> <large.log> [<small.out> <large.out>]');
    process.exit(2);
  }
  const [smallText, largeText] = [smallLog, largeLog].map((file) => readFileSync(file, 'utf8'));
  const [small, large] = [smallText, largeText].map((text) => statementsOf(plansOf(text)));
  if (small.size === 0 || large.size === 0) {
    console.error(`no plans in ${small.size === 0 ? smallLog : largeLog}: was auto_explain on for the runtime logins?`);
    process.exit(2);
  }
  const grown = growing(small, large);
  const flagged = grown.filter(({ why }) => why !== 'new');
  console.log(`${large.size} statements of paths measured; ${flagged.length} grow with history, ${grown.length - flagged.length} ran at the larger size alone`);
  report(grown);
  // A sweep is clean only if both runs went the same way to the end: a statement too slow at the larger size, cut by a
  // timeout, leaves no plan behind, and would otherwise read as none that grew (review r1 of #559).
  const problems = [];
  for (const [file, text] of [[smallLog, smallText], [largeLog, largeText]]) {
    const cut = unparsed(text);
    if (cut > 0) problems.push(`UNPARSED ${cut} plans in ${file}: their statements are measured at neither size`);
  }
  for (const { at, small: was, large: now } of unwarmed(small, large)) {
    problems.push(`COLD  no warm run at the ${was ? 'larger size' : now ? 'smaller size' : 'two sizes'}: ${at.text.slice(0, 200)} (in: ${at.path})`);
  }
  for (const { at } of vanished(small, large)) problems.push(`GONE  ran at the smaller size alone: ${at.text.slice(0, 200)} (in: ${at.path})`);
  for (const [file, text] of [[smallLog, smallText], [largeLog, largeText]]) {
    for (const line of cancelled(text)) problems.push(`CANCELLED in ${file}: ${line.slice(0, 200)}`);
  }
  if (smallOut !== undefined) {
    const [before, after] = [smallOut, largeOut].map((file) => outcomesOf(readFileSync(file, 'utf8')));
    if (before === null || after === null) problems.push(`no outcomes in ${before === null ? smallOut : largeOut}: the run did not finish`);
    else for (const { name, small: was, large: now } of changedOutcomes(before, after)) problems.push(`ANSWER ${name}: ${was} at the smaller size, ${now} at the larger`);
  }
  for (const problem of problems) console.log(problem);
  process.exit(flagged.length === 0 && problems.length === 0 ? 0 : 1);
}
