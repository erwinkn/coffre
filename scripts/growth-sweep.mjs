// The growth sweep's comparison (R48; docs/growth-sweep.md): two Postgres logs of the sweep's run, at a size and at
// ten times it, each holding auto_explain's plan of every statement the runtime logins ran, and the sweep's marks
// between its request paths. Each statement of each measured path, by the path and the statement's text (each run's
// database is another, and a query identifier hashes its tables' OIDs), with its literals left out, read so many
// pages (shared buffers hit or read) at most per run, so many times: one that reads more at the larger size, or runs
// more often, is one whose cost grows with history. Prints each that grows, and whether the list of known growers
// names it, and exits 1 when one it does not name grows, or when the runs cannot be compared.
//
//   node scripts/growth-sweep.mjs <small.log> <large.log> <small.outcomes.json> <large.outcomes.json> [--known <list>] [--write-known <list>]
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
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
    const seen = statements.get(id) ?? { path, shape, pages: 0, cold: 0, warm: false, runs: 0, text: plan.text.replace(/\s+/g, ' ').trim() };
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

/** What each path answered in a run, as its outcomes file tells (`COFFRE_SWEEP_OUTCOMES`, growth.sweep.ts), or null when it wrote none. */
function outcomesOf(file) {
  return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
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

/** A statement's name in the list of known growers: the first 12 hex digits of its shape's SHA-256. */
export function idOf(shape) {
  return createHash('sha256').update(shape).digest('hex').slice(0, 12);
}

/**
 * The list of known growers (scripts/growth-sweep-known.txt): a line for each statement of each path that grows, its
 * id (`idOf`), then its path; `#` starts a comment. The set of `<id> <path>`.
 */
export function knownOf(text) {
  return new Set(text.split('\n').map((line) => line.replace(/#.*/, '').trim()).filter((line) => line !== '')
    .map((line) => line.replace(/\s+/, ' ')));
}

/**
 * The comment lines above each statement's paths in a list of known growers, by its id: its text and where the code asks
 * it, which a person writes in (`#   from <file>:<line>`), and which `listOf` keeps when it writes the list again.
 */
export function notesOf(text) {
  const notes = new Map();
  let comments = [];
  for (const line of text.split('\n')) {
    if (line.trim() === '') comments = [];
    else if (line.startsWith('#')) comments.push(line);
    else {
      const id = line.trim().split(/\s+/)[0];
      if (!notes.has(id)) notes.set(id, comments);
    }
  }
  return notes;
}

/** The list of known growers that `grown` makes: each statement's paths under its notes (`notesOf`), or under its text. */
export function listOf(grown, notes) {
  const byId = new Map();
  for (const { after } of grown) {
    const id = idOf(after.shape);
    const entry = byId.get(id) ?? { notes: notes.get(id) ?? [`# ${after.text.slice(0, 150)}`, '#   from ?'], paths: [] };
    entry.paths.push(after.path);
    byId.set(id, entry);
  }
  const head = [
    '# The statements the growth sweep knows to grow with history (docs/growth-sweep.md): each statement of each path,',
    '# its id, then its path, under its text and where the code asks it. A pull request that fixes one deletes its lines;',
    '# one that makes another grow fails the sweep.',
    '',
  ];
  return head.concat([...byId].sort(([a], [b]) => a.localeCompare(b)).flatMap(([id, { notes: lines, paths }]) => [
    ...lines,
    ...paths.sort().map((path) => `${id} ${path}`),
    '',
  ])).join('\n');
}

function report(grown, notes, known) {
  for (const { why, before, after } of grown) {
    const id = idOf(after.shape);
    const listed = known === null ? '' : known.has(`${id} ${after.path}`) ? '  (known)' : '  NOT KNOWN';
    const was = before === null ? 'not run' : `${before.pages} pages, ${before.runs} runs`;
    console.log(`${why === 'new' ? 'NEW  ' : 'GROWS'} ${was} -> ${after.pages} pages, ${after.runs} runs${why === 'new' ? '' : listed}`);
    console.log(`      ${id} ${after.path}`);
    for (const line of (notes.get(id) ?? []).filter((one) => one.startsWith('#   from'))) console.log(`      ${line.slice(4)}`);
    console.log(`      ${after.text.slice(0, 240)}`);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const option = (name) => {
    const at = args.indexOf(name);
    return at === -1 ? undefined : args.splice(at, 2)[1];
  };
  const [knownFile, writeFile] = [option('--known'), option('--write-known')];
  const [smallLog, largeLog, smallOut, largeOut] = args;
  if (smallLog === undefined || largeLog === undefined || smallOut === undefined || largeOut === undefined) {
    console.error('usage: node scripts/growth-sweep.mjs <small.log> <large.log> <small.outcomes.json> <large.outcomes.json> [--known <list>] [--write-known <list>]');
    process.exit(2);
  }
  const [smallText, largeText] = [smallLog, largeLog].map((file) => readFileSync(file, 'utf8'));
  const [small, large] = [smallText, largeText].map((text) => statementsOf(plansOf(text)));
  if (small.size === 0 || large.size === 0) {
    console.error(`no plans in ${small.size === 0 ? smallLog : largeLog}: was auto_explain on for the runtime logins?`);
    process.exit(2);
  }
  const knownText = knownFile === undefined ? '' : readFileSync(knownFile, 'utf8');
  const known = knownFile === undefined ? null : knownOf(knownText);
  const notes = notesOf(knownText);
  const grown = growing(small, large);
  const flagged = grown.filter(({ why }) => why !== 'new');
  const unknown = known === null ? flagged : flagged.filter(({ after }) => !known.has(`${idOf(after.shape)} ${after.path}`));
  console.log(`${large.size} statements of paths measured; ${flagged.length} grow with history (${unknown.length} not known), ${grown.length - flagged.length} ran at the larger size alone`);
  report(grown, notes, known);
  if (known !== null) {
    const still = new Set(flagged.map(({ after }) => `${idOf(after.shape)} ${after.path}`));
    for (const line of [...known].filter((one) => !still.has(one))) console.log(`FLAT  ${line}: known to grow, but grew no more here; delete its line once a run on main agrees`);
  }
  if (writeFile !== undefined) {
    writeFileSync(writeFile, listOf(flagged, notes));
    console.log(`wrote the ${flagged.length} statements that grew to ${writeFile}`);
  }
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
  const [before, after] = [smallOut, largeOut].map((file) => outcomesOf(file));
  if (before === null || after === null) problems.push(`no outcomes in ${before === null ? smallOut : largeOut}: the run did not finish`);
  else for (const { name, small: was, large: now } of changedOutcomes(before, after)) problems.push(`ANSWER ${name}: ${was} at the smaller size, ${now} at the larger`);
  for (const problem of problems) console.log(problem);
  process.exit(unknown.length === 0 && problems.length === 0 ? 0 : 1);
}
