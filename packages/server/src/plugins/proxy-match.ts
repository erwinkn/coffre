// A route's allow list (docs/design/proxy-ui.md, section 7): which methods
// and paths under its upstream a request may take. A request's path is
// matched as its segments, each percent-decoded once, to bytes, after the
// proxy's own check (`climbs` in credential-proxy.ts) has refused every
// segment that decodes, however often, to a slash, a dot segment or a
// control byte. A pattern is decoded the same way, once, when it is read.
//
//   /companies                 a plain path: a prefix by segments, /companies and /companies/42, never /companiesX
//   /companies/                code's trailing slash, as before 0.16: /companies/ and below, not /companies
//   /                          every path
//   /companies/*/documents     `*`, exactly one non-empty segment: segment by segment, exact
//   /companies/*/documents/**  `**`, zero or more segments, last only
//
// No regexes and no partial-segment globs (`doc*`): matching is one pass
// over the pattern's segments per entry, with no backtracking, since `**`
// is only ever last.

/** `*` in a pattern's segments: one segment, any non-empty bytes. */
const ONE = null;

/** A path pattern, read: its segments (decoded, `*` as `ONE`), and what may follow them. */
export type PathPattern = {
  segments: readonly (string | typeof ONE)[];
  /** `prefix`: anything, a plain path's; `below`: at least one more segment, code's trailing slash; `exact`: nothing; `rest`: anything, `**`; `never`: no path at all. */
  tail: 'prefix' | 'below' | 'exact' | 'rest' | 'never';
};

/** One entry of a route's allow list, read: its methods (null: any) and its path (null: any). */
export type AllowEntry = { methods: ReadonlySet<string> | null; path: PathPattern | null };

/** A pattern that matches nothing: code's, written so that every request it could match is refused anyway. */
export const NOTHING: PathPattern = { segments: [], tail: 'never' };

/** Bytes, one character each, of `%XX` in `text`, every other character as it is. */
function percentDecoded(text: string): string {
  return text.replace(/%([0-9a-f]{2})/gi, (_, byte: string) => String.fromCharCode(parseInt(byte, 16)));
}

/** A string's UTF-8 bytes, one character each. */
function utf8(text: string): string {
  let out = '';
  for (const byte of new TextEncoder().encode(text)) out += String.fromCharCode(byte);
  return out;
}

/**
 * What a decoded segment reads as to a server that decodes it again, or
 * drops its `;` parameters: a slash or a backslash, a control byte, an
 * overlong UTF-8 lead byte, or a dot segment. The request's own check
 * refuses each, so a pattern segment that is one matches nothing.
 */
function unsafeSegment(decoded: string): boolean {
  return /[/\\\x00-\x1f\x7f\xc0\xc1]/.test(decoded) || /^\.{1,2}[ \t]*$/.test(decoded.split(';')[0]!) || (percentDecoded(decoded) !== decoded && unsafeSegment(percentDecoded(decoded)));
}

/**
 * A path pattern as written, read: the pattern, or what is wrong with it.
 * `ui` is a definition saved in the Proxy tab, which takes no trailing
 * slash; `code` keeps code's trailing slash, and reads a segment that
 * decodes to a dot segment, a slash or nothing as matching nothing (a
 * warning: before 0.16 such a path matched nothing either).
 */
export function readPattern(path: string, from: 'code' | 'ui'): { pattern: PathPattern; warning?: string } | { problem: string } {
  if (typeof path !== 'string' || !path.startsWith('/')) return { problem: 'a path starts with /' };
  if (path === '/') return { pattern: { segments: [], tail: 'prefix' } };
  const written = path.slice(1).split('/');
  let tail: PathPattern['tail'] = 'prefix';
  if (written.at(-1) === '') {
    if (from === 'ui') return { problem: `a path ends in no slash: ${path.replace(/\/+$/, '')}/** for everything below it` };
    written.pop();
    tail = 'below';
  }
  const segments: (string | typeof ONE)[] = [];
  let glob = false;
  let dead: string | null = null;
  for (const [at, segment] of written.entries()) {
    if (segment === '**') {
      if (at !== written.length - 1 || tail === 'below') return { problem: '** stands for the rest of the path: last only' };
      tail = 'rest';
      glob = true;
      continue;
    }
    if (segment === '*') {
      segments.push(ONE);
      glob = true;
      continue;
    }
    if (segment.includes('*')) return { problem: `* and ** stand for whole segments, never part of one: ${JSON.stringify(segment)}` };
    const decoded = percentDecoded(utf8(segment));
    if (decoded === '' || unsafeSegment(decoded)) dead ??= segment === '' ? 'an empty segment' : JSON.stringify(segment);
    segments.push(decoded);
  }
  if (dead !== null) {
    if (from === 'ui') return { problem: `no empty, . or .. segment, nor one that decodes to a slash: ${dead}` };
    return { pattern: NOTHING, warning: `${path} has ${dead}, a segment no request reaches the upstream with: it matches nothing` };
  }
  // A plain path is a prefix; one with a glob is matched segment by segment, unless it ends in `**`.
  if (glob && tail === 'prefix') tail = 'exact';
  return { pattern: { segments, tail } };
}

/**
 * A request's path under the upstream (`/companies/42`, `/` for the
 * upstream itself) as the segments it is matched as, each decoded once, to
 * bytes: no UTF-8 check, case folding or normalization. The root is one
 * empty segment, as a trailing slash is. Null for an empty segment that is
 * not the last (`//`), which a glob would count as one.
 */
export function requestSegments(relative: string): string[] | null {
  const segments = relative.slice(1).split('/');
  for (let at = 0; at < segments.length - 1; at++) if (segments[at] === '') return null;
  return segments.map(percentDecoded);
}

/** Whether `pattern` matches the request's decoded `segments`: one pass over the pattern's own. */
export function matches(pattern: PathPattern, segments: readonly string[]): boolean {
  if (pattern.tail === 'never') return false;
  const wanted = pattern.segments;
  const count = segments.length;
  if (count < wanted.length) return false;
  for (let at = 0; at < wanted.length; at++) {
    const want = wanted[at];
    const have = segments[at]!;
    if (want === ONE ? have === '' : have !== want) return false;
  }
  switch (pattern.tail) {
    case 'prefix':
    case 'rest':
      return true;
    case 'below':
      return count > wanted.length;
    case 'exact':
      return count === wanted.length;
  }
}

/**
 * Whether a request is allowed: `allowed` when an entry takes both its
 * method and its path; else `method` when an entry takes its path, or none
 * takes its method on any path (a 405); else `path` (a 403). No entries:
 * everything.
 */
export function allows(entries: readonly AllowEntry[] | null, method: string, segments: readonly string[]): 'allowed' | 'method' | 'path' {
  if (entries === null) return 'allowed';
  let pathTaken = false;
  let methodTaken = false;
  for (const entry of entries) {
    const path = entry.path === null || matches(entry.path, segments);
    const takes = entry.methods === null || entry.methods.has(method);
    if (path && takes) return 'allowed';
    pathTaken ||= path;
    methodTaken ||= takes;
  }
  return pathTaken || !methodTaken ? 'method' : 'path';
}

/** The methods an allow list takes on the path `segments` are, or on any path (null), for a 405's message. */
export function methodsFor(entries: readonly AllowEntry[], segments: readonly string[] | null): string[] {
  return [...new Set(entries.filter((entry) => segments === null || entry.path === null || matches(entry.path, segments)).flatMap((entry) => [...(entry.methods ?? [])]))];
}
