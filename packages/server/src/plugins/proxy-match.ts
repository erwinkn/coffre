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

/**
 * A path or a URL with each `%XX` as its byte, one character each, every
 * other character as it is. It never fails, as decoding the whole as UTF-8
 * does on a `%FF`: what segments are matched as, and what the handle, which
 * is ASCII, is looked for in (`coffre%5Fuse_…`).
 */
export function bytesOf(text: string): string {
  return text.replace(/%([0-9a-f]{2})/gi, (_, byte: string) => String.fromCharCode(parseInt(byte, 16)));
}

/** How many times a segment is decoded, at most, to see what a server behind reads it as: nothing sent encodes deeper. */
const DEPTH = 8;

/**
 * Whether some reading of `decoded`, a segment decoded once, as it is or
 * decoded again, `DEPTH` decodings in all, is `bad`; true, too, when it
 * still decodes past them, which nothing sent has reason to. A loop, so a
 * segment of 40 KB of `%2525…` costs `DEPTH` passes over it at most.
 */
function anyReading(decoded: string, bad: (view: string) => boolean): boolean {
  let view = decoded;
  for (let depth = 1; depth <= DEPTH; depth++) {
    if (bad(view)) return true;
    const next = bytesOf(view);
    if (next === view) return false;
    view = next;
  }
  return true;
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
  return anyReading(decoded, (view) => /[/\\\x00-\x1f\x7f\xc0\xc1]/.test(view) || /^\.{1,2}[ \t]*$/.test(view.split(';')[0]!));
}

/**
 * Whether a request's segment, as sent, climbs out of where it seems to
 * be: decoded, however often, a slash, a control byte or a dot segment
 * (`unsafeSegment`). A request or a presigned URL with one is refused
 * before any matching.
 */
export function climbs(segment: string): boolean {
  return unsafeSegment(bytesOf(segment));
}

/**
 * Whether a segment, decoded once (`decoded`), is no segment to a server
 * that drops `;` parameters, as Tomcat and Spring do, or trailing spaces
 * and dots, as Windows' do, decoded however often: `;x`, `%3Bx`, `%20`,
 * `...`. Such a server reads `/companies/;x/documents` as
 * `/companies//documents`, or `/companies/documents`, and a glob counted
 * it as one.
 */
function vanishes(decoded: string): boolean {
  return anyReading(decoded, (view) => /^[ .]*$/.test(view.split(';')[0]!));
}

/**
 * A path pattern as written, read: the pattern, or what is wrong with it.
 * `ui` is a definition saved in the Proxy tab, which takes no trailing
 * slash; `code` keeps code's trailing slash, and reads a segment that
 * decodes to a dot segment, a slash, nothing or what `vanishes` (`;x`,
 * `%20`, `...`) as matching nothing (a warning: no request with such a
 * segment reaches the upstream).
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
    const decoded = bytesOf(utf8(segment));
    if (unsafeSegment(decoded) || vanishes(decoded)) dead ??= segment === '' ? 'an empty segment' : JSON.stringify(segment);
    segments.push(decoded);
  }
  if (dead !== null) {
    if (from === 'ui') return { problem: `no empty, . or .. segment, none of spaces, dots or ; parameters alone, nor one that decodes to a slash: ${dead}` };
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
 * empty segment, as a trailing slash is. An empty segment (`//`) or one
 * that `vanishes` (`;x`, `%20`, `...`) stays as it is: only a `*` refuses
 * one (`matches`).
 */
export function requestSegments(relative: string): string[] {
  return relative.slice(1).split('/').map(bytesOf);
}

// Whether `pattern` matches the request's decoded `segments`: one pass over
// the pattern's own. A `*` takes one segment a server reads as one, never an
// empty one or one that `vanishes`: a server that drops `;` parameters reads
// `/companies/;x/documents` as `/companies//documents`, or
// `/companies/documents`, which `/companies/*/documents` does not take.
// Anywhere else such a segment is harmless: a literal never equals one
// (`readPattern`), and past a prefix, a `**` or a trailing slash, the path a
// server makes of it is still inside (`/bucket/a//b`, an S3 key, under
// `/bucket`).
export function matches(pattern: PathPattern, segments: readonly string[]): boolean {
  if (pattern.tail === 'never') return false;
  const wanted = pattern.segments;
  const count = segments.length;
  if (count < wanted.length) return false;
  for (let at = 0; at < wanted.length; at++) {
    const want = wanted[at];
    const have = segments[at]!;
    if (want === ONE ? vanishes(have) : have !== want) return false;
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
