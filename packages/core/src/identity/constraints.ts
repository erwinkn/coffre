/**
 * A `narrow` child's limits (docs/design/workload-access.md, section 8.4):
 * the places, credentials, methods and path prefixes it may reach, each
 * left out for no limit of its own. A child holds the intersection of what
 * it asked and what its parent holds, computed when it is made and stored
 * under its row's MAC, and every operation it asks for is checked against
 * them by `constraintsAllow`, on the URL the proxy is about to send.
 *
 *   parent { credentials: ['stripe', 'openai'] }   child asks { credentials: ['stripe'], paths: ['/v1/refunds'] }
 *   child  { credentials: ['stripe'], paths: ['/v1/refunds'] }
 *   POST https://api.stripe.com/v1/refunds/re_1          allowed
 *   POST https://api.stripe.com/v1/refunds/%2e%2e/charges refused: it is /v1/charges once parsed
 *   POST https://api.stripe.com/v1/refundsX              refused: a prefix matches whole segments
 */
import { fetchMethod, METHOD_TOKEN } from '@coffre/client/dpop';

import { CREDENTIAL_NAME } from './workloads.ts';

export type Constraints = {
  /** Environments, `<project>/<environment>`. */
  readonly places?: readonly string[];
  /** The credentials, signers, verifiers, tunnels and minters it may reach, by name. */
  readonly credentials?: readonly string[];
  readonly methods?: readonly string[];
  /** Path prefixes, each matching whole segments. */
  readonly paths?: readonly string[];
};

/** A constraint that does not parse, said so the caller can fix it. */
export class ConstraintsInvalid extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConstraintsInvalid';
  }
}

const PLACE = /^[a-z0-9][a-z0-9-]{0,62}\/[a-z0-9][a-z0-9-]{0,62}(@me)?$/;
/** A path segment as a constraint names one: no escape, no `;`, no dot segment. */

/**
 * What a path may not hold for a constrained session, since an upstream
 * might read a segment otherwise than coffre: an escaped `.`, `/` or `\`,
 * a `%25` (double encoding), or a `;`, raw or escaped
 * (`/v1/refunds/..;/charges` and `/v1/refunds/..%3b/charges` are
 * `/v1/charges` to Tomcat).
 */
const AMBIGUOUS = /%2e|%2f|%5c|%25|%3b|;/i;

function list(value: unknown, what: string, valid: (item: string) => boolean): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !valid(item))) {
    throw new ConstraintsInvalid(`${what} is a list of them`);
  }
  return [...new Set(value as string[])].sort();
}

/** Segments of the characters a constraint's path takes, none a dot segment: one pass over the whole path, never split, however many it holds. */
const PREFIX = /^(?:\/(?!\.\.?(?:\/|$))[A-Za-z0-9\-_~!$&'()*+,=:@.]+)+$/;

function isPrefix(path: string): boolean {
  return path === '/' || PREFIX.test(path);
}

/** Whether `path` is `prefix` or below it, by whole segments. */
function under(path: string, prefix: string): boolean {
  return prefix === '/' || path === prefix || path.startsWith(`${prefix}/`);
}

/**
 * Constraints as a child asks for them, checked and canonical: each list
 * sorted, without duplicates; methods as Fetch sends them; prefixes absolute,
 * with no trailing slash, escape, `;` or dot segment, and none under
 * another, which it would add nothing to. Throws `ConstraintsInvalid`.
 */
export function checkConstraints(input: unknown): Constraints {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new ConstraintsInvalid('constraints are an object');
  const { places, credentials, methods, paths, ...rest } = input as Record<string, unknown>;
  if (Object.keys(rest).length > 0) throw new ConstraintsInvalid(`constraints hold places, credentials, methods and paths, not ${Object.keys(rest).join(', ')}`);
  const checked: { -readonly [K in keyof Constraints]: Constraints[K] } = {};
  const placeList = list(places, 'places', (place) => PLACE.test(place));
  const credentialList = list(credentials, 'credentials', (name) => CREDENTIAL_NAME.test(name));
  // As Fetch sends each, and so as a proof signs it: `get` is GET, and `M-SEARCH` stays itself.
  const methodList = list(Array.isArray(methods) ? methods.map((method) => (typeof method === 'string' && METHOD_TOKEN.test(method) ? fetchMethod(method) : method)) : methods, 'methods', (method) => METHOD_TOKEN.test(method));
  const pathList = list(paths, 'paths', isPrefix);
  if (placeList !== undefined) checked.places = placeList;
  if (credentialList !== undefined) checked.credentials = credentialList;
  if (methodList !== undefined) checked.methods = methodList;
  if (pathList !== undefined) checked.paths = outermost(pathList);
  return checked;
}

/** The prefixes no other one is above. */
/**
 * Paths in the order of their segments, each `/` sorting before any other
 * character: so every path below one comes right after it, before a
 * sibling such as `/a-b` of `/a`, and what is under a path is found by its
 * neighbours alone, never by comparing every pair of a list as long as a
 * body lets one be.
 */
function bySegments(paths: Iterable<string>): string[] {
  return [...new Set(paths)]
    .map((path) => [path.replaceAll('/', '\0'), path] as const)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, path]) => path);
}

/** Those of `paths` under no other, sorted: each kept unless it is under the last one kept, its nearest ancestor if any. */
function outermost(paths: readonly string[]): string[] {
  const kept: string[] = [];
  for (const path of bySegments(paths)) if (kept.length === 0 || !under(path, kept[kept.length - 1]!)) kept.push(path);
  return kept.sort();
}

/** Those of `paths` under one of `prefixes`: each under the nearest of the outermost prefixes before it, or under none. */
function inside(paths: readonly string[], prefixes: readonly string[]): string[] {
  const outer = bySegments(outermost(prefixes));
  const keys = outer.map((prefix) => prefix.replaceAll('/', '\0'));
  return paths.filter((path) => {
    const key = path.replaceAll('/', '\0');
    let low = 0;
    for (let high = keys.length; low < high;) {
      const middle = (low + high) >> 1;
      if (keys[middle]! <= key) low = middle + 1;
      else high = middle;
    }
    return low > 0 && under(path, outer[low - 1]!);
  });
}

function both(a: readonly string[] | undefined, b: readonly string[] | undefined): readonly string[] | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  const held = new Set(b);
  return a.filter((item) => held.has(item));
}

/**
 * What a child holds: what it asked within what its parent holds, list by
 * list, and for paths each prefix of one side that is under one of the
 * other's. A parent with none is a root, which only its scope bounds. Never
 * wider than either: whatever `intersect(a, b)` allows, `a` and `b` allow.
 */
export function intersect(parent: Constraints | null, child: Constraints): Constraints {
  if (parent === null) return child;
  const result: { -readonly [K in keyof Constraints]: Constraints[K] } = {};
  const places = both(parent.places, child.places);
  const credentials = both(parent.credentials, child.credentials);
  const methods = both(parent.methods, child.methods);
  if (places !== undefined) result.places = places;
  if (credentials !== undefined) result.credentials = credentials;
  if (methods !== undefined) result.methods = methods;
  if (parent.paths === undefined || child.paths === undefined) {
    const paths = parent.paths ?? child.paths;
    if (paths !== undefined) result.paths = paths;
  } else {
    const kept = [...inside(child.paths, parent.paths), ...inside(parent.paths, child.paths)];
    result.paths = outermost([...new Set(kept)].sort());
  }
  return result;
}

/**
 * Whether one operation is within the constraints: its place and credential
 * named, and, for one that sends a request upstream, its method and the
 * path of the URL it is about to send, as the WHATWG parser resolved it.
 * An operation with no request to check (`sign`, `verify`, `mint`, the
 * tunnel) is refused wherever methods or paths are limited: a constraint
 * that cannot be checked refuses.
 */
export function constraintsAllow(
  constraints: Constraints | null,
  operation: { place: string; credential: string; request?: { method: string; url: string | URL } },
): boolean {
  if (constraints === null) return true;
  if (constraints.places !== undefined && !constraints.places.includes(operation.place)) return false;
  if (constraints.credentials !== undefined && !constraints.credentials.includes(operation.credential)) return false;
  if (constraints.methods === undefined && constraints.paths === undefined) return true;
  if (operation.request === undefined) return false;
  // Exactly, as a proof signs it: a child of POST is refused `post`, which an upstream may read otherwise.
  if (constraints.methods !== undefined && !(METHOD_TOKEN.test(operation.request.method) && constraints.methods.includes(fetchMethod(operation.request.method)))) return false;
  if (constraints.paths === undefined) return true;
  let path: string;
  try {
    path = new URL(String(operation.request.url)).pathname;
  } catch {
    return false;
  }
  if (AMBIGUOUS.test(path)) return false;
  return constraints.paths.some((prefix) => under(path, prefix));
}
