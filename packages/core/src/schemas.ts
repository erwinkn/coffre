import { z } from 'zod';

import { INSTANCE_ROLE_NAMES, ROLE_ID, ROLE_ID_RULE, type InstanceRole } from './access.ts';
import { PROJECT_PAGES } from './pages.ts';

export const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
/**
 * Your personal config of an environment, in a path: `market/dev@me`
 * (docs/design/forking.md). A read falls back to `market/dev` when you have
 * none; a write never does.
 */
export const PERSONAL_SUFFIX = '@me';

/** `dev@me` as the environment it is a personal config of, `dev`; null for any other slug. */
export function personalOf(environment: string): string | null {
  return environment.endsWith(PERSONAL_SUFFIX) ? environment.slice(0, -PERSONAL_SUFFIX.length) : null;
}

/** An environment as a path names it: a slug, or `<slug>@me` for your personal config of it. */
export const environmentPath = z.string().refine((value) => slug.safeParse(personalOf(value) ?? value).success, 'not a valid environment');

/** An environment's slug: any slug but the name of one of its project's pages. */
export const environmentSlug = slug.refine((value) => !(PROJECT_PAGES as readonly string[]).includes(value), {
  error: (issue) => `"${String(issue.input)}" is taken by a project's page, /projects/<project>/${String(issue.input)}: an environment cannot have it`,
});

/**
 * A deleted project or environment keeps its row as a tombstone, under a
 * slug no live place can hold: `market~deleted-2026-10-05`. The `~` is the
 * whole rule: a place is deleted when its slug, or its project's, holds one.
 * `@coffre/db/dialect`'s `tombstone()` is the same rule in SQL.
 */
export const TOMBSTONE = '~';

export function isTombstone(slug: string): boolean {
  return slug.includes(TOMBSTONE);
}

/** The slug a place deleted on `day` keeps: the `n`th that day is `market~deleted-2026-10-05-<n>`. */
export function tombstoneOf(slug: string, day: Date, n = 1): string {
  const base = `${slug}${TOMBSTONE}deleted-${day.toISOString().slice(0, 10)}`;
  return n === 1 ? base : `${base}-${n}`;
}

/**
 * The slug an environment deleted with its project keeps, with 0.15's log:
 * `dev~deleted`, undated. Its project is deleted once, so within it no other
 * environment holds it, and an environment deleted alone holds a dated one.
 * The project's tombstone dates both; its old path still names it,
 * `market~deleted-2026-10-05/dev` (`resolvePath`'s `tombstones`).
 */
export function deletedWithProject(slug: string): string {
  return `${slug}${TOMBSTONE}deleted`;
}
/** A name for people to read, such as a place's label from before 0.6.2: anything but blank. */
export const displayName = z.string().trim().min(1);
/** A folder: 1 to 64 characters, no `/`, no control character, no space at either end (the tables check it too). */
export const folderName = z.string().min(1).max(64)
  .refine((name) => name === name.trim(), 'a folder name cannot start or end with a space')
  .refine((name) => !/[/\p{Cc}]/u.test(name), 'a folder name cannot hold "/" or a control character');
export const secretKey = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);

/**
 * The most a secret's value may be, in bytes of UTF-8: 64 KiB. `coffre run`
 * hands each value to its command as an environment variable, and Linux
 * holds each such string, `NAME=value` and its NUL, to `MAX_ARG_STRLEN`,
 * 32 pages, 128 KiB on 4 KiB pages (execve(2), "Limits on size of arguments
 * and environment"; `include/uapi/linux/binfmts.h`), else the command does
 * not start (`E2BIG`). Half of that, so the name (at most 128 bytes,
 * `secretKey`) always fits beside it (W331, 2026-11-06).
 */
export const MAX_VALUE_BYTES = 64 * 1024;

/**
 * A member as people read it, in a message or on a page: a service account
 * as `service:<name>`, though the API, the vault and the log keep the
 * `token:<name>` their signed entries hold.
 */
export function shownMember(member: string): string {
  return member.startsWith('token:') ? `service:${member.slice('token:'.length)}` : member;
}

export const principalType = z.enum(['user', 'service']);
/** At most 320 characters: an email address's longest, its local part's 64 and its domain's 255 (RFC 5321, section 4.5.3.1). */
export const principalId = z.string().trim().min(1).max(320);
export const instanceRole = z.enum(INSTANCE_ROLE_NAMES as [InstanceRole, ...InstanceRole[]]);

/** A project role's id: one coffre ships, or one an Owner made (`ROLE_ID`). Which the instance defines, its policy says. */
export const roleId = z.string().regex(ROLE_ID, ROLE_ID_RULE);

/** Which projects or environments a scope takes in, by slug: `all`, `{ only: [...] }` or `{ except: [...] }`. */
export const scopeFilter = z.union([
  z.literal('all'),
  z.object({ only: z.array(slug) }).strict(),
  z.object({ except: z.array(slug).min(1) }).strict(),
]);

/** Where an instance role applies, as the API takes it: either filter left out is `all`. */
export const scopeInput = z.object({ projects: scopeFilter.optional(), environments: scopeFilter.optional() }).strict();
export const grantId = z.string().uuid();
/** As `principalId`: 320 characters at most (RFC 5321, section 4.5.3.1). */
export const emailAddress = z.string().email().max(320);

/**
 * The most an API request body may be, read as it streams and abandoned
 * past this (413), at every route the app answers once its caller has a
 * credential (the API, MCP's endpoint); before sign-in, `SIGN_IN_BODY_BYTES`:
 * a control-plane request, a bulk secret write its largest. Workers gives an isolate 128 MB
 * (https://developers.cloudflare.com/workers/platform/limits/, "Memory"); a
 * body takes about 5 MiB of it while it is read, 4% at most: its chunks and
 * their one copy (2 MiB), its text (up to 2 MiB, two bytes a character past
 * Latin-1) and its parsed value, which `MAX_BODY_NODES` holds to about its
 * size (`packages/server/scripts/body-cost.ts`: 1.0 times, where a mebibyte
 * of tiny entries or nesting, parsed, would hold 8 to 28). Uses carry no
 * body, and an isolate serves a few control-plane requests at once. An `.env` of a
 * thousand keys is a few dozen kilobytes.
 */
export const API_BODY_BYTES = 1024 * 1024;

/**
 * A request's CPU at p99, in microseconds: R27's 20 ms, under which every
 * request stays, so that a body, refused or not, costs no more before its
 * route runs.
 */
export const REQUEST_CPU_US = 20_000;

/**
 * Reading the largest body at worst, in microseconds: counting its values
 * (`countValues`), then `JSON.parse` of one that passes, a mebibyte of
 * strings its costliest, 2.6 to 3.9 ms; a body refused by the count costs
 * 0.1 ms (`packages/server/scripts/body-cost.ts`, Node 24, the machine
 * named below).
 */
export const READ_CPU_US = 4_000;

/**
 * Validation's CPU per body value, at worst, in microseconds:
 * `@coffre/server`'s `check` with every route's schema, on bodies of
 * `MAX_BODY_NODES` values in the costliest shapes, alone and under every
 * field a route reads a map or a list from
 * (`packages/server/scripts/body-cost.ts`: Node 24.22 on a 96-core Linux
 * host at a load of 15, the thread's own CPU, the median of five; with zod's
 * eval-built
 * fast paths and without, as on Workers, which forbids eval). The worst is a
 * secret write whose every entry fails its six-way union, 7.7 to 9.4 µs a
 * value over six runs, taken as 10; every other route is under 5. Through
 * zod's own `safeParse`, which builds every issue's message and a JSON of
 * them all, the same body cost 18 to 21.
 */
export const VALUE_CPU_US = 10;

/**
 * The most values a request body may hold, counted over the whole tree
 * (every object entry, array element and leaf) before it is parsed: what is
 * left of a request's CPU once the largest body is read, at validation's
 * worst cost per value (1,600). A bulk write of plain values is one per key
 * and its root: an `.env` of 1,599 keys fits, a larger one is written in
 * parts. The CBOR a passkey's response carries in its strings decodes under
 * the same count, on its own (`CeremonyExpectation.values`).
 */
export const MAX_BODY_NODES = Math.floor((REQUEST_CPU_US - READ_CPU_US) / VALUE_CPU_US);

/**
 * At most this many keys in a set, fetched or uploaded: a bound on a CI
 * sign-in's work, not on a field. A token that names no key, or one several
 * share, is tried against each (`@coffre/core/identity`'s `anyKey`), so it
 * sets, with the token's size, what a stranger's sign-in costs
 * (`SIGN_IN_BODY_BYTES`).
 */
export const MAX_KEYS = 32;

/**
 * A key tried against a workload token that does not verify, in
 * microseconds of CPU, beside the token's bytes: jose's `jwtVerify`, the key
 * imported from its JWK, the signature checked and failed. Fitted with
 * `TOKEN_BYTE_CPU_NS` over tokens of 1 to 32 KiB, the range the bound is
 * chosen in: 203 to 257 µs for ES256 and 81 to 185 for RS256 over nine runs
 * (`SIGN_IN_BODY_BYTES` names the host), taken as the dearest, rounded up.
 */
export const KEY_TRY_CPU_US = 260;

/**
 * Each byte of a workload token, per key tried, in nanoseconds of CPU: each
 * signature check encodes and hashes the token whole again, its one
 * decoding spread over the tries. Fitted over 1 to 32 KiB: 6 to 13.5 over
 * nine runs, ES256 and RS256 alike, taken as the dearest, rounded up: a try
 * costs more than linearly near 32 KiB (twice as much at 64 KiB as at 32).
 */
export const TOKEN_BYTE_CPU_NS = 14;

/**
 * The most a body sent before sign-in may be, in bytes, read as it streams
 * and refused past this with a 413 before it is read whole: a device login's
 * start and poll, a CI run's or a workload's exchange (its ID token, AWS
 * proof or enrollment code), a passkey's answer, and MCP's OAuth token,
 * revocation and registration. Anyone may send one, and the costliest it
 * can make the app do, per byte, is a workload token that names no key,
 * tried against each of `MAX_KEYS` keys: `MAX_KEYS × (KEY_TRY_CPU_US +
 * TOKEN_BYTE_CPU_NS × B)` within what a request has left once a body is read
 * (`REQUEST_CPU_US − READ_CPU_US`, 16 ms) gives B ≤ 17.1 kB, so 16 KiB, the
 * power of two below. Measured directly, 32 tries of a token of 16 KiB cost
 * 9.7 to 12.0 ms (ES256) and 7.1 to 10.1 (RS256); of 32 KiB, 10.3 to 21.4,
 * past the 16 ms in a third of the runs. 16 KiB was the exchanges' and MCP's
 * OAuth bound before this change, so every body that signed in still fits: a
 * GitHub Actions ID token is about 1.2 kB, a passkey's answer under 1 kB,
 * an AWS proof a few kB with its session token.
 *
 * Every other thing a stranger's body makes the app do costs less
 * (`packages/server/scripts/sign-in-cost.ts`, Node 24.22, jose 6.2, a 96-core
 * Linux host at loads of 33 to 57, 2026-11-07, the process's CPU, the median
 * of nine samples, with zod's eval-built fast paths and without): a passkey's
 * answer, verified, 71 to 77 ns a byte (1.1 to 1.3 ms at 16 KiB); a form of
 * `+` or of short distinct fields, read and checked for a name given twice,
 * 10 to 26 ns (at most 0.6 ms); the body's count, parse and validation, under
 * 6 ns (0.1 ms); and claim matching, once a token verifies, against GitHub's,
 * GitLab's and Kubernetes' bindings and one of five-dot names, every split of
 * each present in the token, 20 to 30 µs whatever its size.
 */
export const SIGN_IN_BODY_BYTES =
  1024 * 2 ** Math.floor(Math.log2(((REQUEST_CPU_US - READ_CPU_US - MAX_KEYS * KEY_TRY_CPU_US) * 1000) / (MAX_KEYS * TOKEN_BYTE_CPU_NS) / 1024));

/**
 * How many values a JSON text holds, counted as `JSON.parse` would make
 * them but without making any: the root, each array element and each object
 * entry, a key and its value together (`{"a":[1,2]}` is 4). One pass over
 * the characters, strings skipped whole, and it stops once past `cap`. A
 * value starts at the first character after `[`, `{` or `,` that is not
 * space and does not close a container, whatever the container is, so no
 * stack is kept. Text that is not JSON may count otherwise; `JSON.parse`
 * refuses it after.
 */
export function countValues(text: string, cap = Infinity): number {
  let count = 1;
  let expecting = false;
  for (let i = 0; i < text.length && count <= cap; i += 1) {
    const c = text.charCodeAt(i);
    // Space, tab, line feed, carriage return: JSON's whitespace, which neither starts nor ends a value.
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) continue;
    if (expecting) {
      expecting = false;
      if (c !== 0x5d && c !== 0x7d) count += 1;
    }
    if (c === 0x5b || c === 0x7b || c === 0x2c) expecting = true;
    else if (c === 0x22) {
      for (i += 1; i < text.length; i += 1) {
        const d = text.charCodeAt(i);
        if (d === 0x5c) i += 1;
        else if (d === 0x22) break;
      }
    }
  }
  return count;
}

/**
 * `text` split on `separator`, or null when it holds more than `max` parts:
 * its separators counted first, by index, and nothing split past the count.
 * A string a request turns into a list holds no more items than a body may
 * hold values (`MAX_BODY_NODES`), or than the list's own shape takes (a path
 * of three parts, a sealed state of two), so one field of a mebibyte of
 * separators costs a count, never a million parts (about 13 ns each).
 */
export function splitAtMost(text: string, separator: string, max: number = MAX_BODY_NODES): string[] | null {
  let parts = 1;
  for (let at = text.indexOf(separator); at !== -1; at = text.indexOf(separator, at + separator.length)) {
    parts += 1;
    if (parts > max) return null;
  }
  return text.split(separator);
}
