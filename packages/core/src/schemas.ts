import { z } from 'zod';

import { INSTANCE_ROLE_NAMES, type InstanceRole } from './access.ts';
import { PROJECT_PAGES } from './pages.ts';

export const slug = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
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
export const displayName = z.string().trim().min(1).max(120);
/** A folder: 1 to 64 characters, no `/`, no control character, no space at either end (the tables check it too). */
export const folderName = z.string().min(1).max(64)
  .refine((name) => name === name.trim(), 'a folder name cannot start or end with a space')
  .refine((name) => !/[/\p{Cc}]/u.test(name), 'a folder name cannot hold "/" or a control character');
export const secretKey = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);
/**
 * A member as people read it, in a message or on a page: a service account
 * as `service:<name>`, though the API, the vault and the log keep the
 * `token:<name>` their signed entries hold.
 */
export function shownMember(member: string): string {
  return member.startsWith('token:') ? `service:${member.slice('token:'.length)}` : member;
}

export const principalType = z.enum(['user', 'service']);
export const principalId = z.string().trim().min(1).max(320);
export const instanceRole = z.enum(INSTANCE_ROLE_NAMES as [InstanceRole, ...InstanceRole[]]);

/** Which projects or environments a scope takes in, by slug: `all`, `{ only: [...] }` or `{ except: [...] }`. */
export const scopeFilter = z.union([
  z.literal('all'),
  z.object({ only: z.array(slug).max(200) }).strict(),
  z.object({ except: z.array(slug).min(1).max(200) }).strict(),
]);

/** Where an instance role applies, as the API takes it: either filter left out is `all`. */
export const scopeInput = z.object({ projects: scopeFilter.optional(), environments: scopeFilter.optional() }).strict();
export const grantId = z.string().uuid();
export const emailAddress = z.string().email().max(320);
