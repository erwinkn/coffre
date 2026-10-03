import { badRequest } from './errors.ts';

export type { ResolvedPath } from '../db/queries.ts';

/** `market`, `market/prod` or `market/prod/DATABASE_URL`. */
export type Path = { project: string; environment?: string; key?: string };

/** Split `market/prod/KEY`; the depth says what it names. */
export function parsePath(path: string, depths: readonly (1 | 2 | 3)[] = [1, 2, 3]): Path {
  const parts = path.trim().replace(/^\/+|\/+$/g, '').split('/');
  if (parts.some((part) => part === '') || !depths.includes(parts.length as 1 | 2 | 3)) {
    const shapes = { 1: 'project', 2: 'project/environment', 3: 'project/environment/KEY' };
    throw badRequest(`name a ${depths.map((depth) => shapes[depth]).join(' or ')}`);
  }
  const [project, environment, key] = parts;
  return { project, environment, key };
}

export function formatPath(path: Path): string {
  return [path.project, path.environment, path.key].filter((part) => part !== undefined).join('/');
}

/** A member as written in a URL: `user:ada@acme.example` or `token:ci-deploy`. */
export type MemberRef = { type: 'user' | 'service'; id: string };

export function parseMember(member: string): MemberRef {
  const colon = member.indexOf(':');
  const prefix = member.slice(0, colon);
  const id = member.slice(colon + 1);
  if (colon < 1 || id === '' || (prefix !== 'user' && prefix !== 'token')) {
    throw badRequest('name a member as user:<email> or token:<name>');
  }
  // Emails are stored lowercase, so `user:Ada@…` and `user:ada@…` are one person.
  return prefix === 'user' ? { type: 'user', id: id.toLowerCase() } : { type: 'service', id };
}

export function formatMember(member: MemberRef): string {
  return `${member.type === 'user' ? 'user' : 'token'}:${member.id}`;
}

/** Grants name the same people and services as membership. */
export type GranteeRef = MemberRef;
export const parseGrantee = parseMember;
export const formatGrantee = formatMember;
