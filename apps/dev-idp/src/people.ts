import { createHash } from 'node:crypto';

export interface Persona {
  email: string;
  name: string;
  /** What the seed grants them, shown on the sign-in page. */
  note: string;
}

/**
 * The people the sign-in pages offer. Mirrors the users in
 * `scripts/seed-config.mjs` (a test keeps the two in step), so each button
 * lands on a seeded account.
 */
export const PERSONAS: readonly Persona[] = Object.freeze([
  { email: 'admin@acme.example', name: 'Ada Admin', note: 'root admin' },
  { email: 'lead@acme.example', name: 'Lea Lead', note: 'owner' },
  { email: 'dev@acme.example', name: 'Devon Dev', note: 'developer on dev' },
  { email: 'auditor@acme.example', name: 'Audrey Auditor', note: 'auditor' },
  { email: 'accessmgr@acme.example', name: 'Max Access', note: 'access manager' },
  { email: 'outsider@acme.example', name: 'Otto Outsider', note: 'registered, no grants' },
]);

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Stable for an email but deliberately not the email, the way real providers
 * key accounts: a client that binds to `sub` survives an address changing
 * hands, one that binds to `email` does not.
 */
export function defaultSubject(email: string): string {
  return `dev-${sha256Hex(email).slice(0, 24)}`;
}

export function displayName(email: string): string {
  const persona = PERSONAS.find((p) => p.email === email);
  if (persona) return persona.name;
  const local = email.split('@')[0]!;
  return local.charAt(0).toUpperCase() + local.slice(1);
}

export interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: 'public' | 'private' | null;
}

export interface GitHubAccount {
  id: number;
  login: string;
  name: string;
  emails: GitHubEmail[];
  /** Organizations the account is an active member of. */
  orgs: string[];
}

export interface GitHubAccountPatch {
  id?: number;
  login?: string;
  name?: string;
  /** Replaces the list. The first is primary unless one says so; all verified unless they say not. */
  emails?: ReadonlyArray<{ email: string } & Partial<Omit<GitHubEmail, 'email'>>>;
  orgs?: readonly string[];
}

/**
 * Outsider's GitHub account also lists lead's address, unverified: a client
 * that trusts unverified emails signs Otto in as Lea.
 */
const UNVERIFIED_GITHUB_EMAILS: Readonly<Record<string, readonly string[]>> = {
  'outsider@acme.example': ['lead@acme.example'],
};

export function gitHubEmails(list: NonNullable<GitHubAccountPatch['emails']>): GitHubEmail[] {
  const primary = Math.max(0, list.findIndex((e) => e.primary));
  return list.map((e, i) => ({
    email: normalizeEmail(e.email),
    primary: i === primary,
    verified: e.verified ?? true,
    visibility: e.visibility !== undefined ? e.visibility : i === primary ? 'public' : null,
  }));
}

/** Stable per email, so a persona keeps its numeric id across runs. */
export function defaultGitHubAccount(email: string): GitHubAccount {
  const unverified = UNVERIFIED_GITHUB_EMAILS[email] ?? [];
  return {
    id: 1_000_000 + Number.parseInt(sha256Hex(`github:${email}`).slice(0, 7), 16),
    login: email.split('@')[0]!.replace(/[^A-Za-z0-9-]/g, '-'),
    name: displayName(email),
    emails: gitHubEmails([{ email }, ...unverified.map((e) => ({ email: e, verified: false }))]),
    orgs: ['acme'],
  };
}
