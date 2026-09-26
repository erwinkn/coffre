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
  { email: 'erwin@equisafe.io', name: 'Erwin Kuhn', note: 'root admin' },
  { email: 'lead@equisafe.io', name: 'Lea Lead', note: 'owner' },
  { email: 'dev@equisafe.io', name: 'Devon Dev', note: 'developer on dev' },
  { email: 'auditor@equisafe.io', name: 'Audrey Auditor', note: 'auditor' },
  { email: 'accessmgr@equisafe.io', name: 'Max Access', note: 'access manager' },
  { email: 'outsider@equisafe.io', name: 'Otto Outsider', note: 'registered, no grants' },
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
