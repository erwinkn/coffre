/**
 * Client-side hints for the two identifier shapes people type.
 *
 * The server validates with the zod schemas in `shared/schemas.ts` and stays
 * the authority; these only let a form say what is wrong before a round trip.
 * They are plain patterns rather than imports of those schemas so the browser
 * bundle does not carry zod, and `test/validation.test.ts` holds the two in
 * agreement.
 */

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const SECRET_KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

export function slugProblem(value: string): string | null {
  if (SLUG.test(value)) return null;
  if (value.length > 63) return 'At most 63 characters.';
  if (/[A-Z]/.test(value)) return 'Lowercase only.';
  if (value.startsWith('-')) return 'Start with a letter or digit.';
  return 'Lowercase letters, digits and dashes only.';
}

export function secretKeyProblem(value: string): string | null {
  if (SECRET_KEY.test(value)) return null;
  if (value.length > 128) return 'At most 128 characters.';
  if (/^[0-9]/.test(value)) return 'Cannot start with a digit.';
  return 'Letters, digits and underscores only.';
}
