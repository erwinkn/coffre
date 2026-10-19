import type { SecretKey, Sensitivity } from '../shared/models.ts';
import type { SecretChange } from './secret-edit-batch.ts';

/**
 * Who sees a key's value, loosest first: `plain`, whoever lists its
 * environment; `secret`, the default, people whose role reads secrets;
 * `sensitive`, no person, Owners included, while their apps use it through
 * the credential proxy and service accounts read it. A key is made
 * stricter with its value kept; looser only with its value typed again, so
 * nobody shows a value by flipping it.
 */
export const SENSITIVITIES = ['plain', 'secret', 'sensitive'] as const satisfies readonly Sensitivity[];

/** Each level as the page names it, and who it lets see the value. */
export const LEVELS: Record<Sensitivity, { label: string; hint: string }> = {
  plain: { label: 'Plain', hint: 'Visible to anyone who can see this environment' },
  secret: { label: 'Secret', hint: 'Visible to people whose role can read secrets' },
  sensitive: { label: 'Sensitive', hint: 'Never shown to anyone, Owners included. Used through the proxy or by services' },
};

/** The levels in your personal config, `dev@me`, whose values nobody else sees, whatever their level. */
const PERSONAL_LEVELS: Record<Sensitivity, { label: string; hint: string }> = {
  plain: { label: 'Plain', hint: 'Visible to you alone, as it is' },
  secret: { label: 'Secret', hint: 'Visible to you alone, when you reveal it' },
  sensitive: { label: 'Sensitive', hint: 'Never shown, you included. Your app uses it through the proxy' },
};

/** Each level as a page names it, in your personal config or elsewhere. */
export function levelsIn(personal: boolean): Record<Sensitivity, { label: string; hint: string }> {
  return personal ? PERSONAL_LEVELS : LEVELS;
}

/** Whether `a` lets fewer people see a value than `b`. */
export function stricter(a: Sensitivity, b: Sensitivity): boolean {
  return SENSITIVITIES.indexOf(a) > SENSITIVITIES.indexOf(b);
}

/** A key's own value, which a mark makes stricter in place: not a reference's, nor one a fork inherits. */
export function markable(entry: SecretKey): boolean {
  return entry.sensitivity !== null && entry.reference === null && (entry.parent === null || entry.parent.state === 'overridden');
}

/**
 * Whether a change of who sees a key waits for its value typed: looser
 * than the key is, or where it has no value of its own to mark.
 */
export function waitsForValue(entry: SecretKey, change: SecretChange | undefined): boolean {
  if (change === undefined || change.archived || change.value !== null || change.sensitivity === undefined) return false;
  return !markable(entry) || stricter(entry.sensitivity!, change.sensitivity);
}
