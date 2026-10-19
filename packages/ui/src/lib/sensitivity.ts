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

/**
 * The levels a value may be written at: in a personal config, a secret or
 * sensitive, never plain, which is read without the vault that binds its
 * values to their owner (R8); only its owner lists one anyway.
 */
export function levelsIn(personal: boolean): readonly Sensitivity[] {
  return personal ? SENSITIVITIES.filter((level) => level !== 'plain') : SENSITIVITIES;
}

/** Each level as the page names it, and who it lets see the value. */
export const LEVELS: Record<Sensitivity, { label: string; hint: string }> = {
  plain: { label: 'Plain', hint: 'Visible to anyone who can see this environment' },
  secret: { label: 'Secret', hint: 'Visible to people whose role can read secrets' },
  sensitive: { label: 'Sensitive', hint: 'Never shown to anyone, Owners included. Used through the proxy or by services' },
};

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
