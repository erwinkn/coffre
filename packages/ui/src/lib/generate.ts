/**
 * What the Generate dialog checks of the names it saves a key pair under.
 * The values themselves, and their recipes, are `@coffre/core/recipe`'s,
 * which the CLI makes them by too.
 */
import { secretKeyProblem } from './validation.ts';

/** What stops a key pair's two names from being saved, if anything. */
export function pairNameProblem(privateName: string, publicName: string): string | null {
  const names = [privateName.trim(), publicName.trim()];
  if (names.includes('')) return 'Give each key a name.';
  for (const name of names) {
    const problem = secretKeyProblem(name);
    if (problem !== null) return `${name}: ${problem}`;
  }
  return names[0] === names[1] ? 'The two keys need different names.' : null;
}
