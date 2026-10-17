/**
 * Values the CLI makes for `coffre set --generate` and `coffre regenerate`:
 * made here, with the platform's CSPRNG, by the recipe the pages use too
 * (`@coffre/core/recipe`), and sent with it, so the next one is made the
 * same way. Nothing here prints a value: what is said is the recipe, the
 * keys and their versions.
 */
import { describeRecipe, generateWrite, parseRecipe, publicKeyName, regenerateWrite, type Generation, type GeneratedWrite, type Recipe } from '@coffre/core/recipe';

import { UsageError } from './manage.ts';

/** A key's name, as the server takes it: `secretKey` in `@coffre/core/schemas`, without loading zod here. */
const KEY_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/** A listed key, as far as regenerating it goes; an instance before 0.7 says nothing of `generated`. */
export type Listed = { key: string; archived: boolean; version: number | null; generated?: Generation | null };

/** The recipe `--generate` names, or a usage error that says the syntax. */
export function recipeFlag(text: string): Recipe {
  try {
    return parseRecipe(text);
  } catch (error) {
    throw new UsageError(`--generate: ${(error as Error).message}`);
  }
}

/**
 * The patch that writes a value made by the recipe to `key`, and for a key
 * pair its public key to `publicKey`, or the name it follows from the
 * private key's: `JWT_PRIVATE_KEY` gives `JWT_PUBLIC_KEY`.
 */
export async function generatedPatch(key: string, recipe: Recipe, publicKey?: string): Promise<GeneratedWrite> {
  if (recipe.kind !== 'pair') {
    if (publicKey !== undefined) throw new UsageError(`--public-key names a key pair's public key, and this recipe makes one value`);
    return generateWrite(key, recipe);
  }
  const publicName = publicKey ?? publicKeyName(key);
  if (!KEY_NAME.test(publicName)) throw new UsageError(`--public-key: "${publicName}" is no key name: letters, digits and underscores`);
  if (publicName === key) throw new UsageError(`a key pair's two keys need different names: --public-key names the other`);
  return generateWrite(key, recipe, publicName);
}

/**
 * What regenerating `key` writes, from its environment's listing: a new
 * value by its recipe, and for a key pair's either half, the pair whole,
 * under the names it has now. A key with no recipe says how it gets one:
 * a plain error, as the key is what is wrong, not the command.
 */
export async function regeneratedPatch(path: string, key: string, listed: readonly Listed[]): Promise<GeneratedWrite> {
  const entry = listed.find((each) => each.key === key);
  if (entry === undefined) throw new Error(`${path} has no key ${key}`);
  if (entry.archived) throw new Error(`${path}/${key} is archived: unarchive it before regenerating it`);
  if (entry.generated === undefined) {
    throw new Error(`this instance is older than recipes (coffre 0.7) and keeps none to regenerate by: upgrade it`);
  }
  if (entry.generated === null) {
    throw new Error(
      `${path}/${key} has no recipe: its value was typed, or written by hand since it was generated. ` +
        `\`coffre set ${path}/${key} --generate <recipe>\` gives it one`,
    );
  }
  // Each key replaces the version listed, or the server refuses it: renamed or written since, it is not the one to regenerate.
  return regenerateWrite(key, entry.generated, (name) => listed.find((each) => each.key === name && !each.archived)?.version ?? null);
}

/**
 * What a generated write says, a line per key: its version and how it was
 * made, never its value. `{ JWT_PRIVATE_KEY: 3, JWT_PUBLIC_KEY: 3 }` for a
 * pair says which half each holds.
 */
export function generatedLines(patch: GeneratedWrite, versions: Record<string, number | null>, verb: string): string[] {
  return Object.entries(patch).map(([key, { generated }]) => {
    const version = versions[key] ?? '?';
    const recipe = parseRecipe(generated.recipe);
    if (recipe.kind !== 'pair' || generated.pair === undefined) {
      return `${key} ${verb} as version ${version}: ${describeRecipe(recipe)} (${generated.recipe})`;
    }
    const [half, other] = key === generated.pair.private ? ['private', generated.pair.public] : ['public', generated.pair.private];
    return `${key} ${verb} as version ${version}: the ${half} key of a new ${recipe.algorithm} ${recipe.curve} pair with ${other} (${generated.recipe})`;
  });
}
