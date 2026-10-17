import type { SecretKey } from '@coffre/client';
import { describeRecipe, parseRecipe, recipeProblem, type Generation } from '@coffre/core/recipe';

import { Generate } from './icons';
import { ConfirmDialog, Tip } from './ui';

/** What a generated key's recipe makes, in words; null for one this page does not know. */
export function recipeInWords(generated: Generation): string | null {
  return recipeProblem(generated.recipe) === null ? describeRecipe(parseRecipe(generated.recipe)) : null;
}

/** Beside a key whose value was generated: how, on hover or focus. */
export function RecipeMark({ generated }: { generated: Generation }) {
  const label = `Generated: ${recipeInWords(generated) ?? generated.recipe}`;
  return (
    <Tip label={label}>
      <span className="recipe-mark" tabIndex={0} role="img" aria-label={label}>
        <Generate size={12} />
      </span>
    </Tip>
  );
}

/** The keys regenerating a key writes: itself, or a key pair's two halves. */
export function regeneratedKeys(key: string, generated: Generation): string[] {
  return generated.pair === undefined ? [key] : [generated.pair.private, generated.pair.public];
}

/**
 * Asks before regenerating a key by its recipe (`regenerateWrite`, which
 * the row runs on confirm): a new value made in this browser, written as
 * its next version, and never shown. A key pair's either half makes the
 * pair again, both keys in one write, in the environment the page is on.
 */
export function RegenerateSecret({
  open,
  onOpenChange,
  place,
  entry,
  generated,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** `project/environment`, where it is written. */
  place: string;
  entry: SecretKey;
  generated: Generation;
  onConfirm: () => void;
}) {
  const made = recipeInWords(generated);
  const body =
    generated.pair === undefined
      ? `A new value, ${made ?? generated.recipe}, is made in this browser and saved as v${(entry.version ?? 0) + 1}. Nobody sees it; whatever reads ${place} gets it from now on.`
      : `A new key pair is made in this browser and saved as ${generated.pair.private} and ${generated.pair.public}, together. Nobody sees it; whatever reads ${place} gets both from now on.`;
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={
        <>
          Regenerate <span className="mono">{entry.key}</span>
          {generated.pair !== undefined && ' and its pair'}?
        </>
      }
      body={body}
      detail={
        <p className="hint">
          Recipe <span className="mono">{generated.recipe}</span>
          {generated.pair !== undefined && made !== null && <>: {made}</>}
        </p>
      }
      confirmLabel="Regenerate"
      onConfirm={onConfirm}
    />
  );
}
