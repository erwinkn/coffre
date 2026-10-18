import type { Generation } from '@coffre/core/recipe';
import type { Sensitivity } from '../shared/models.ts';
import { stricter } from './sensitivity.ts';

/**
 * A second secret a row writes with its own value, in the same patch: a
 * generated key pair's public key, beside its private key. It is part of
 * the row's edit, so saving, undoing or retrying the row takes both. It is
 * written at its own level, not its row's (`companionLevel`): `sensitivity`
 * where the user chose one.
 */
export type Companion = { key: string; value: string; sensitivity?: 'secret' | 'sensitive' };

export type SecretDraft = {
  id: number;
  key: string;
  value: string;
  companion?: Companion;
  /** The recipe a generated value was made by, saved with it; typing over the value drops it. */
  recipe?: string;
  /** Who sees it (`lib/sensitivity.ts`). */
  sensitivity: Sensitivity;
};

export type SecretChange = {
  key: string;
  value: string | null;
  archived: boolean;
  /** Only beside a new value. */
  companion?: Companion;
  /** Only beside a generated value. */
  recipe?: string;
  /**
   * Who sees the key's value once saved: beside a new value, that value's
   * level; alone, a mark, the current value made stricter and kept (`valueEdit`).
   */
  sensitivity?: Sensitivity;
};

/**
 * What an edit of a row's value, and of who sees it, makes of its change,
 * from where it started: `from.start`, the value the editor opened on (''
 * when it could not be read), and `from.level`, who sees the row's value
 * now (null for none of its own: a secret is written). A value left as it
 * opened writes nothing; its level changed alone is then a mark. Looser
 * than the row, the field opens empty, as that takes the value typed again:
 * a stored value is never made more visible by a flip. Back where it
 * started, it is no change.
 *
 *   secret 'sk_1', opened on 'sk_1': Sensitive  -> { value: null, sensitivity: 'sensitive' }, a mark
 *   secret 'sk_1', opened on 'sk_1': Plain      -> { value: null, sensitivity: 'plain' }, waiting for a value
 *                  then 'sk_2' typed            -> { value: 'sk_2', sensitivity: 'plain' }
 */
export function valueEdit(
  from: { start: string; level: Sensitivity | null },
  next: { value: string | null; sensitivity: Sensitivity },
): Pick<SecretChange, 'value' | 'sensitivity'> {
  const level = from.level ?? 'secret';
  const opened = stricter(level, next.sensitivity) ? '' : from.start;
  const value = next.value === opened ? null : next.value;
  return { value, sensitivity: value === null && next.sensitivity === level ? undefined : next.sensitivity };
}

/** A listed key, and who sees its value now (null for none of its own). */
type ActiveSecret = { key: string; sensitivity?: Sensitivity | null };

/**
 * A merge patch: a value sets a key with who sees it, adding it if it is
 * new; a value with how it was generated sets it with its recipe; a level
 * alone makes the key's value stricter, kept; `null` archives it.
 */
export type SecretPatch = Record<
  string,
  | { value: string; sensitivity: Sensitivity }
  | { value: string; generated: Generation; sensitivity: 'secret' | 'sensitive' }
  | { sensitivity: Sensitivity }
  | null
>;

/**
 * How a row's generated value was made, as its write says it: its recipe,
 * and for a key pair the names both halves are saved under.
 */
function generationOf(key: string, edit: { recipe?: string; companion?: Companion }): Generation | undefined {
  if (edit.recipe === undefined) return undefined;
  return edit.companion === undefined
    ? { recipe: edit.recipe }
    : { recipe: edit.recipe, pair: { private: key, public: edit.companion.key.trim() } };
}

type ValueEdit = { recipe?: string; companion?: Companion; sensitivity?: Sensitivity };

/** Who sees the value a row writes: a secret unless it says, and a generated one never plain. */
function levelOf(edit: ValueEdit): 'secret' | 'sensitive' | 'plain' {
  return edit.sensitivity === 'sensitive' || (edit.sensitivity === 'plain' && edit.recipe === undefined) ? edit.sensitivity : 'secret';
}

/**
 * Who sees each listed key's value now, by its name after the save: a
 * renamed key keeps its level under its new name; an archived one is gone.
 */
function levelsNow(
  active: readonly ActiveSecret[],
  changes: Readonly<Record<string, SecretChange>>,
): Map<string, Sensitivity | null> {
  const out = new Map<string, Sensitivity | null>();
  for (const entry of active) {
    const change = secretChangeFor(changes, entry.key);
    if (change?.archived) continue;
    out.set(change?.key.trim() ?? entry.key, entry.sensitivity ?? null);
  }
  return out;
}

/**
 * Who sees the public key a pair writes: who the user chose, else who sees
 * the key it writes over now, or a secret, as a generated value is never
 * plain. A public key need not be hidden, so a sensitive private key does
 * not make it sensitive.
 *
 *   PRIVATE_KEY sensitive, PUBLIC_KEY secret  -> PUBLIC_KEY written secret
 *   PRIVATE_KEY secret, PUBLIC_KEY sensitive  -> PUBLIC_KEY written sensitive
 *   PUBLIC_KEY new                            -> secret
 */
function companionLevel(companion: Companion, now: ReadonlyMap<string, Sensitivity | null>): 'secret' | 'sensitive' {
  return companion.sensitivity ?? (now.get(companion.key.trim()) === 'sensitive' ? 'sensitive' : 'secret');
}

/**
 * What a row writes under each key: its value, and its companion's beside
 * it, each saying who sees it, as every write does: over a sensitive key,
 * one that said nothing would stay sensitive.
 */
function rowPatch(key: string, value: string, edit: ValueEdit, now: ReadonlyMap<string, Sensitivity | null>): SecretPatch {
  const generated = generationOf(key, edit);
  const entry = (each: string, sensitivity: Sensitivity) => (generated === undefined || sensitivity === 'plain'
    ? { value: each, sensitivity }
    : { value: each, generated, sensitivity });
  const patch: SecretPatch = Object.create(null);
  patch[key] = entry(value, levelOf(edit));
  if (edit.companion !== undefined) patch[edit.companion.key.trim()] = entry(edit.companion.value, companionLevel(edit.companion, now));
  return patch;
}

/**
 * The one merge patch a save writes, by each key's name after its renames:
 * every value with its companion, every mark and every archive. An edit
 * whose key went from the list writes nothing.
 */
function patchOf(
  active: readonly ActiveSecret[],
  drafts: readonly SecretDraft[],
  changes: Readonly<Record<string, SecretChange>>,
): SecretPatch {
  const now = levelsNow(active, changes);
  // A key named `__proto__` is a key like any other.
  const patch: SecretPatch = Object.create(null);
  for (const entry of active) {
    const change = secretChangeFor(changes, entry.key);
    if (change === undefined) continue;
    const key = change.key.trim();
    if (change.archived) patch[entry.key] = null;
    else if (change.value !== null) Object.assign(patch, rowPatch(key, change.value, change, now));
    else if (change.sensitivity !== undefined) patch[key] = { sensitivity: change.sensitivity };
  }
  for (const draft of drafts) Object.assign(patch, rowPatch(draft.key.trim(), draft.value, draft, now));
  return patch;
}

/**
 * The keys a save makes sensitive, by their names after it: each it writes
 * sensitive, a companion included, that was not sensitive before. Nobody
 * sees them again, so the save asks first.
 */
export function madeSensitive(
  active: readonly ActiveSecret[],
  drafts: readonly SecretDraft[],
  changes: Readonly<Record<string, SecretChange>>,
): string[] {
  const now = levelsNow(active, changes);
  return Object.entries(patchOf(active, drafts, changes))
    .filter(([key, write]) => write !== null && write.sensitivity === 'sensitive' && now.get(key) !== 'sensitive')
    .map(([key]) => key);
}

/**
 * The recipe each key a save writes will hold, by its name after the save:
 * what the list shows of it until it is read back.
 */
export function generationsOf(
  active: readonly ActiveSecret[],
  drafts: readonly SecretDraft[],
  changes: Readonly<Record<string, SecretChange>>,
): Map<string, Generation> {
  const out = new Map<string, Generation>();
  const add = (key: string, edit: { recipe?: string; companion?: Companion }) => {
    const generated = generationOf(key, edit);
    if (generated === undefined) return;
    out.set(key, generated);
    if (edit.companion !== undefined) out.set(edit.companion.key.trim(), generated);
  };
  for (const draft of drafts) add(draft.key.trim(), draft);
  for (const entry of active) {
    const change = secretChangeFor(changes, entry.key);
    if (change !== undefined && !change.archived && change.value !== null) add(change.key.trim(), change);
  }
  return out;
}

/**
 * Who sees each value a save writes, and a plain one's value, by its key's
 * name after the save: what the list shows of it until it is read back.
 */
export function levelsOf(
  active: readonly ActiveSecret[],
  drafts: readonly SecretDraft[],
  changes: Readonly<Record<string, SecretChange>>,
): Map<string, { sensitivity: Sensitivity; value: string | null }> {
  const out = new Map<string, { sensitivity: Sensitivity; value: string | null }>();
  for (const [key, write] of Object.entries(patchOf(active, drafts, changes))) {
    if (write !== null && 'value' in write) out.set(key, { sensitivity: write.sensitivity, value: write.sensitivity === 'plain' ? write.value : null });
  }
  return out;
}

type SecretEditOperations = {
  rename: (key: string, nextKey: string) => Promise<void>;
  /** One transaction: every key in it lands, or none does. */
  write: (patch: SecretPatch) => Promise<void>;
};

type PlannedEdit = { sourceKey: string; change: SecretChange };

export function secretChangeFor(
  changes: Readonly<Record<string, SecretChange>>,
  key: string,
): SecretChange | undefined {
  return Object.hasOwn(changes, key) ? changes[key] : undefined;
}

export type SecretEditBatchResult = {
  applied: number;
  drafts: SecretDraft[];
  changes: Record<string, SecretChange>;
  error: unknown | null;
};

/**
 * The companions a save writes: those of new rows, and of value edits to keys
 * still listed. An edit whose key went from the list (renamed or archived
 * elsewhere, then refreshed) writes nothing, its companion included.
 */
export function companionsOf(
  active: readonly ActiveSecret[],
  drafts: readonly SecretDraft[],
  changes: Readonly<Record<string, SecretChange>>,
): Companion[] {
  return [
    ...drafts.flatMap((draft) => (draft.companion === undefined ? [] : [draft.companion])),
    ...active.flatMap((entry) => {
      const change = secretChangeFor(changes, entry.key);
      return change === undefined || change.archived || change.value === null || change.companion === undefined
        ? []
        : [change.companion];
    }),
  ];
}

/** Return true when one save would give two pending edits the same target. */
export function hasSecretEditConflict(
  active: readonly ActiveSecret[],
  drafts: readonly SecretDraft[],
  changes: Readonly<Record<string, SecretChange>>,
): boolean {
  const finalActiveKeys = active
    .filter((entry) => !secretChangeFor(changes, entry.key)?.archived)
    .map((entry) => secretChangeFor(changes, entry.key)?.key.trim() ?? entry.key);
  if (new Set(finalActiveKeys).size !== finalActiveKeys.length) return true;

  // A companion writes its key as a new row does.
  const draftKeys = [...drafts, ...companionsOf(active, drafts, changes)].map((draft) => draft.key.trim());
  if (new Set(draftKeys).size !== draftKeys.length) return true;

  const valueEditTargets = new Set(
    active.flatMap((entry) => {
      const change = secretChangeFor(changes, entry.key);
      return change !== undefined && !change.archived && (change.value !== null || change.sensitivity !== undefined)
        ? [change.key.trim()]
        : [];
    }),
  );
  if (draftKeys.some((key) => valueEditTargets.has(key))) return true;

  const archivedKeys = new Set(
    active
      .filter((entry) => secretChangeFor(changes, entry.key)?.archived)
      .map((entry) => entry.key),
  );
  return draftKeys.some((key) => archivedKeys.has(key));
}

/**
 * Save every pending edit: renames first, one call each, then everything else
 * as one merge patch.
 *
 * The patch is a single transaction, so values, new keys and archives land
 * together or not at all. Renames cannot join it: a merge patch names keys and
 * has no way to move one with its history. A failed rename therefore stops the
 * save before the patch. The renames before it stay done, and every other edit
 * is kept for the retry, a value following its key to the new name.
 */
export async function applySecretEditBatch({
  active,
  drafts,
  changes,
  operations,
}: {
  active: readonly ActiveSecret[];
  drafts: readonly SecretDraft[];
  changes: Readonly<Record<string, SecretChange>>;
  operations: SecretEditOperations;
}): Promise<SecretEditBatchResult> {
  const remainingChanges = { ...changes };
  const plan = planEdits(active, drafts, changes);
  if (plan instanceof Error) {
    return { applied: 0, drafts: [...drafts], changes: remainingChanges, error: plan };
  }

  let applied = 0;
  const patch = patchOf(active, drafts, changes);
  try {
    for (const { sourceKey, change } of plan) {
      const key = change.key.trim();
      if (change.archived || key === sourceKey) continue;
      await operations.rename(sourceKey, key);
      delete remainingChanges[sourceKey];
      applied += 1;
      if (change.value !== null || change.sensitivity !== undefined) remainingChanges[key] = { ...change, key };
    }

    const written = Object.keys(patch).length;
    if (written > 0) await operations.write({ ...patch });
    return { applied: applied + written, drafts: [], changes: {}, error: null };
  } catch (error) {
    return { applied, drafts: [...drafts], changes: remainingChanges, error };
  }
}

/**
 * Put dependent renames in an order that frees each destination first.
 * Cycles and archive-then-restore plans fail before the first mutation.
 */
function planEdits(
  active: readonly ActiveSecret[],
  drafts: readonly SecretDraft[],
  changes: Readonly<Record<string, SecretChange>>,
): PlannedEdit[] | Error {
  const activeKeys = new Set(active.map((entry) => entry.key));
  const archivedKeys = new Set(
    active
      .filter((entry) => secretChangeFor(changes, entry.key)?.archived)
      .map((entry) => entry.key),
  );
  const restoredByDraft = [...drafts, ...companionsOf(active, drafts, changes)].find((draft) =>
    archivedKeys.has(draft.key.trim()),
  );
  if (restoredByDraft) {
    return new Error(
      `${restoredByDraft.key.trim()}: cannot archive and write the same key in one save`,
    );
  }

  const renames = new Map<string, SecretChange>();
  const otherEdits: PlannedEdit[] = [];
  for (const entry of active) {
    const change = secretChangeFor(changes, entry.key);
    if (change === undefined) continue;
    if (!change.archived && change.key.trim() !== entry.key) {
      renames.set(entry.key, change);
    } else {
      otherEdits.push({ sourceKey: entry.key, change });
    }
  }

  for (const [sourceKey, change] of renames) {
    const destination = change.key.trim();
    if (activeKeys.has(destination) && !renames.has(destination)) {
      return new Error(`${sourceKey}: ${destination} is already in use`);
    }
  }

  const orderedRenames: PlannedEdit[] = [];
  const freedKeys = new Set<string>();
  while (renames.size > 0) {
    const ready = [...renames].find(([, change]) => {
      const destination = change.key.trim();
      return !activeKeys.has(destination) || freedKeys.has(destination);
    });
    if (!ready) {
      return new Error('Secret renames contain a cycle. Save them in separate steps.');
    }
    const [sourceKey, change] = ready;
    renames.delete(sourceKey);
    freedKeys.add(sourceKey);
    orderedRenames.push({ sourceKey, change });
  }

  return [...orderedRenames, ...otherEdits];
}
