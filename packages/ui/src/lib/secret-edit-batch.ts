import type { Generation } from '@coffre/core/recipe';

/**
 * A second secret a row writes with its own value, in the same patch: a
 * generated key pair's public key, beside its private key. It is part of
 * the row's edit, so saving, undoing or retrying the row takes both.
 */
export type Companion = { key: string; value: string };

export type SecretDraft = {
  id: number;
  key: string;
  value: string;
  companion?: Companion;
  /** The recipe a generated value was made by, saved with it; typing over the value drops it. */
  recipe?: string;
  /** Written plain: no secret, shown to whoever lists the environment. */
  plain?: boolean;
};

export type SecretChange = {
  key: string;
  value: string | null;
  archived: boolean;
  /** Only beside a new value. */
  companion?: Companion;
  /** Only beside a generated value. */
  recipe?: string;
  /** Only beside a new value: whether it is written plain, no secret. A value is a secret unless it says so. */
  plain?: boolean;
  /**
   * Only beside a plain value: the version the edit started from, by id,
   * which a stored secret made plain replaces, or the write is refused, so
   * that it never publishes a value someone has written over since.
   */
  replaces?: string;
};

type ActiveSecret = { key: string };

/**
 * A merge patch: a string sets a key, adding it if it is new; a value with
 * how it was generated sets it with its recipe; a plain one, no secret,
 * says so; `null` archives it.
 */
export type SecretPatch = Record<string, string | { value: string; generated: Generation } | { value: string; plain: true; replaces?: string } | null>;

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

/** What a row writes under each key: its value, and its companion's beside it. */
function rowPatch(key: string, value: string, edit: { recipe?: string; companion?: Companion; plain?: boolean; replaces?: string }): SecretPatch {
  const generated = generationOf(key, edit);
  const plain = (each: string) => (edit.replaces === undefined ? { value: each, plain: true as const } : { value: each, plain: true as const, replaces: edit.replaces });
  const entry = (each: string) => (generated !== undefined ? { value: each, generated } : edit.plain === true ? plain(each) : each);
  const patch: SecretPatch = Object.create(null);
  patch[key] = entry(value);
  if (edit.companion !== undefined) patch[edit.companion.key.trim()] = entry(edit.companion.value);
  return patch;
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
 * The value each key a save writes plain will show, by its name after the
 * save: what the list shows of it until it is read back.
 */
export function plainValuesOf(
  active: readonly ActiveSecret[],
  drafts: readonly SecretDraft[],
  changes: Readonly<Record<string, SecretChange>>,
): Map<string, string> {
  const out = new Map<string, string>();
  for (const draft of drafts) if (draft.plain === true && draft.recipe === undefined) out.set(draft.key.trim(), draft.value);
  for (const entry of active) {
    const change = secretChangeFor(changes, entry.key);
    if (change !== undefined && !change.archived && change.value !== null && change.plain === true && change.recipe === undefined) out.set(change.key.trim(), change.value);
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
      return change !== undefined && !change.archived && change.value !== null
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
  // A key named `__proto__` is a key like any other.
  const patch: SecretPatch = Object.create(null);
  try {
    for (const { sourceKey, change } of plan) {
      if (change.archived) {
        patch[sourceKey] = null;
        continue;
      }
      const key = change.key.trim();
      if (key !== sourceKey) {
        await operations.rename(sourceKey, key);
        delete remainingChanges[sourceKey];
        applied += 1;
        if (change.value !== null) remainingChanges[key] = { ...change, key };
      }
      if (change.value !== null) Object.assign(patch, rowPatch(key, change.value, change));
    }
    for (const draft of drafts) Object.assign(patch, rowPatch(draft.key.trim(), draft.value, draft));

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
