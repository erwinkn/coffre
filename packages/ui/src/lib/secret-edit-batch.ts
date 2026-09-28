export type SecretDraft = { id: number; key: string; value: string };

export type SecretChange = {
  key: string;
  value: string | null;
  archived: boolean;
};

type ActiveSecret = { key: string };

/** A merge patch: a string sets a key, adding it if it is new; `null` archives it. */
export type SecretPatch = Record<string, string | null>;

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

  const draftKeys = drafts.map((draft) => draft.key.trim());
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
        if (change.value !== null) remainingChanges[key] = { key, value: change.value, archived: false };
      }
      if (change.value !== null) patch[key] = change.value;
    }
    for (const draft of drafts) patch[draft.key.trim()] = draft.value;

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
  const restoredByDraft = drafts.find((draft) => archivedKeys.has(draft.key.trim()));
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
