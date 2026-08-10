export type SecretDraft = { id: number; key: string; value: string };

export type SecretChange = {
  key: string;
  value: string | null;
  archived: boolean;
};

type ActiveSecret = { key: string };

type SecretEditOperations = {
  archive: (key: string) => Promise<void>;
  rename: (key: string, nextKey: string) => Promise<void>;
  save: (key: string, value: string) => Promise<void>;
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
 * Apply edits in order and return only work that still needs to run.
 *
 * A rename and value update are two audited operations. If the rename lands but
 * the value update fails, the pending value follows the new key for the retry.
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
  let applied = 0;
  let remainingDrafts = [...drafts];
  const remainingChanges = { ...changes };
  const plan = planEdits(active, drafts, changes);
  if (plan instanceof Error) {
    return {
      applied,
      drafts: remainingDrafts,
      changes: remainingChanges,
      error: plan,
    };
  }

  try {
    for (const { sourceKey, change } of plan) {
      if (change.archived) {
        await operations.archive(sourceKey);
        delete remainingChanges[sourceKey];
        applied += 1;
        continue;
      }

      let currentKey = sourceKey;
      if (change.key !== sourceKey) {
        currentKey = change.key.trim();
        await operations.rename(sourceKey, currentKey);
        delete remainingChanges[sourceKey];
        applied += 1;

        if (change.value !== null) {
          remainingChanges[currentKey] = {
            key: currentKey,
            value: change.value,
            archived: false,
          };
        }
      }

      if (change.value !== null) {
        await operations.save(currentKey, change.value);
        delete remainingChanges[currentKey];
        applied += 1;
      }
    }

    for (const draft of drafts) {
      await operations.save(draft.key.trim(), draft.value);
      remainingDrafts = remainingDrafts.filter((entry) => entry.id !== draft.id);
      applied += 1;
    }

    return {
      applied,
      drafts: remainingDrafts,
      changes: remainingChanges,
      error: null,
    };
  } catch (error) {
    return {
      applied,
      drafts: remainingDrafts,
      changes: remainingChanges,
      error,
    };
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
