/**
 * Rows grouped by folder, as every list shows them: those in no folder
 * first, then each folder by name, each keeping the order it was given. A
 * folder only arranges a list (docs/design/environments.md).
 */
export function byFolder<T extends { folder: string | null }>(rows: readonly T[]): [string | null, T[]][] {
  const groups = new Map<string | null, T[]>([[null, []]]);
  for (const folder of [...new Set(rows.flatMap((row) => (row.folder === null ? [] : [row.folder])))].sort()) groups.set(folder, []);
  for (const row of rows) groups.get(row.folder)!.push(row);
  return [...groups].filter(([, inFolder]) => inFolder.length > 0);
}

/** The folders in use among `rows`, by name. */
export function foldersOf(rows: readonly { folder: string | null }[]): string[] {
  return [...new Set(rows.flatMap((row) => (row.folder === null ? [] : [row.folder])))].sort();
}
