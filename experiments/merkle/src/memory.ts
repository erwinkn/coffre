import { open, readFile, rename } from 'node:fs/promises';
import { dirname } from 'node:path';

import type { Memory } from './log.ts';

/** The signer's memory in a file beside a Node vault: the last head it signed. */
export function fileMemory(path: string): Memory {
  return {
    async last() {
      try {
        return await readFile(path, 'utf8');
      } catch {
        return null;
      }
    },
    async remember(note) {
      // Durable before the database write that follows (RememberFirst): the file, then the rename, each synced.
      const file = await open(`${path}.part`, 'w');
      await file.writeFile(note);
      await file.sync();
      await file.close();
      await rename(`${path}.part`, path);
      const dir = await open(dirname(path), 'r');
      await dir.sync();
      await dir.close();
    },
  };
}
