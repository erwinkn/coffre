import { readFile, rename, writeFile } from 'node:fs/promises';

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
      await writeFile(`${path}.part`, note);
      await rename(`${path}.part`, path);
    },
  };
}
