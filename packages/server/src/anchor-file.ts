// The audit anchor in a file, for Node (anchor.ts): its own module, so that
// a Worker's bundle never imports the file system.
import { mkdir, open, readFile, rename } from 'node:fs/promises';
import { dirname } from 'node:path';

import { admits, type AnchorStore, type AuditAnchor } from './anchor.ts';

/**
 * An anchor in a file, for one Node process with a persistent volume: each
 * write a new file, synced, renamed over the old, mode 0600, one at a time.
 * Two processes, or replicas, each with a file of their own, do not see
 * each other's writes; a container whose file goes with it finds the
 * anchor lost on its next start. Those want a store they share, with a
 * compare-and-set of its own (docs/deploy.md, "The audit watch").
 */
export function fileAnchor(path: string): AnchorStore {
  let turn: Promise<unknown> = Promise.resolve();
  const read = async (): Promise<AuditAnchor | null> => {
    try {
      return JSON.parse(await readFile(path, 'utf8')) as AuditAnchor;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
  };
  return {
    read,
    write: (prev, next) => {
      const written = turn.then(async () => {
        if (!admits(await read(), prev, next)) return false;
        await mkdir(dirname(path), { recursive: true });
        const temporary = `${path}.${process.pid}.tmp`;
        const file = await open(temporary, 'w', 0o600);
        try {
          await file.writeFile(JSON.stringify(next));
          await file.sync();
        } finally {
          await file.close();
        }
        await rename(temporary, path);
        const directory = await open(dirname(path), 'r');
        await directory.sync().finally(() => directory.close());
        return true;
      });
      turn = written.catch(() => undefined);
      return written;
    },
  };
}
