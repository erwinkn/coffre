// Copy examples/workers and examples/node into dist/templates, for
// `coffre init` once published. Each `.gitignore` becomes `gitignore`,
// since npm leaves any file called `.gitignore` out of a package.
import { cpSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { KINDS, templateDir, templateFiles } from '../src/init.ts';

const out = fileURLToPath(new URL('../dist/templates/', import.meta.url));
rmSync(out, { recursive: true, force: true });
for (const kind of KINDS) {
  const source = templateDir(kind);
  const files = templateFiles(source);
  for (const file of files) {
    cpSync(join(source, file), join(out, kind, file === '.gitignore' ? 'gitignore' : file));
  }
  console.log(`dist/templates/${kind}: ${files.length} files`);
}
