import { readdirSync } from 'node:fs';

import { defineConfig } from 'tsdown';

const pages = Object.fromEntries(
  readdirSync('src/pages')
    .filter((file) => file.endsWith('.tsx'))
    .map((file) => [`pages/${file.slice(0, -'.tsx'.length)}`, `src/pages/${file}`]),
);

// The declarations of the package's entries, and the Vite plugin itself:
// `vite build` makes the modules, into the same `dist/`, which this must
// leave alone.
export default defineConfig([
  {
    entry: { index: 'src/index.ts', ...pages },
    platform: 'neutral',
    dts: { emitDtsOnly: true },
    clean: false,
    fixedExtension: false,
  },
  {
    entry: { vite: 'src/vite.ts' },
    platform: 'node',
    // The deployment's own Vite.
    external: ['vite'],
    dts: true,
    clean: false,
    fixedExtension: false,
  },
]);
