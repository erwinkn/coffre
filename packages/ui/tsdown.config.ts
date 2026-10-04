import { defineConfig } from 'tsdown';

// The declarations of the package's two halves, and the Vite plugin itself:
// `vite build` makes the pages' modules, into the same `dist/`, which this
// must leave alone.
export default defineConfig([
  {
    entry: { index: 'src/types.ts' },
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
