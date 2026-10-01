import { defineConfig } from 'tsdown';

// Only the declarations: `vite build` makes the package itself, into the
// same `dist/`, which this must leave alone.
export default defineConfig({
  entry: { index: 'src/types.ts' },
  platform: 'neutral',
  dts: { emitDtsOnly: true },
  clean: false,
  fixedExtension: false,
});
