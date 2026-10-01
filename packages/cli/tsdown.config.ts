import { defineConfig } from 'tsdown';

// One file with no dependencies: the client and core, devDependencies here, are bundled in.
export default defineConfig({
  entry: ['src/main.ts'],
  platform: 'node',
  dts: false,
  fixedExtension: false,
});
