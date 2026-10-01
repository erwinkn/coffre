import { defineConfig } from 'tsdown';

// core is bundled in; what `dependencies` names stays an import.
export default defineConfig({
  entry: ['src/index.ts', 'src/cloudflare.ts', 'src/node.ts', 'src/bin.ts'],
  platform: 'node',
  dts: true,
  fixedExtension: false,
});
