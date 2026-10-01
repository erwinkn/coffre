import { defineConfig } from 'tsdown';

// What `dependencies` names stays an import, the other `@coffre/*` packages included.
export default defineConfig({
  entry: ['src/index.ts', 'src/cloudflare.ts', 'src/node.ts', 'src/bin.ts'],
  platform: 'node',
  dts: true,
  fixedExtension: false,
});
