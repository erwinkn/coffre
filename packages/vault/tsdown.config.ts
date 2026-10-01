import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts', 'src/cloudflare.ts', 'src/node.ts'],
  platform: 'node',
  deps: { neverBundle: [/^cloudflare:/] },
  fixedExtension: false,
});
