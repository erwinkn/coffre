import { defineConfig } from 'tsdown';

// The published client is built JavaScript with no dependency, so it runs on
// the caller's Node, like the CLI; the workspace's sources still need Node 24.
export default defineConfig({
  entry: ['src/index.ts', 'src/routes.ts', 'src/credential.ts'],
  platform: 'neutral',
  target: 'node20',
  dts: true,
  fixedExtension: false,
});
