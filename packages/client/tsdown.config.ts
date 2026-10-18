import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts', 'src/routes.ts', 'src/credential.ts'],
  platform: 'neutral',
  dts: true,
  fixedExtension: false,
});
