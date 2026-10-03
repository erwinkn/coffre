import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts', 'src/routes.ts'],
  platform: 'neutral',
  dts: true,
  fixedExtension: false,
});
