import { defineConfig } from 'tsdown';

// The client, a devDependency, is bundled in; what `dependencies` names stays an import.
export default defineConfig({
  entry: { main: 'src/main.ts', idp: 'src/idp/index.ts', authenticator: 'src/authenticator.ts' },
  platform: 'node',
  dts: { entry: ['src/idp/index.ts', 'src/authenticator.ts'] },
  fixedExtension: false,
});
