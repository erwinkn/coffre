import { defineConfig } from 'tsdown';

// What `dependencies` names stays an import, the other `@coffre/*` packages included.
export default defineConfig({
  entry: ['src/index.ts', 'src/cloudflare.ts', 'src/node.ts', 'src/bin.ts', 'src/start.ts', 'src/routes.ts', 'src/plugins/vault-kv.ts', 'src/plugins/credential-proxy.ts', 'src/plugins/audit-watch.ts'],
  platform: 'node',
  dts: true,
  fixedExtension: false,
});
