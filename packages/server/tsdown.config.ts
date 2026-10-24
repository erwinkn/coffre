import { defineConfig } from 'tsdown';

// What `dependencies` names stays an import, the other `@coffre/*` packages included.
export default defineConfig({
  entry: ['src/index.ts', 'src/cloudflare.ts', 'src/node.ts', 'src/bin.ts', 'src/start.ts', 'src/routes.ts', 'src/plugins/vault-kv.ts', 'src/plugins/credential-proxy.ts'],
  platform: 'node',
  // The Workers runtime's own modules, which a deployment's build resolves.
  deps: { neverBundle: [/^cloudflare:/] },
  dts: true,
  fixedExtension: false,
});
