import { defineConfig } from 'tsdown';

// What `dependencies` names stays an import, the other `@coffre/*` packages included.
// No `src/node.ts` in 0.16.0, Workers only (D198): docs/design/0.16.md, "Node in 0.16.0".
export default defineConfig({
  entry: ['src/index.ts', 'src/cloudflare.ts', 'src/bin.ts', 'src/start.ts', 'src/routes.ts', 'src/plugins/vault-kv.ts', 'src/plugins/credential-proxy.ts'],
  platform: 'node',
  // The Workers runtime's own module, which `CoffreWorkload` extends a class of: the deployment's build resolves it.
  deps: { neverBundle: [/^cloudflare:/] },
  dts: true,
  fixedExtension: false,
});
