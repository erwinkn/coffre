import { defineConfig } from 'tsdown';

// One entry per subpath in `exports`; what they share becomes chunks.
export default defineConfig({
  entry: {
    access: 'src/access.ts',
    audit: 'src/audit/chain.ts',
    // What a deployment chooses, in one object: its deployment.ts, read by the app, the vault and the build.
    deployment: 'src/deployment.ts',
    dotenv: 'src/dotenv.ts',
    envelope: 'src/envelope.ts',
    identity: 'src/identity/index.ts',
    kek: 'src/kek/index.ts',
    // MCP's scopes and client rules, for the server and the consent page.
    mcp: 'src/mcp.ts',
    // What a Worker's isolate holds, by share, and the cache its kept answers are made of.
    memory: 'src/memory.ts',
    // 0.15's audit trees: the tree, tiles, checkpoints, the head pair and the verifier's walk.
    merkle: 'src/audit/merkle.ts',
    pages: 'src/pages.ts',
    // Proxy definitions written in the UI: their shapes and the vault's checks, for the server, the vault and the Proxy tab.
    proxy: 'src/proxy.ts',
    // A credential proxy's allow lists and inject rules: what the proxy matches and what a saved definition must be.
    'proxy-match': 'src/proxy-match.ts',
    // How a generated value is made, for the pages, the CLI and the server's checks.
    recipe: 'src/recipe.ts',
    schemas: 'src/schemas.ts',
    vault: 'src/vault.ts',
    // Trust bindings' rules alone, for the pages and the CLI: none of sign-in's own code.
    workloads: 'src/identity/workloads.ts',
  },
  platform: 'node',
  dts: true,
  fixedExtension: false,
});
