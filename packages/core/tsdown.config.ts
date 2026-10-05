import { defineConfig } from 'tsdown';

// One entry per subpath in `exports`; what they share becomes chunks.
export default defineConfig({
  entry: {
    access: 'src/access.ts',
    audit: 'src/audit/chain.ts',
    dotenv: 'src/dotenv.ts',
    envelope: 'src/envelope.ts',
    identity: 'src/identity/index.ts',
    kek: 'src/kek/index.ts',
    // MCP's scopes and client rules, for the server and the consent page.
    mcp: 'src/mcp.ts',
    pages: 'src/pages.ts',
    schemas: 'src/schemas.ts',
    vault: 'src/vault.ts',
    // Trust bindings' rules alone, for the pages and the CLI: none of sign-in's own code.
    workloads: 'src/identity/workloads.ts',
  },
  platform: 'node',
  dts: true,
  fixedExtension: false,
});
