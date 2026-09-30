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
    schemas: 'src/schemas.ts',
    vault: 'src/vault.ts',
  },
  platform: 'node',
  dts: true,
  fixedExtension: false,
});
