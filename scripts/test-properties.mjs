// node:test also runs registered tests when imported by a plain Node script.
// Keeping the options here avoids adding environment variables to packages.
const allowed = process.argv.slice(2).every((arg) => arg === '--long' || /^--seed=\d+$/.test(arg));
if (!allowed) throw new Error('Usage: pnpm test:properties [--long] [--seed=<unsigned integer>]');
await import('../packages/core/test/audit-properties.test.ts');
await import('../packages/core/test/access-properties.test.ts');
await import('../packages/core/test/access-rules-properties.test.ts');
await import('../packages/core/test/domain-properties.test.ts');
await import('../packages/core/test/envelope-properties.test.ts');
await import('../packages/core/test/dotenv-properties.test.ts');
await import('../packages/core/test/workload-token-properties.test.ts');
await import('../packages/cli/test/export-properties.test.ts');
await import('../packages/cli/test/tunnel-properties.test.ts');
await import('../packages/server/test/tunnel-properties.test.ts');
await import('../packages/server/test/sigv4-properties.test.ts');
await import('../packages/server/test/credential-proxy-properties.test.ts');
await import('../packages/core/test/workload-properties.test.ts');
