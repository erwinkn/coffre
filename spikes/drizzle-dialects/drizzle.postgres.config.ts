import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/schema.postgres.ts',
  out: './migrations/postgres',
});
