import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'sqlite',
  schema: './schema.sqlite.ts',
  out: './migrations/sqlite',
});
