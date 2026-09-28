import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'mysql',
  schema: './schema.mysql.ts',
  out: './migrations/mysql',
});
