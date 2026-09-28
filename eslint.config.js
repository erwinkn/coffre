import { defineConfig } from 'eslint/config';
import tsParser from '@typescript-eslint/parser';

const webBoundaries = {
  paths: [
    {
      name: '@tanstack/react-start',
      importNames: ['createServerFn'],
      message:
        'Pages read and write through the API client (context.client, useCoffre()); add a route to the API instead.',
    },
  ],
  patterns: [
    {
      regex: '^drizzle-orm(/|$)',
      message: 'Every query lives in packages/db/src/queries.ts; add or extend one there.',
    },
  ],
};

export default defineConfig([
  {
    name: 'coffre/ui-boundaries',
    files: ['packages/ui/src/**/*.{ts,tsx}'],
    ignores: ['packages/ui/src/routeTree.gen.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
    },
    linterOptions: {
      noInlineConfig: true,
    },
    rules: {
      'no-restricted-imports': ['error', webBoundaries],
    },
  },
]);
