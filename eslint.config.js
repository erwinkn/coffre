import { defineConfig } from 'eslint/config';
import tsParser from '@typescript-eslint/parser';

const noDrizzle = {
  regex: '^drizzle-orm(/|$)',
  message: 'Every query lives in packages/db/src/queries.ts; add or extend one there.',
};

const parsing = {
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
};

const uiBoundaries = {
  paths: [
    {
      name: '@tanstack/react-start',
      importNames: ['createServerFn'],
      message:
        'Pages read and write through the API client (context.client, useCoffre()); add a route to the API instead.',
    },
  ],
  patterns: [noDrizzle],
};

export default defineConfig([
  {
    name: 'coffre/ui-boundaries',
    files: ['packages/ui/src/**/*.{ts,tsx}'],
    ignores: ['packages/ui/src/routeTree.gen.ts'],
    ...parsing,
    rules: {
      'no-restricted-imports': ['error', uiBoundaries],
    },
  },
  {
    name: 'coffre/server-boundaries',
    files: ['packages/server/src/**/*.ts'],
    ...parsing,
    rules: {
      'no-restricted-imports': ['error', { patterns: [noDrizzle] }],
    },
  },
]);
