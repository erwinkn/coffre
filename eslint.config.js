import { defineConfig } from 'eslint/config';
import tsParser from '@typescript-eslint/parser';

const noDrizzle = {
  regex: '^drizzle-orm(/|$)',
  message: 'Every query lives in packages/server/src/db/queries.ts; add or extend one there.',
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

const vaultBoundaries = {
  paths: [
    {
      name: 'node:sqlite',
      message: 'Only src/sqlite-node.ts opens SQLite on Node; the Worker must never import it.',
    },
  ],
  patterns: [
    {
      regex: '^(drizzle-orm|libsql)(/|$)',
      message: "The vault's queries are plain SQL in src/store.ts, over src/sqlite.ts.",
    },
  ],
};

export default defineConfig([
  {
    // Drizzle belongs to the server's database layer, and nowhere else.
    name: 'coffre/query-boundary',
    files: ['packages/*/src/**/*.{ts,tsx}'],
    ignores: ['packages/server/src/db/**', 'packages/ui/src/routeTree.gen.ts'],
    ...parsing,
    rules: {
      'no-restricted-imports': ['error', { patterns: [noDrizzle] }],
    },
  },
  {
    // The vault's queries are plain SQL in its store, and only its Node
    // adapter may import node:sqlite, which the Worker cannot load.
    name: 'coffre/vault-boundaries',
    files: ['packages/vault/src/**/*.ts'],
    ignores: ['packages/vault/src/sqlite-node.ts'],
    ...parsing,
    rules: {
      'no-restricted-imports': ['error', vaultBoundaries],
    },
  },
  {
    name: 'coffre/ui-boundaries',
    files: ['packages/ui/src/**/*.{ts,tsx}'],
    ignores: ['packages/ui/src/routeTree.gen.ts'],
    ...parsing,
    rules: {
      'no-restricted-imports': ['error', uiBoundaries],
    },
  },
]);
