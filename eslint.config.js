import path from 'node:path';

import { defineConfig } from 'eslint/config';
import tsParser from '@typescript-eslint/parser';

const noDrizzle = {
  regex: '^drizzle-orm(/|$)',
  message: 'Every query of the server lives in packages/server/src/db; add or extend one there.',
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

/**
 * What each of the vault's files may import: Drizzle only in its queries, and
 * what opens a database from a URL only in its Node entry, since the Worker
 * cannot load it.
 */
const vaultBoundaries = {
  paths: [
    {
      name: '@coffre/db/connect',
      message: 'Only src/node.ts opens a database from a URL; the Worker builds its own from Hyperdrive.',
    },
  ],
};

/**
 * A relative import stays inside its package: another package is imported by
 * name, `@coffre/core/vault` and not `../../core/src/vault.ts`, so that each
 * one builds, ships and can be internalized on its own. Tests and scripts may
 * also reach the dev tooling beside the packages, such as the seed's
 * config; what ships in `src/` may not.
 */
const packageImports = {
  meta: {
    type: 'problem',
    schema: [],
    messages: {
      otherPackage: "Import another package by name, '@coffre/{{name}}', not by path.",
      outsidePackages: 'What ships in src/ cannot import from outside its package.',
    },
  },
  create(context) {
    const file = path.relative(context.cwd, context.filename).split(path.sep);
    if (file[0] !== 'packages' || file.length < 4) return {};
    const [, own, dir] = file;

    function check(source) {
      if (source?.type !== 'Literal' || typeof source.value !== 'string' || !source.value.startsWith('.')) return;
      const target = path.relative(context.cwd, path.resolve(path.dirname(context.filename), source.value)).split(path.sep);
      if (target[0] === 'packages' && target[1] === own) return;
      if (target[0] === 'packages') {
        context.report({ node: source, messageId: 'otherPackage', data: { name: target[1] } });
      } else if (dir === 'src') {
        context.report({ node: source, messageId: 'outsidePackages' });
      }
    }

    return {
      ImportDeclaration: (node) => check(node.source),
      ExportNamedDeclaration: (node) => check(node.source),
      ExportAllDeclaration: (node) => check(node.source),
      ImportExpression: (node) => check(node.source),
    };
  },
};

export default defineConfig([
  {
    name: 'coffre/package-imports',
    files: ['packages/*/{src,test,scripts}/**/*.{ts,tsx}'],
    ignores: ['packages/ui/src/routeTree.gen.ts'],
    ...parsing,
    plugins: { coffre: { rules: { 'package-imports': packageImports } } },
    rules: {
      'coffre/package-imports': 'error',
    },
  },
  {
    // Drizzle belongs to @coffre/db, the server's queries and the vault's, and nowhere else.
    name: 'coffre/query-boundary',
    files: ['packages/*/src/**/*.{ts,tsx}'],
    ignores: ['packages/db/src/**', 'packages/server/src/db/**', 'packages/vault/src/**', 'packages/ui/src/routeTree.gen.ts'],
    ...parsing,
    rules: {
      'no-restricted-imports': ['error', { patterns: [noDrizzle] }],
    },
  },
  {
    // The vault's Worker cannot load what opens a database on Node. Drizzle
    // is not confined within the vault: an operation names its rows with
    // Drizzle's conditions, and has no database to run a query on
    // (`Operation`, in src/change.ts).
    name: 'coffre/vault-boundaries',
    files: ['packages/vault/src/**/*.ts'],
    ignores: ['packages/vault/src/node.ts'],
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
