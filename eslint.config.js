import { defineConfig } from 'eslint/config';
import tsParser from '@typescript-eslint/parser';

const rawServerFunctionImport = {
  paths: [
    {
      name: '@tanstack/react-start',
      importNames: ['createServerFn'],
      message: 'Use registeredServerFn, or the reviewed sessionServerFn boundary.',
    },
  ],
};

const protectedServerFunctionImports = {
  ...rawServerFunctionImport,
  patterns: [
    {
      regex: '(^|/)server/server-fn(?:\\.ts)?$',
      importNames: ['sessionServerFn'],
      message: 'Session server functions are limited to the login and shell boundaries.',
    },
  ],
};

export default defineConfig([
  {
    name: 'coffre/server-function-boundaries',
    files: ['apps/web/src/**/*.{ts,tsx}'],
    ignores: ['apps/web/src/routeTree.gen.ts'],
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
      'no-restricted-imports': ['error', protectedServerFunctionImports],
    },
  },
  {
    name: 'coffre/reviewed-session-boundaries',
    files: [
      'apps/web/src/server-functions/auth.ts',
      'apps/web/src/server-functions/shell.ts',
    ],
    rules: {
      'no-restricted-imports': ['error', rawServerFunctionImport],
    },
  },
  {
    name: 'coffre/server-function-factory',
    files: ['apps/web/src/server/server-fn.ts'],
    rules: {
      'no-restricted-imports': 'off',
    },
  },
]);
