import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import viteReact from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

/** Each page, an entry of its own, `@coffre/ui/pages/<name>`: a file route names its component from there. */
const pages = Object.fromEntries(
  readdirSync(here('src/pages'))
    .filter((file) => file.endsWith('.tsx'))
    .map((file) => [`pages/${file.slice(0, -'.tsx'.length)}`, here(`src/pages/${file}`)]),
);

// Builds `@coffre/ui` as a library: its route options and provider, and
// each page, as ES modules a deployment's own TanStack Start build bundles,
// and its splitter splits.
// React, the router, Start and Query stay imports, so the deployment's
// single copy serves both. `pnpm dev` runs the sources instead.
export default defineConfig({
  mode: 'production',
  plugins: [viteReact()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Readable: the deployment's build minifies what it ships.
    minify: false,
    sourcemap: true,
    target: 'es2022',
    lib: { entry: { index: here('src/index.ts'), ...pages }, formats: ['es'] },
    rollupOptions: {
      // Every package stays an import: the deployment installs and bundles it once.
      external: (id) => !id.startsWith('.') && !id.startsWith('/') && !id.startsWith('\0') && !/^[A-Za-z]:/.test(id),
      output: {
        format: 'es',
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
      },
    },
  },
});
