import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { tanstackRouter } from '@tanstack/router-plugin/vite';
import viteReact from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

/**
 * The files a page links to (`globals.css?url`, the icons), left for the
 * deployment's build: it processes the stylesheet, fonts and all, and puts
 * them with the rest of its static files. The import keeps pointing at this
 * package's `src/`, which it ships.
 */
function linkedFiles(): Plugin {
  const MARK = 'coffre-linked:';
  return {
    name: 'coffre:linked-files',
    enforce: 'pre',
    async resolveId(source, importer) {
      if (!source.endsWith('?url') || importer === undefined) return null;
      const resolved = await this.resolve(source.slice(0, -'?url'.length), importer, { skipSelf: true });
      return resolved === null ? null : { id: `${MARK}${resolved.id}?url`, external: true };
    },
    // Each from where its chunk is: dist/index.js, or dist/chunks/….
    renderChunk(code, chunk) {
      const from = dirname(join(here('dist'), chunk.fileName));
      const rewritten = code.replaceAll(new RegExp(`${MARK}([^"'?]+)\\?url`, 'g'), (_, file: string) => {
        const path = relative(from, file);
        return `${path.startsWith('.') ? path : `./${path}`}?url`;
      });
      return rewritten === code ? null : { code: rewritten, map: null };
    },
  };
}

/**
 * Dynamic imports as plain `import()`: Vite wraps each in its preload
 * helper, which the deployment's own build adds again, and two helpers of
 * one name in a module do not parse.
 */
function plainDynamicImports(): Plugin {
  return {
    name: 'coffre:plain-dynamic-imports',
    enforce: 'post',
    generateBundle(_options, bundle) {
      for (const [name, chunk] of Object.entries(bundle)) {
        if (chunk.type !== 'chunk') continue;
        if (/(^|\/)preload-helper-[^/]*\.js$/.test(name)) {
          delete bundle[name];
          continue;
        }
        chunk.code = chunk.code
          .replace(/^import \{ \w+ as __vitePreload \} from "[^"]+";\n/m, '')
          .replace(/__vitePreload\(\(\) => (import\("[^"]+"\)), (?:\[[^\]]*\]|__VITE_PRELOAD__)\)/g, '$1');
        if (chunk.code.includes("__vitePreload")) this.error(`${name} still calls __vitePreload: ${chunk.code.split("\n").filter((l) => l.includes("__vitePreload")).slice(0, 3).join(" | ")}`);
      }
    },
  };
}

// Builds `@coffre/ui` as a library: the pages' route tree and `getRouter`,
// as ES modules a deployment's own TanStack Start build bundles. Each
// route's component is a chunk of its own, loaded when the route is, as in
// an app's own build: the deployment's Start splits only the routes it
// generates itself. React, the router, Start and Query stay imports, so the
// deployment's single copy serves both. `pnpm dev` runs the sources instead.
export default defineConfig({
  // A production build: `import.meta.env.DEV` is false, which drops the
  // Agentation toolbar (components/agentation.tsx) and its import.
  mode: 'production',
  plugins: [
    linkedFiles(),
    plainDynamicImports(),
    // Writes src/routeTree.gen.ts from src/routes, and splits each route.
    // Before the React plugin, as the router plugin requires.
    tanstackRouter({
      target: 'react',
      autoCodeSplitting: true,
      routesDirectory: here('src/routes'),
      generatedRouteTree: here('src/routeTree.gen.ts'),
    }),
    viteReact(),
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Readable: the deployment's build minifies what it ships.
    minify: false,
    sourcemap: true,
    target: 'es2022',
    lib: false,
    rollupOptions: {
      input: { index: here('src/index.ts') },
      preserveEntrySignatures: 'strict',
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
