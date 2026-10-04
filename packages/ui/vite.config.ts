import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

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

// Builds `@coffre/ui` as a library: coffre's routes and `createRouter`, as
// ES modules a deployment's own TanStack Start build bundles. Each page's
// component is a chunk of its own, imported as its route is loaded, which
// the deployment's build keeps apart. React, the router, Start and Query
// stay imports, so the deployment's single copy serves both. `pnpm dev`
// runs the sources instead.
export default defineConfig({
  // A production build: `import.meta.env.DEV` is false, which drops the
  // Agentation toolbar (components/agentation.tsx) and its import.
  mode: 'production',
  plugins: [
    linkedFiles(),
    viteReact(),
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Readable: the deployment's build minifies what it ships.
    minify: false,
    sourcemap: true,
    target: 'es2022',
    // Library mode: dynamic imports stay plain `import()`, which the
    // deployment's build wraps in its own preload helper.
    lib: { entry: here('src/index.ts'), formats: ['es'], fileName: 'index' },
    rollupOptions: {
      // Every package stays an import: the deployment installs and bundles it once.
      external: (id) => !id.startsWith('.') && !id.startsWith('/') && !id.startsWith('\0') && !/^[A-Za-z]:/.test(id),
      output: {
        format: 'es',
        entryFileNames: '[name].js',
        // Each page by its name, which the deployment's build finds its chunk by (src/vite.ts).
        chunkFileNames: (chunk) => (/[\\/]src[\\/]pages[\\/]/.test(chunk.facadeModuleId ?? '') ? 'pages/[name].js' : 'chunks/[name]-[hash].js'),
      },
    },
  },
});
