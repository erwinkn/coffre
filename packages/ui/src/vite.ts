// `@coffre/ui/vite`: what a deployment's Vite build needs to carry coffre's
// pages, beside TanStack Start's and React's own plugins:
//
//   plugins: [cloudflare(…), tanstackStart({ router: { enableRouteGeneration: false } }), viteReact(), coffre()]
//
// The app's routes are code (its src/router.tsx), so Start's generator, which
// looks for files in src/routes, is off.
//
// It runs in Node, in the deployment's build; nothing here reaches a page.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { searchForWorkspaceRoot, type Plugin } from 'vite';

/**
 * The schema's tables whose names could appear in no page: those with an
 * underscore. Single words such as `secrets` are in the pages' own copy.
 * A test holds this to packages/db/src/schema.ts.
 */
export const SERVER_TABLES = [
  'audit_chain_head',
  'audit_log',
  'consumed_tokens',
  'device_authorizations',
  'secret_versions',
  'service_bindings',
  'vault_grants',
  'vault_members',
];

/**
 * What only server code carries, and so must never be in what the browser
 * loads. A bundler keeps a module whose top level has side effects, such as
 * `pgTable(…)`, even when nothing uses its exports, so a page importing
 * across the line just grows by the database layer, with no error: this is
 * the error.
 */
const MARKERS: { label: string; pattern: RegExp }[] = [
  { label: 'drizzle-orm', pattern: /drizzle:[A-Z]/ },
  ...SERVER_TABLES.map((name) => ({ label: `the table ${name}`, pattern: new RegExp(`\\b${name}\\b`) })),
  { label: 'pg', pattern: /cloudflare:sockets|pg-protocol|pgpass/ },
  { label: 'libsql', pattern: /@libsql|libsql/ },
  { label: 'a COFFRE_ variable read', pattern: /env\s*(\.|\[\s*['"`])COFFRE_/ },
  { label: 'agentation', pattern: /agentation-(theme|root|color)/ },
];

/** What the browser would load that only the server may hold: each file, and what it carries. */
export function serverCodeIn(files: { name: string; code: string }[]): string[] {
  return files.flatMap(({ name, code }) => MARKERS.filter(({ pattern }) => pattern.test(code)).map(({ label }) => `${name}: ${label}`));
}

/**
 * The packages this one shares with the deployment, at the versions it was
 * built against, and those the deployment has. Two copies of React, or of
 * the router, render nothing that hydrates; another version of one is a
 * build no one tested.
 */
export function versionDrift(root: string): string[] {
  const own = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    version: string;
    peerDependencies: Record<string, string>;
  };
  const from = createRequire(join(root, 'package.json'));
  return Object.entries(own.peerDependencies).flatMap(([name, wanted]) => {
    let installed: string;
    try {
      installed = (JSON.parse(readFileSync(from.resolve(`${name}/package.json`), 'utf8')) as { version: string }).version;
    } catch {
      return [`${name} ${wanted} is not installed`];
    }
    return installed === wanted ? [] : [`${name} is ${installed}, and @coffre/ui ${own.version} is built for ${wanted}`];
  });
}

/**
 * The routes manifest Start's server build reads. Its route generator writes
 * it for the routes it finds in an app's `src/routes`; with the routes in
 * code, the generator is off and there is none. The root alone
 * carries the client entry, which is all the pages need: each route's code
 * is loaded as the route is.
 */
function routesManifest(): void {
  const scope = globalThis as { TSS_ROUTES_MANIFEST?: unknown };
  scope.TSS_ROUTES_MANIFEST ??= { __root__: {} };
}

/** Files the browser runs or reads as text, which the guard reads whatever form the build holds them in. */
const TEXT = /\.(m?js|css|html|json|svg|txt|wasm\.js)$/;

/** An emitted file's text: a chunk's code, or an asset's source, a string or bytes. */
function textOf(file: { type: 'chunk'; code: string } | { type: 'asset'; fileName: string; source: string | Uint8Array }): string {
  if (file.type === 'chunk') return file.code;
  if (typeof file.source === 'string') return file.source;
  return TEXT.test(file.fileName) ? new TextDecoder().decode(file.source) : '';
}

const PRELOADS = 'virtual:coffre/preloads';

/**
 * Each of coffre's pages, by name, and the files the browser needs to show
 * it: its chunk and every chunk that one imports. `@coffre/ui` emits each
 * page as `dist/pages/<name>.js`; the deployment's build makes it a chunk of
 * its own, which this finds in the client's bundle.
 */
function pagePreloads(bundle: Record<string, { type: string; fileName: string; facadeModuleId?: string | null; imports?: string[] }>, base: string) {
  const chunks = new Map(Object.values(bundle).filter((file) => file.type === 'chunk').map((chunk) => [chunk.fileName, chunk]));
  const preloads: Record<string, string[]> = {};
  for (const chunk of chunks.values()) {
    const page = /[\\/](?:@coffre[\\/]ui|packages[\\/]ui)[\\/]dist[\\/]pages[\\/]([a-z-]+)\.js$/.exec(chunk.facadeModuleId ?? '')?.[1];
    if (page === undefined) continue;
    const files = new Set<string>();
    const visit = (fileName: string) => {
      if (files.has(fileName)) return;
      files.add(fileName);
      for (const imported of chunks.get(fileName)?.imports ?? []) visit(imported);
    };
    visit(chunk.fileName);
    preloads[page] = [...files].map((file) => `${base}${file}`);
  }
  return preloads;
}

/**
 * coffre's pages in a deployment's build: its static files under
 * `/_coffre/`, as the server expects them; a server build that holds what
 * it renders with; the versions it shares, as built; and nothing of the
 * server in what the browser loads.
 */
export function coffre(): Plugin {
  // Found in the client's build, which Start runs first, and read in the server's.
  let preloads: Record<string, string[]> = {};
  let base = '/';
  return {
    name: 'coffre',
    sharedDuringBuild: true,
    config(config) {
      routesManifest();
      return {
        // `vite dev` serves coffre's files from this package, wherever it
        // is: under node_modules, inside the project, as installed; or
        // linked from elsewhere. Naming it keeps the project's own root.
        server: { fs: { allow: [searchForWorkspaceRoot(resolve(config.root ?? '')), fileURLToPath(new URL('..', import.meta.url))] } },
        // The server's build holds all it renders with, as a Worker's does:
        // run by Node, it then resolves nothing from node_modules, where
        // pnpm lets a deployment reach only its own dependencies.
        ssr: { noExternal: true },
        build: {
          // A deployment serves these from its own origin, beside `/api` and
          // `/auth`; the prefix keeps the two apart.
          assetsDir: '_coffre/assets',
          // Vite inlines files under 4 KiB as data: URLs, which would catch a
          // small font subset: the Content-Security-Policy takes fonts from
          // coffre's own origin alone.
          assetsInlineLimit: (file: string) => (/\.woff2?$/.test(file) ? false : undefined),
        },
      };
    },
    resolveId(id) {
      return id === PRELOADS ? `\0${PRELOADS}` : null;
    },
    // The server renders each page's preloads into its head (routes.ts);
    // the browser's own navigations preload through the router.
    load(id) {
      if (id !== `\0${PRELOADS}`) return null;
      const known = this.environment.name === 'client' ? {} : preloads;
      return `export default ${JSON.stringify(known)};`;
    },
    configResolved(config) {
      base = config.base;
      if (config.command !== 'build') return;
      const drift = versionDrift(config.root);
      if (drift.length > 0) {
        throw new Error(
          `coffre's pages need the versions they were built with: ${drift.join('; ')}. ` +
            '`coffre update` pins them all, or set them by hand, exactly, in package.json',
        );
      }
    },
    generateBundle(_options, bundle) {
      if (this.environment.name !== 'client') return;
      preloads = pagePreloads(bundle, base);
      const files = Object.values(bundle).map((file) => ({ name: file.fileName, code: textOf(file) }));
      const found = serverCodeIn(files);
      if (found.length > 0) {
        this.error(
          `What the browser loads holds server code:\n  ${found.join('\n  ')}\n` +
            'A page imports something of the server: pages reach the API only through context.client.',
        );
      }
    },
  };
}
