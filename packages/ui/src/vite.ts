// `@coffre/ui/vite`: what a deployment's Vite build needs to carry coffre's
// pages, beside TanStack Start's and React's own plugins:
//
//   plugins: [cloudflare(…), tanstackStart(), viteReact(), coffre()]
//
// It runs in Node, in the deployment's build; nothing here reaches a page.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import type { Plugin } from 'vite';

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
 * it for the routes it finds in the app's own `src/routes`; coffre's come
 * prebuilt from this package, so there are none to find. The root alone
 * carries the client entry, which is all the pages need: each route's code
 * is loaded as the route is.
 */
function routesManifest(): void {
  const scope = globalThis as { TSS_ROUTES_MANIFEST?: unknown };
  scope.TSS_ROUTES_MANIFEST ??= { __root__: {} };
}

/**
 * coffre's pages in a deployment's build: its static files under
 * `/_coffre/`, as the server expects them; a server build that holds what
 * it renders with; the versions it shares, as built; and nothing of the
 * server in what the browser loads.
 */
export function coffre(): Plugin {
  return {
    name: 'coffre',
    config() {
      routesManifest();
      return {
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
    configResolved(config) {
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
      const files = Object.values(bundle).map((file) => ({
        name: file.fileName,
        code: file.type === 'chunk' ? file.code : typeof file.source === 'string' ? file.source : '',
      }));
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
