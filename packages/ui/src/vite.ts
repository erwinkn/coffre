// `@coffre/ui/vite`: what a deployment's Vite build needs to carry coffre's
// pages, beside TanStack Start's and React's own plugins:
//
//   plugins: [cloudflare(…), tanstackStart(), viteReact(), coffre()]
//
// It runs in Node, in the deployment's build; nothing here reaches a page.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { searchForWorkspaceRoot, type Plugin } from 'vite';

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
 * coffre's pages in a deployment's build: its static files under
 * `/_coffre/`, as the server expects them; a server build that holds what
 * it runs; and the versions it shares, as built.
 */
export function coffre(): Plugin {
  return {
    name: 'coffre',
    config(config) {
      return {
        // `vite dev` serves coffre's files from this package, wherever it
        // is: under node_modules, inside the project, as installed; or
        // linked from elsewhere. Naming it keeps the project's own root.
        server: { fs: { allow: [searchForWorkspaceRoot(resolve(config.root ?? '')), fileURLToPath(new URL('..', import.meta.url))] } },
        // The server's build holds all it runs, as a Worker's does: run by
        // Node, it then resolves nothing from node_modules, where pnpm lets
        // a deployment reach only its own dependencies.
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
  };
}
