// `@coffre/ui/vite`: what a deployment's Vite build needs to carry coffre's
// pages, beside TanStack Start's and React's own plugins:
//
//   plugins: [cloudflare(…), tanstackStart(), viteReact(), coffre({ deployment })]
//
// It runs in Node, in the deployment's build; nothing here reaches a page.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SIGN_IN_PERIOD_SECONDS, type Deployment } from '@coffre/core/deployment';
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

/** The rate-limiting binding every sign-in that takes anyone passes first, on Workers (`app/wrangler.jsonc`). */
const SIGN_IN_BINDING = 'SIGN_IN_PER_SOURCE';

/** What `signInLimitProblem` reads of a Worker's config: the rate-limiting bindings, and the file they came from. */
export type WorkerConfig = {
  configPath?: unknown;
  ratelimits?: unknown;
};

/**
 * Why a Worker's config, as the build resolved it, does not count sign-ins as `deployment.ts` says; null when it
 * does. Cloudflare takes the number only from the config's `SIGN_IN_PER_SOURCE` binding, so the two must agree: a
 * deployment that lowered `services.signInsPerAddress` alone would still let 10,000 through. The config is the one
 * the Cloudflare plugin writes beside the built Worker (`dist/server/wrangler.json`), after it picked the file and
 * the environment (`CLOUDFLARE_ENV`), so that an `env.production` binding of its own is the one held to the object,
 * as wrangler deploys it. No such binding: nothing to compare.
 */
export function signInLimitProblem(config: WorkerConfig, deployment: Deployment): string | null {
  const bindings = Array.isArray(config.ratelimits) ? (config.ratelimits as { name?: unknown; simple?: { limit?: unknown; period?: unknown } }[]) : [];
  const binding = bindings.find((each) => each?.name === SIGN_IN_BINDING);
  if (binding === undefined) return null;
  const wanted = { limit: deployment.services.signInsPerAddress, period: SIGN_IN_PERIOD_SECONDS };
  const { limit, period } = binding.simple ?? {};
  if (limit === wanted.limit && period === wanted.period) return null;
  const file = typeof config.configPath === 'string' ? config.configPath : 'the Worker\'s wrangler config';
  return (
    `${file}'s ${SIGN_IN_BINDING} binding, as this build resolves it, allows ${String(limit)} sign-ins per ${String(period)} s, and deployment.ts's ` +
    `services.signInsPerAddress ${wanted.limit.toLocaleString('en-US')} per ${wanted.period} s. Cloudflare reads only the binding: ` +
    `set its "simple" to { "limit": ${wanted.limit}, "period": ${wanted.period} } (in the environment the build deploys, if it names one), ` +
    'or services.signInsPerAddress to what it says'
  );
}

/** What the plugin takes: the deployment's own object, from its `deployment.ts`. */
export type CoffreViteOptions = {
  /**
   * The deployment's `deployment.ts` object, which the build holds its
   * Worker's settings to: on Workers, `SIGN_IN_PER_SOURCE`'s limit in the
   * Worker's config as built (`signInLimitProblem`). Left out, nothing is
   * checked.
   */
  deployment?: Deployment;
};

/**
 * coffre's pages in a deployment's build: its static files under
 * `/_coffre/`, as the server expects them; a server build that holds what
 * it runs; the versions it shares, as built; and, given the deployment's
 * object, the Worker's settings held to it.
 */
export function coffre(options: CoffreViteOptions = {}): Plugin {
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
    // The Cloudflare plugin emits the Worker's config, with its environment applied, as `wrangler.json` beside each
    // Worker it builds; after it, the build holds that config to the object. A Node build emits none.
    generateBundle: {
      order: 'post',
      handler(_, bundle) {
        const asset = bundle['wrangler.json'];
        if (options.deployment === undefined || asset?.type !== 'asset') return;
        const limit = signInLimitProblem(JSON.parse(String(asset.source)) as WorkerConfig, options.deployment);
        if (limit !== null) this.error(limit);
      },
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
