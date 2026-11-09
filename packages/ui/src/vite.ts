// `@coffre/ui/vite`: what a deployment's Vite build needs to carry coffre's
// pages, beside TanStack Start's and React's own plugins:
//
//   plugins: [cloudflare(…), tanstackStart(), viteReact(), coffre({ deployment })]
//
// It runs in Node, in the deployment's build; nothing here reaches a page.
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SIGN_IN_PERIOD_SECONDS, type Deployment } from '@coffre/core/deployment';
import { parse, printParseErrorCode, type ParseError } from 'jsonc-parser';
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

/**
 * Why the Worker's wrangler.jsonc in `root`, the Vite root the Cloudflare
 * plugin reads it from, does not count sign-ins as `deployment.ts` says;
 * null when it does. Cloudflare takes the number only from the file's
 * `SIGN_IN_PER_SOURCE` binding, so the two must agree: a deployment that
 * lowered `services.signInsPerAddress` alone would still let 10,000
 * through. No such file (Node), or no such binding: nothing to compare.
 */
export function signInLimitProblem(root: string, deployment: Deployment): string | null {
  const path = join(root, 'wrangler.jsonc');
  if (!existsSync(path)) return null;
  const errors: ParseError[] = [];
  const config = parse(readFileSync(path, 'utf8'), errors, { allowTrailingComma: true }) as {
    ratelimits?: { name?: unknown; simple?: { limit?: unknown; period?: unknown } }[];
  } | null;
  if (errors.length > 0) return `${path} is not valid JSONC: ${printParseErrorCode(errors[0]!.error)} at offset ${errors[0]!.offset}`;
  const binding = (Array.isArray(config?.ratelimits) ? config.ratelimits : []).find((each) => each?.name === SIGN_IN_BINDING);
  if (binding === undefined) return null;
  const wanted = { limit: deployment.services.signInsPerAddress, period: SIGN_IN_PERIOD_SECONDS };
  const { limit, period } = binding.simple ?? {};
  if (limit === wanted.limit && period === wanted.period) return null;
  return (
    `${path}'s ${SIGN_IN_BINDING} binding allows ${String(limit)} sign-ins per ${String(period)} s, and deployment.ts's ` +
    `services.signInsPerAddress ${wanted.limit.toLocaleString('en-US')} per ${wanted.period} s. Cloudflare reads only the binding: ` +
    `set its "simple" to { "limit": ${wanted.limit}, "period": ${wanted.period} }, or services.signInsPerAddress to what it says`
  );
}

/** What the plugin takes: the deployment's own object, from its `deployment.ts`. */
export type CoffreViteOptions = {
  /**
   * The deployment's `deployment.ts` object, which the build holds its
   * Worker's settings to: on Workers, `SIGN_IN_PER_SOURCE`'s limit in
   * wrangler.jsonc (`signInLimitProblem`). Left out, nothing is checked.
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
    configResolved(config) {
      if (config.command !== 'build') return;
      const limit = options.deployment === undefined ? null : signInLimitProblem(config.root, options.deployment);
      if (limit !== null) throw new Error(limit);
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
