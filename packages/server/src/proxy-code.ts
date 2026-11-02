import type { ProxyDefinition } from '@coffre/core/vault';

import type { CoffrePlugin } from './plugins.ts';

/**
 * What the deployment's code says of its credential proxy that the Proxy
 * tab's API needs (docs/design/proxy-ui.md, sections 1 and 6): whether the
 * tab may write (`editable`, off unless set), whether definitions may reach
 * local fakes (`insecureUpstreams`), every name code defines, of any kind,
 * which no UI item takes and no release frees while this code runs, each
 * of those items as the tab shows it, locked, and how long a save's old
 * upstream may still be sent values decided before it (`cacheSeconds`).
 */
export type ProxyCode = {
  editable: boolean;
  insecureUpstreams: boolean;
  names: readonly string[];
  items: readonly ProxyCodeItem[];
  /** How long values a use decided keep serving from an isolate's memory (`cacheSeconds`): how long after a save they may still reach the old upstream. */
  cacheSeconds: number;
};

/**
 * An item the deployment's code defines, as the Proxy tab shows it, locked
 * (R66): its definition in the tab's shape, where it serves, and what code
 * says that no field of a UI item can.
 *
 *   credentials: { maps: { upstream: 'https://maps.googleapis.com', inject: query('key', '{MAPS_API_KEY}'), environments: ['market/prod'] } }
 *   -> { definition: { kind: 'route', name: 'maps', … }, environments: ['market/prod'], limitPerService: false, bound: false }
 */
export type ProxyCodeItem = {
  definition: ProxyDefinition;
  /** The environments it serves, by path, as its `environments` names them; null: every one. Its name is taken in all of them. */
  environments: string[] | null;
  /** Its limit is a function of the service, which no form shows: `definition.limit` is then none. */
  limitPerService: boolean;
  /** Its requests leave through a binding code gives it (a route's egress, a tunnel's network), which has no name to show. */
  bound: boolean;
};

const CODE = Symbol('coffre.proxy-code');

/** `plugin`, carrying its proxy's `code` for the API to find (`proxyCodeOf`). */
export function withProxyCode<T extends CoffrePlugin>(plugin: T, code: ProxyCode): T {
  return Object.assign(plugin, { [CODE]: code });
}

/** The credential proxy's code among the deployment's plugins; null when it adds none. */
export function proxyCodeOf(plugins: readonly CoffrePlugin[]): ProxyCode | null {
  for (const plugin of plugins) {
    const code = (plugin as { [CODE]?: ProxyCode })[CODE];
    if (code !== undefined) return code;
  }
  return null;
}
