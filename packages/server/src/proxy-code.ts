import type { Deployment } from '@coffre/core/deployment';
import type { ProxyDefinition } from '@coffre/core/vault';

import type { CoffrePlugin } from './plugins.ts';

/**
 * What the deployment's code says of its credential proxy that the Proxy
 * tab's API needs (docs/design/proxy-ui.md, sections 1 and 6): whether the
 * tab may write (`editable`, its `deployment.ts`'s `proxy.editable`),
 * whether definitions may reach local fakes (`insecureUpstreams`), every
 * name code defines, of any kind, which no UI item takes and no release
 * frees while this code runs, each of those items as the tab shows it,
 * locked, and how long a save's old upstream may still be sent values
 * decided before it (`windowSeconds`).
 */
export type ProxyCode = PluginCode & {
  editable: boolean;
  /**
   * How long a request may still send, or answer, after its values were decided, in seconds: how long after a save
   * they may still reach the old upstream. R, the deployment's `proxy.revokedWithinSeconds`, cached values or not.
   */
  windowSeconds: number;
};

/** What the plugin itself carries, its code's part, which the gate reserves the names of: the rest is the deployment's (`proxyCodeWith`). */
export type PluginCode = {
  insecureUpstreams: boolean;
  names: readonly string[];
  items: readonly ProxyCodeItem[];
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
  /**
   * How its allow list matches where code reads it otherwise than the tab:
   * `code`, an `allow` in code, whose trailing slash takes what is below it
   * (`/files/`, which the tab writes `/files/**`); `legacy`, `methods` and
   * `paths` as before 0.16, each path compared as written and `*` itself,
   * never a glob, with `methods` as code wrote them, upper-cased: null where
   * unset (any), `[]` taking none, which the tab's `methods: []` (any) cannot
   * say, and kept apart since `paths: []` has no allow entry to carry them.
   * Null: no allow list, or as the tab's.
   */
  allowAs: { from: 'code' | 'legacy'; methods: string[] | null } | null;
};

const CODE = Symbol('coffre.proxy-code');

/** `plugin`, carrying its proxy's `code` for the gate and the API to find (`proxyCodeOf`). */
export function withProxyCode<T extends CoffrePlugin>(plugin: T, code: PluginCode): T {
  return Object.assign(plugin, { [CODE]: code });
}

/** The credential proxy's code among the deployment's plugins; null when it adds none. */
export function proxyCodeOf(plugins: readonly CoffrePlugin[]): PluginCode | null {
  for (const plugin of plugins) {
    const code = (plugin as { [CODE]?: PluginCode })[CODE];
    if (code !== undefined) return code;
  }
  return null;
}

/** The same, with what `deployment` chose for the proxy: what the Proxy tab's API reads. */
export function proxyCodeWith(plugins: readonly CoffrePlugin[], deployment: Deployment): ProxyCode | null {
  const code = proxyCodeOf(plugins);
  return code === null ? null : { ...code, editable: deployment.proxy.editable, windowSeconds: deployment.proxy.revokedWithinSeconds };
}
