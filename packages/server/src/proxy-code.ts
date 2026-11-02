import type { CoffrePlugin } from './plugins.ts';

/**
 * What the deployment's code says of its credential proxy that the Proxy
 * tab's API needs (docs/design/proxy-ui.md, sections 1 and 6): whether the
 * tab may write (`editable`, off unless set), whether definitions may reach
 * local fakes (`insecureUpstreams`), and every name code defines, of any
 * kind, which no UI item takes and no release frees while this code runs.
 */
export type ProxyCode = { editable: boolean; insecureUpstreams: boolean; names: readonly string[] };

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
