/**
 * Credentials the vault mints when a key is read, rather than stores: a
 * GitHub App's installation token, scoped R2 keys. The deployment holds the
 * root credential, in the vault's configuration and nowhere else, and names
 * each key it mints and what for (W108's prototype; docs/spikes/dynamic-secrets.md):
 *
 *   const release = githubApp({ appId: env.RELEASE_APP_ID, privateKey: env.RELEASE_APP_KEY });
 *   vault(env => ({
 *     kek, owners,
 *     minted: [{ at: 'infra/ci', key: 'GITHUB_TOKEN',
 *                from: release.tokens({ account: 'acme', repositories: ['infra'], permissions: { contents: 'write' } }) }],
 *   }))
 *
 * Whoever reads `infra/ci` gets a fresh token where a value would be: no
 * one reads the App's key, and no one widens what it mints but a deploy.
 */

/** One minted key's source: its root credential and the scope it mints, fixed when the deployment made it. */
export interface Minter {
  /** What kind of credential: `github-app`, `r2`. */
  readonly provider: string;
  /**
   * What it mints, none of it secret, as the log records it with each
   * mint and the pages show it: `{ app: '1001', account: 'acme',
   * repositories: ['infra'], permissions: { contents: 'write' } }`.
   */
  readonly scope: Readonly<Record<string, unknown>>;
  /** A fresh credential, abandoned when `signal` aborts. Throws `MintUnavailable` when its provider cannot be asked or refuses. */
  mint(signal: AbortSignal): Promise<Minted>;
}

export type Minted = {
  value: string;
  /** ISO 8601. */
  expiresAt: string;
  /** What the provider says it granted, when it says: logged beside the scope asked for. */
  granted?: Record<string, unknown>;
};

/** The provider could not be asked, or refused: the message says which, and never carries a credential. */
export class MintUnavailable extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'MintUnavailable';
  }
}
