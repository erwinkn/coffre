import manifest from '../package.json' with { type: 'json' };

/**
 * The version of coffre this server is, as its package says: what `coffre
 * migrate` holds the CLI to, since the CLI applies its own migrations.
 */
export const COFFRE_VERSION: string = manifest.version;
