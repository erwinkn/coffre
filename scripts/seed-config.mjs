const LOCAL_SEED_CONFIG = Object.freeze({
    ownerDatabaseUrl: 'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre',
    apiUrl: 'http://127.0.0.1:8080',
    idpUrl: 'http://127.0.0.1:8081',
    audience: 'coffre-local-dev-aud',
    rootAdmin: 'erwin@equisafe.io',
});

/**
 * Resolve the destructive seed targets, refusing mixed environments.
 *
 * `node --env-file` deliberately gives already-exported variables precedence.
 * Without exact target validation, a production database URL exported by the
 * caller could be combined with COFFRE_AUTH_MODE=dev from `.env.dev`.
 */
export function loadLocalSeedConfig(env) {
    if (env.COFFRE_AUTH_MODE !== 'dev') {
        throw new Error('seed refuses to run unless COFFRE_AUTH_MODE=dev');
    }

    const resolved = {
        ownerDatabaseUrl:
            env.COFFRE_OWNER_DATABASE_URL ?? LOCAL_SEED_CONFIG.ownerDatabaseUrl,
        apiUrl: env.COFFRE_API_URL ?? LOCAL_SEED_CONFIG.apiUrl,
        idpUrl: env.COFFRE_DEV_IDP_URL ?? LOCAL_SEED_CONFIG.idpUrl,
        audience: env.COFFRE_ACCESS_AUD ?? LOCAL_SEED_CONFIG.audience,
        rootAdmin: env.COFFRE_ROOT_ADMINS ?? LOCAL_SEED_CONFIG.rootAdmin,
    };

    for (const key of Object.keys(LOCAL_SEED_CONFIG)) {
        if (resolved[key] !== LOCAL_SEED_CONFIG[key]) {
            throw new Error(
                `seed refuses non-local ${key}: expected ${LOCAL_SEED_CONFIG[key]}`,
            );
        }
    }

    return resolved;
}
