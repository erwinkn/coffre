const LOCAL_SEED_CONFIG = Object.freeze({
    databaseUrl: 'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre',
    apiUrl: 'http://127.0.0.1:3000',
    idpUrl: 'http://127.0.0.1:8081',
    audience: 'coffre-local-dev-aud',
    rootAdmin: 'admin@acme.example',
});

/**
 * Identities the login page lists as seeded personas.
 *
 * Root admin is deployment config (`COFFRE_ROOT_ADMINS`), not a directory row.
 * Everyone else must be registered here before `createGrant` will accept them.
 * `outsider@` is registered with no grants so the closed-door view is a denial,
 * not `/unregistered`.
 */
export const LOCAL_SEED_DIRECTORY = Object.freeze([
    Object.freeze({ principalType: 'user', principalId: 'lead@acme.example' }),
    Object.freeze({ principalType: 'user', principalId: 'dev@acme.example' }),
    Object.freeze({ principalType: 'user', principalId: 'auditor@acme.example' }),
    Object.freeze({ principalType: 'user', principalId: 'accessmgr@acme.example' }),
    Object.freeze({ principalType: 'user', principalId: 'outsider@acme.example' }),
    Object.freeze({ principalType: 'service', principalId: 'ci-deploy.access' }),
]);

export const LOCAL_SEED_GRANTS = Object.freeze([
    Object.freeze({ principalType: 'user', principalId: 'lead@acme.example', role: 'owner' }),
    Object.freeze({
        principalType: 'user',
        principalId: 'dev@acme.example',
        role: 'developer',
        environmentSlug: 'dev',
    }),
    Object.freeze({ principalType: 'user', principalId: 'auditor@acme.example', role: 'auditor' }),
    Object.freeze({
        principalType: 'user',
        principalId: 'accessmgr@acme.example',
        role: 'access-manager',
    }),
    Object.freeze({
        principalType: 'service',
        principalId: 'ci-deploy.access',
        role: 'viewer',
        environmentSlug: 'prod',
    }),
]);

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
        databaseUrl: env.DATABASE_URL ?? LOCAL_SEED_CONFIG.databaseUrl,
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
