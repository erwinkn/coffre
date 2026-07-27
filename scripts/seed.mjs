#!/usr/bin/env node
// Seed a project, two environments, a few secrets and some grants.
//
// Writes go through the API, not straight into Postgres, so the seed itself is
// audited like anything else -- and so the seed exercises the same envelope
// and audit code path the CLI and UI use.

const API = process.env.COFFRE_API_URL ?? 'http://127.0.0.1:8080';
const IDP = process.env.COFFRE_DEV_IDP_URL ?? 'http://127.0.0.1:8081';
const AUD = process.env.COFFRE_ACCESS_AUD ?? 'coffre-local-dev-aud';
const ADMIN = process.env.COFFRE_ROOT_ADMINS?.split(',')[0] ?? 'erwin@equisafe.io';

const pg = (await import('pg')).default;
const pool = new pg.Pool({
    connectionString:
        process.env.COFFRE_DATABASE_URL ??
        'postgresql://coffre_owner:local-dev-only@127.0.0.1:55432/coffre',
});

async function mint(params) {
    const url = new URL('/dev/mint', IDP);
    url.searchParams.set('aud', AUD);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const response = await fetch(url);
    if (!response.ok) throw new Error(`dev IdP returned ${response.status}`);
    return (await response.json()).token;
}

async function put(token, path, body) {
    const response = await fetch(`${API}${path}`, {
        method: 'PUT',
        headers: { 'cf-access-jwt-assertion': token, 'content-type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`PUT ${path} -> ${response.status}`);
    return response.json();
}

// Projects, environments and grants are structural, so they go in directly.
// Secret values do not: those go through the API so they are enveloped and
// audited properly.
console.log('==> resetting local data');
await pool.query('UPDATE secrets SET current_version_id = NULL');
await pool.query('DELETE FROM secret_versions');
await pool.query('DELETE FROM secrets');
await pool.query('DELETE FROM grants');
await pool.query('DELETE FROM environments');
await pool.query('DELETE FROM projects');
await pool.query('DELETE FROM audit_log');
await pool.query(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
);

const project = await pool.query(
    "INSERT INTO projects (slug, name) VALUES ('market', 'Equisafe Market') RETURNING id",
);
const environments = {};
for (const [slug, name] of [
    ['dev', 'Development'],
    ['prod', 'Production'],
]) {
    const row = await pool.query(
        'INSERT INTO environments (project_id, slug, name) VALUES ($1, $2, $3) RETURNING id',
        [project.rows[0].id, slug, name],
    );
    environments[slug] = row.rows[0].id;
}

await pool.query(
    `INSERT INTO grants (principal_type, principal_id, environment_id, capability, created_by)
     VALUES ('user',    'dev@equisafe.io',    $1, 'write', 'seed'),
            ('user',    'auditor@equisafe.io',$1, 'read',  'seed'),
            ('service', 'ci-deploy.access',   $2, 'read',  'seed')`,
    [environments.dev, environments.prod],
);
console.log('==> created project market with environments dev, prod');

const adminToken = await mint({ email: ADMIN });

const values = {
    dev: {
        DATABASE_URL: 'postgres://market:devpw@127.0.0.1:5432/market_dev',
        REDIS_URL: 'redis://127.0.0.1:6379/0',
        STRIPE_SECRET_KEY: 'sk_test_51LocalDevOnlyNotARealKey',
        JWT_SIGNING_SECRET: 'dev-signing-secret-not-for-prod',
    },
    prod: {
        DATABASE_URL: 'postgres://market:prodpw@10.0.0.5:5432/market_prod',
        REDIS_URL: 'redis://10.0.0.6:6379/0',
        STRIPE_SECRET_KEY: 'sk_live_51LocalDevOnlyNotARealKey',
        JWT_SIGNING_SECRET: 'prod-signing-secret-not-for-prod',
    },
};

for (const [environment, secrets] of Object.entries(values)) {
    for (const [key, value] of Object.entries(secrets)) {
        await put(adminToken, `/v1/projects/market/environments/${environment}/secrets/${key}`, {
            value,
        });
    }
    console.log(`==> wrote ${Object.keys(secrets).length} secrets to market/${environment}`);
}

await pool.end();

console.log('\nSeeded. Try:');
console.log('  export COFFRE_DEV_IDP_URL=http://127.0.0.1:8081');
console.log('  node apps/cli/src/main.ts login --email erwin@equisafe.io');
console.log('  node apps/cli/src/main.ts list market/dev');
console.log('  node apps/cli/src/main.ts run market/dev -- printenv');
