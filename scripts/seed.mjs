#!/usr/bin/env node
// Seed a project, two environments, a few secrets and some grants.
//
// Writes go through the API, not straight into Postgres, so the seed itself is
// audited like anything else -- and so the seed exercises the same envelope
// and audit code path the CLI and UI use.

import { loadLocalSeedConfig } from './seed-config.mjs';

const local = loadLocalSeedConfig(process.env);
const API = local.apiUrl;
const IDP = local.idpUrl;
const AUD = local.audience;
const ADMIN = local.rootAdmin;

const pg = (await import('pg')).default;
const pool = new pg.Pool({
    connectionString: local.ownerDatabaseUrl,
});

async function mint(params) {
    const url = new URL('/dev/mint', IDP);
    url.searchParams.set('aud', AUD);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const response = await fetch(url);
    if (!response.ok) throw new Error(`dev IdP returned ${response.status}`);
    return (await response.json()).token;
}

async function call(token, method, path, body) {
    const response = await fetch(`${API}${path}`, {
        method,
        headers: { 'cf-access-jwt-assertion': token, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`${method} ${path} -> ${response.status}`);
    return response.json();
}

const put = (token, path, body) => call(token, 'PUT', path, body);
const post = (token, path, body) => call(token, 'POST', path, body);

// Everything goes through the API, including the structural setup. That way the
// seed exercises the same authorisation and audit paths the UI and CLI use, and
// the resulting audit log is a realistic one rather than a log with no history
// of how any of this came to exist.
// Reset order matters. audit_log holds ON DELETE RESTRICT references to
// secrets, environments and projects, so it has to go FIRST -- otherwise every
// re-seed on top of an already-audited database fails on the environments
// delete. This only ever appeared to work because the log happened to be empty.
//
// This wholesale delete is possible only because the seed connects as the
// owner. The application role cannot do any of it: coffre_app has no DELETE on
// audit_log at all.
console.log('==> resetting local data');
await pool.query('DELETE FROM audit_log');
await pool.query('UPDATE secrets SET current_version_id = NULL');
await pool.query('DELETE FROM secret_versions');
await pool.query('DELETE FROM secrets');
await pool.query('DELETE FROM grants');
await pool.query('DELETE FROM principals');
await pool.query('DELETE FROM environments');
await pool.query('DELETE FROM projects');
await pool.query(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
);

const adminToken = await mint({ email: ADMIN });

await post(adminToken, '/v1/admin/projects', { slug: 'market', name: 'Equisafe Market' });
for (const [slug, name] of [
    ['dev', 'Development'],
    ['prod', 'Production'],
]) {
    await post(adminToken, '/v1/admin/projects/market/environments', { slug, name });
}
console.log('==> created project market with environments dev, prod');

// A mix of scopes, so the UI shows both kinds of grant:
//   lead     -- project admin: can add environments and manage access
//   dev      -- write, but only on dev
//   auditor  -- read across the whole project
//   ci       -- a machine principal, matched on its service-token common name
for (const grant of [
    { principalType: 'user', principalId: 'lead@equisafe.io', role: 'owner' },
    {
        principalType: 'user',
        principalId: 'dev@equisafe.io',
        role: 'developer',
        environmentSlug: 'dev',
    },
    // The two roles that motivated having roles at all: both deliberately
    // exclude secret.read, so neither can see a single secret value.
    { principalType: 'user', principalId: 'auditor@equisafe.io', role: 'auditor' },
    { principalType: 'user', principalId: 'accessmgr@equisafe.io', role: 'access-manager' },
    {
        principalType: 'service',
        principalId: 'ci-deploy.access',
        role: 'viewer',
        environmentSlug: 'prod',
    },
]) {
    await post(adminToken, '/v1/admin/projects/market/grants', grant);
}
console.log('==> granted access to lead, dev, auditor, accessmgr and ci-deploy.access');

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
console.log('  node --env-file=.env.dev apps/cli/src/main.ts login --email erwin@equisafe.io');
console.log('  node --env-file=.env.dev apps/cli/src/main.ts list market/dev');
console.log('  node --env-file=.env.dev apps/cli/src/main.ts run market/dev -- printenv');
