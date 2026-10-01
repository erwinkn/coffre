#!/usr/bin/env node
// Seed a project, two environments, a few secrets and some grants.
//
// Writes go through the API, not straight into Postgres, so the seed itself is
// audited like anything else -- and so the seed exercises the same envelope
// and audit code path the CLI and UI use.

import {
    loadLocalSeedConfig,
    LOCAL_SEED_DIRECTORY,
    LOCAL_SEED_GRANTS,
} from './seed-config.mjs';

const local = loadLocalSeedConfig(process.env);
const API = local.apiUrl;
const IDP = local.idpUrl;
const AUD = local.audience;
const ADMIN = local.rootAdmin;

const pg = (await import('pg')).default;
const pool = new pg.Pool({
    connectionString: local.databaseUrl,
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
    if (!response.ok) {
        const detail = await response.text();
        throw new Error(`${method} ${path} -> ${response.status} ${detail}`);
    }
    return response.json();
}

const put = (token, path, body) => call(token, 'PUT', path, body);
const patch = (token, path, body) => call(token, 'PATCH', path, body);
const member = ({ principalType, principalId }) =>
    encodeURIComponent(`${principalType === 'user' ? 'user' : 'token'}:${principalId}`);

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
//
// Syncs hold references to secrets, versions and environments, and sign-in
// sessions, device logins and linked accounts to principals, so they go next.
console.log('==> resetting local data');
await pool.query('DELETE FROM audit_log');
await pool.query('DELETE FROM sync_keys');
await pool.query('DELETE FROM syncs');
await pool.query('DELETE FROM credentials');
await pool.query('DELETE FROM device_authorizations');
await pool.query('DELETE FROM identities');
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

await put(adminToken, '/api/projects/market', { name: 'Acme Market' });
for (const [slug, name] of [
    ['dev', 'Development'],
    ['prod', 'Production'],
]) {
    await put(adminToken, `/api/projects/market/${slug}`, { name });
}
console.log('==> created project market with environments dev, prod');

// Members first. Access refuses anyone who is not a member (HTTP 409):
// membership is a separate write from project access.
for (const principal of LOCAL_SEED_DIRECTORY) {
    await put(adminToken, `/api/members/${member(principal)}`, {});
}
console.log('==> registered directory principals (lead, dev, auditor, accessmgr, outsider, ci-deploy.access)');

// A mix of scopes, so the UI shows both kinds of grant:
//   lead     -- project admin: can add environments and manage access
//   dev      -- write, but only on dev
//   auditor  -- read across the whole project
//   ci       -- a machine principal, matched on its service-token common name
// outsider is in the directory with no grants — the login page's closed door.
for (const grant of LOCAL_SEED_GRANTS) {
    const place = grant.environmentSlug === undefined ? 'market' : `market/${grant.environmentSlug}`;
    await patch(adminToken, `/api/access/${member(grant)}`, { [place]: grant.role });
}
console.log('==> granted access to lead, dev, auditor, accessmgr and ci-deploy.access');

const values = {
    dev: {
        DATABASE_URL: 'postgres://127.0.0.1:5432/market_dev',
        REDIS_URL: 'redis://127.0.0.1:6379/0',
        STRIPE_SECRET_KEY: 'sk_test_51LocalDevOnlyNotARealKey',
        JWT_SIGNING_SECRET: 'dev-signing-secret-not-for-prod',
    },
    prod: {
        DATABASE_URL: 'postgres://10.0.0.5:5432/market_prod',
        REDIS_URL: 'redis://10.0.0.6:6379/0',
        STRIPE_SECRET_KEY: 'sk_live_51LocalDevOnlyNotARealKey',
        JWT_SIGNING_SECRET: 'prod-signing-secret-not-for-prod',
    },
};

for (const [environment, secrets] of Object.entries(values)) {
    await patch(adminToken, `/api/secrets/market/${environment}`, secrets);
    console.log(`==> wrote ${Object.keys(secrets).length} secrets to market/${environment}`);
}

await pool.end();

console.log('\nSeeded. Try:');
console.log('  node --env-file=.env.dev apps/cli/src/main.ts login --email admin@acme.example');
console.log('  node --env-file=.env.dev apps/cli/src/main.ts list market/dev');
console.log('  node --env-file=.env.dev apps/cli/src/main.ts run market/dev -- printenv');
