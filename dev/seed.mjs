#!/usr/bin/env node
// Seed a project, two environments, a few secrets and some grants.
//
// Writes go through the API, not straight into Postgres, so the seed itself is
// audited like anything else -- and so the seed exercises the same envelope
// and audit code path the CLI and UI use. It signs in first, as the Owner the
// vault bootstraps, the way a browser does, through the dev IdP's stand-in GitHub.

import { browser } from './browser.mjs';
import {
    loadLocalSeedConfig,
    LOCAL_SEED_DIRECTORY,
    LOCAL_SEED_GRANTS,
} from './seed-config.mjs';

const local = loadLocalSeedConfig(process.env);
const API = local.apiUrl;
const IDP = local.idpUrl;
const ADMIN = local.owner;

const { postgresClient } = await import('@coffre/db/connect');
const pool = postgresClient(local.databaseUrl, { max: 1 });

// Behind a tunnel (dev/start.sh), the stack's own URLs are its public ones.
const tunnel = { api: process.env.COFFRE_DEV_PUBLIC_URL, idp: process.env.COFFRE_DEV_IDP_PUBLIC_URL };

const { signIn, send, call } = browser(API, IDP, tunnel);

const put = (session, path, body) => call(session, 'PUT', path, body);
const patch = (session, path, body) => call(session, 'PATCH', path, body);
const post = (session, path, body) => call(session, 'POST', path, body);
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
// owner, and lifts the log's append-only triggers for it. Neither runtime
// login can do any of it: they have no DELETE on audit_log at all.
//
// Sign-in sessions, device logins, linked accounts and trust bindings refer
// to the vault's members, so they go next; then the members and grants,
// which go with the log that records them.
console.log('==> resetting local data');
await pool.unsafe('DELETE FROM secret_references');
await pool.unsafe('ALTER TABLE audit_log DISABLE TRIGGER USER');
await pool.unsafe('DELETE FROM audit_log');
await pool.unsafe('ALTER TABLE audit_log ENABLE TRIGGER USER');
await pool.unsafe('DELETE FROM vault_releases');
await pool.unsafe('DELETE FROM mcp_approvals');
await pool.unsafe('DELETE FROM mcp_connections');
await pool.unsafe('DELETE FROM oauth_clients');
await pool.unsafe('DELETE FROM credentials');
await pool.unsafe('DELETE FROM enrollments');
await pool.unsafe('DELETE FROM device_authorizations');
await pool.unsafe('DELETE FROM identities');
await pool.unsafe('DELETE FROM service_bindings');
await pool.unsafe('DELETE FROM consumed_tokens');
await pool.unsafe('DELETE FROM capped_alerts');
await pool.unsafe('DELETE FROM vault_grants');
await pool.unsafe('DELETE FROM vault_members');
await pool.unsafe('DELETE FROM dismissed_keys');
await pool.unsafe('UPDATE secrets SET current_version_id = NULL');
await pool.unsafe('DELETE FROM secret_versions');
await pool.unsafe('DELETE FROM secrets');
await pool.unsafe('DELETE FROM environments');
await pool.unsafe('DELETE FROM projects');
await pool.unsafe(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
);

const admin = await signIn(ADMIN);

await put(admin, '/api/projects/market', {});
for (const slug of ['dev', 'prod']) {
    await put(admin, `/api/projects/market/${slug}`, {});
}
console.log('==> created project market with environments dev, prod');

// Members first. Access refuses anyone who is not a member (HTTP 409):
// membership is a separate write from project access.
// dev and auditor reach every project by their instance role:
//   dev      -- Developer, on every project's dev
//   auditor  -- Auditor, every project's log
for (const { role, scope, ...principal } of LOCAL_SEED_DIRECTORY) {
    await put(admin, `/api/members/${member(principal)}`, role === undefined ? {} : { role, ...(scope === undefined ? {} : { scope }) });
}
console.log('==> registered directory principals (lead, dev, auditor, accessmgr, outsider, ci-deploy)');

// A mix of grants, so the UI shows both kinds beside the roles:
//   lead      -- project owner: can add environments and manage access
//   accessmgr -- manages market's access, reads nothing
//   ci        -- a service, reading prod, with a token of its own
// outsider is in the directory with no grants — the login page's closed door.
for (const grant of LOCAL_SEED_GRANTS) {
    const place = grant.environmentSlug === undefined ? 'market' : `market/${grant.environmentSlug}`;
    await patch(admin, `/api/access/${member(grant)}`, { [place]: grant.role });
}
console.log('==> granted access to lead, accessmgr and ci-deploy');

const values = {
    dev: {
        DATABASE_URL: 'postgres://127.0.0.1:5432/market_dev',
        REDIS_URL: 'redis://127.0.0.1:6379/0',
        STRIPE_SECRET_KEY: 'sk_test_51LocalDevOnlyNotARealKey',
        JWT_SIGNING_SECRET: 'dev-signing-secret-not-for-prod',
        // What the proxy page's prototype credentials name (dev/deployment/app/src/proxy-prototype.ts).
        OPENAI_API_KEY: 'sk-proj-LocalDevOnlyNotARealKey',
        AWS_ACCESS_KEY_ID: 'AKIALOCALDEVONLY0000',
        AWS_SECRET_ACCESS_KEY: 'local-dev-only-not-a-real-aws-secret',
        SCHUMAN_API_KEY: 'schuman-local-dev-only',
        MAPS_API_KEY: 'AIzaLocalDevOnlyNotARealKey',
    },
    prod: {
        DATABASE_URL: 'postgres://10.0.0.5:5432/market_prod',
        REDIS_URL: 'redis://10.0.0.6:6379/0',
        // Sensitive: the proxy page's prototype shows where a definition sending it may no longer point.
        STRIPE_SECRET_KEY: { value: 'sk_live_51LocalDevOnlyNotARealKey', sensitivity: 'sensitive' },
        JWT_SIGNING_SECRET: 'prod-signing-secret-not-for-prod',
        OPENAI_API_KEY: 'sk-proj-LocalProdOnlyNotARealKey',
        AWS_ACCESS_KEY_ID: 'AKIALOCALPRODONLY000',
        AWS_SECRET_ACCESS_KEY: { value: 'local-prod-only-not-a-real-aws-secret', sensitivity: 'sensitive' },
        SCHUMAN_API_KEY: 'schuman-local-prod-only',
        MAPS_API_KEY: 'AIzaLocalProdOnlyNotARealKey',
    },
};

for (const [environment, secrets] of Object.entries(values)) {
    await patch(admin, `/api/secrets/market/${environment}`, secrets);
    console.log(`==> wrote ${Object.keys(secrets).length} secrets to market/${environment}`);
}

const ci = await post(admin, '/api/members/token:ci-deploy/tokens', { label: 'local', expiresInDays: 30 });
console.log('==> issued ci-deploy a token, for 30 days');

// The seed's own session ends here, rather than lingering in the admin's list.
await send(admin, 'POST', '/auth/signout');
await pool.end();

console.log(`\nSeeded. ci-deploy, which reads market/prod, holds this token, for \`coffre login ${API} --token\`\n(from a home of its own: it replaces the session saved there):\n  ${ci.token}`);
