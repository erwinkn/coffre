#!/usr/bin/env node
// Seed a project, two environments, a few secrets and some grants.
//
// Writes go through the API, not straight into Postgres, so the seed itself is
// audited like anything else -- and so the seed exercises the same envelope
// and audit code path the CLI and UI use. It signs in as the root admin the
// way a browser does, through the dev IdP's stand-in GitHub.

import { browser } from './browser.mjs';
import {
    loadLocalSeedConfig,
    LOCAL_SEED_DIRECTORY,
    LOCAL_SEED_GRANTS,
} from './seed-config.mjs';

const local = loadLocalSeedConfig(process.env);
const API = local.apiUrl;
const IDP = local.idpUrl;
const ADMIN = local.rootAdmin;

const pg = (await import('pg')).default;
const pool = new pg.Pool({
    connectionString: local.databaseUrl,
});

const { signIn, call } = browser(API, IDP);

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
await pool.query('DELETE FROM secret_references');
await pool.query('ALTER TABLE audit_log DISABLE TRIGGER USER');
await pool.query('DELETE FROM audit_log');
await pool.query('ALTER TABLE audit_log ENABLE TRIGGER USER');
await pool.query('DELETE FROM credentials');
await pool.query('DELETE FROM device_authorizations');
await pool.query('DELETE FROM identities');
await pool.query('DELETE FROM service_bindings');
await pool.query('DELETE FROM consumed_tokens');
await pool.query('DELETE FROM vault_grants');
await pool.query('DELETE FROM vault_members');
await pool.query('DELETE FROM secret_folders');
await pool.query('DELETE FROM project_folders');
await pool.query('UPDATE secrets SET current_version_id = NULL');
await pool.query('DELETE FROM secret_versions');
await pool.query('DELETE FROM secrets');
await pool.query('DELETE FROM environments');
await pool.query('DELETE FROM projects');
await pool.query(
    "UPDATE audit_chain_head SET next_seq = 0, head_hash = decode(repeat('00', 32), 'hex')",
);

const admin = await signIn(ADMIN);

await put(admin, '/api/projects/market', { name: 'Acme Market' });
for (const [slug, name] of [
    ['dev', 'Development'],
    ['prod', 'Production'],
]) {
    await put(admin, `/api/projects/market/${slug}`, { name });
}
console.log('==> created project market with environments dev, prod');

// Members first. Access refuses anyone who is not a member (HTTP 409):
// membership is a separate write from project access.
for (const principal of LOCAL_SEED_DIRECTORY) {
    await put(admin, `/api/members/${member(principal)}`, {});
}
console.log('==> registered directory principals (lead, dev, auditor, accessmgr, outsider, ci-deploy)');

// A mix of scopes, so the UI shows both kinds of grant:
//   lead     -- project admin: can add environments and manage access
//   dev      -- write, but only on dev
//   auditor  -- read across the whole project
//   ci       -- a service, with a token of its own
// outsider is in the directory with no grants — the login page's closed door.
for (const grant of LOCAL_SEED_GRANTS) {
    const place = grant.environmentSlug === undefined ? 'market' : `market/${grant.environmentSlug}`;
    await patch(admin, `/api/access/${member(grant)}`, { [place]: grant.role });
}
console.log('==> granted access to lead, dev, auditor, accessmgr and ci-deploy');

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
    await patch(admin, `/api/secrets/market/${environment}`, secrets);
    console.log(`==> wrote ${Object.keys(secrets).length} secrets to market/${environment}`);
}

const ci = await post(admin, '/api/members/token:ci-deploy/tokens', { label: 'local', expiresInDays: 30 });
console.log('==> issued ci-deploy a token, for 30 days');

// The seed's own session ends here, rather than lingering in the admin's list.
await fetch(`${API}/auth/signout`, {
    method: 'POST',
    headers: { cookie: admin, origin: API, 'sec-fetch-site': 'same-origin' },
    redirect: 'manual',
});
await pool.end();

console.log(`\nSeeded. ci-deploy, which reads market/prod, holds this token, for \`coffre login ${API} --token\`\n(from a home of its own: it replaces the session saved there):\n  ${ci.token}`);
