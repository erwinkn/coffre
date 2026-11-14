#!/usr/bin/env node
// Seed a project, two environments, a few secrets and some grants.
//
// Writes go through the API, not straight into Postgres, so the seed itself is
// audited like anything else, and exercises the same authorization and vault
// paths the CLI and UI use. It signs in first, as the Owner the vault makes,
// the way a browser does, through the dev IdP's stand-in GitHub.
//
// It wants a fresh instance: dev/start.sh drops the database and the Workers'
// local storage before it starts the stack (dev/reset.mjs). The vault's log is
// signed, so no SQL can start it over under a running signer.

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

// Behind a tunnel (dev/start.sh), the stack's own URLs are its public ones.
const tunnel = { api: process.env.COFFRE_DEV_PUBLIC_URL, idp: process.env.COFFRE_DEV_IDP_PUBLIC_URL };

const { signIn, send, call } = browser(API, IDP, tunnel);

const put = (session, path, body) => call(session, 'PUT', path, body);
const patch = (session, path, body) => call(session, 'PATCH', path, body);
const post = (session, path, body) => call(session, 'POST', path, body);
const member = ({ principalType, principalId }) =>
    encodeURIComponent(`${principalType === 'user' ? 'user' : 'token'}:${principalId}`);

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
await send(admin, 'POST', '/auth/signout');

console.log(`\nSeeded. ci-deploy, which reads market/prod, holds this token, for \`coffre login ${API} --token\`\n(from a home of its own: it replaces the session saved there):\n  ${ci.token}`);
