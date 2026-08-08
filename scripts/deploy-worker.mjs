import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const webDirectory = resolve(repositoryRoot, 'apps/web');
const builtConfigPath = resolve(webDirectory, 'dist/server/wrangler.json');
const sentinel = '__COFFRE_HYPERDRIVE_ID__';

const requiredSecrets = [
  'COFFRE_ACCESS_ISSUER',
  'COFFRE_ACCESS_JWKS_URL',
  'COFFRE_ACCESS_AUD',
  'COFFRE_ROOT_ADMINS',
  'COFFRE_KEK_LOCAL',
  'COFFRE_KEK_ID',
  'COFFRE_AUDIT_CHAIN_KEY',
];

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`missing required deployment environment variable: ${name}`);
  return value;
}

function run(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd: webDirectory, env: process.env, stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} exited with ${signal ?? code}`));
    });
  });
}

const hyperdriveId = requiredEnvironment('CLOUDFLARE_HYPERDRIVE_ID');
if (!/^[0-9a-f-]{32,36}$/i.test(hyperdriveId)) {
  throw new Error('CLOUDFLARE_HYPERDRIVE_ID is not a valid Cloudflare resource ID');
}
requiredEnvironment('CLOUDFLARE_ACCOUNT_ID');
const dryRun = process.env.COFFRE_DEPLOY_DRY_RUN === 'true';
if (!dryRun) requiredEnvironment('CLOUDFLARE_API_TOKEN');

const secrets = Object.fromEntries(
  requiredSecrets.map((name) => [name, requiredEnvironment(name)]),
);
// Wrangler intentionally preserves secret bindings omitted from a secrets
// file. Always overwrite the optional rotation value so removing it from the
// protected environment cannot leave an old decryption key active.
secrets.COFFRE_KEK_LOCAL_PREVIOUS = process.env.COFFRE_KEK_LOCAL_PREVIOUS?.trim() ?? '';

const temporaryDirectory = await mkdtemp(join(tmpdir(), 'coffre-worker-deploy-'));
let builtConfig;
try {
  const secretsPath = join(temporaryDirectory, 'secrets.json');
  builtConfig = await readFile(builtConfigPath, 'utf8');
  if (!builtConfig.includes(sentinel)) {
    throw new Error('built Wrangler configuration is missing the Hyperdrive sentinel');
  }

  await writeFile(builtConfigPath, builtConfig.replaceAll(sentinel, hyperdriveId));
  await writeFile(secretsPath, JSON.stringify(secrets), { mode: 0o600 });

  const wrangler = resolve(webDirectory, 'node_modules/wrangler/bin/wrangler.js');
  const deployArguments = [
    wrangler,
    'deploy',
    '--secrets-file',
    secretsPath,
  ];
  if (dryRun) deployArguments.push('--dry-run');
  await run(process.execPath, deployArguments);
} finally {
  if (builtConfig !== undefined) {
    await writeFile(builtConfigPath, builtConfig);
  }
  await rm(temporaryDirectory, { recursive: true, force: true });
}
