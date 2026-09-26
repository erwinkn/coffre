import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const webDirectory = resolve(repositoryRoot, 'apps/web');
const builtConfigPath = resolve(webDirectory, 'dist/server/wrangler.json');
const sentinel = '__COFFRE_HYPERDRIVE_ID__';
const terminationSignals = ['SIGINT', 'SIGTERM'];

let activeChild;
let receivedSignal;

function interrupted() {
  if (receivedSignal) throw new Error(`deployment interrupted by ${receivedSignal}`);
}

function receiveSignal(signal) {
  receivedSignal ??= signal;
  if (activeChild && !activeChild.killed) activeChild.kill(signal);
}

const signalHandlers = new Map(
  terminationSignals.map((signal) => [signal, () => receiveSignal(signal)]),
);
for (const [signal, handler] of signalHandlers) process.on(signal, handler);

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`missing required deployment environment variable: ${name}`);
  return value;
}

function run(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd: webDirectory, env: process.env, stdio: 'inherit' });
    activeChild = child;
    let settled = false;
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      activeChild = undefined;
      callback();
    };
    child.once('error', (error) => finish(() => reject(error)));
    child.once('exit', (code, signal) => {
      finish(() => {
        if (code === 0) resolvePromise();
        else reject(new Error(`${command} exited with ${signal ?? code}`));
      });
    });
  });
}

// The build applied the instance file (apps/web/instance.ts). Without one it
// is coffre with no name of its own and no route, which has nowhere to go.
requiredEnvironment('COFFRE_INSTANCE');
const builtConfig = await readFile(builtConfigPath, 'utf8');
if (!builtConfig.includes(sentinel)) {
  throw new Error('built Wrangler configuration is missing the Hyperdrive sentinel');
}
const { name, routes = [], vars = {}, secrets: declared } = JSON.parse(builtConfig);
// The instance decides which secrets exist: Access needs its issuer and
// audience, sign-in its providers' client secrets.
const requiredSecrets = declared?.required ?? [];
if (requiredSecrets.length === 0) {
  throw new Error('built Wrangler configuration declares no required secrets');
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

const destination = routes.map((route) => route.pattern ?? route).join(', ') || 'no route';
console.log(`Deploying ${name} to ${destination}, in ${vars.COFFRE_AUTH_MODE} mode`);

const temporaryDirectory = await mkdtemp(join(tmpdir(), 'coffre-worker-deploy-'));
let replaced = false;
let deploymentError;
let cleanupError;
try {
  interrupted();
  const secretsPath = join(temporaryDirectory, 'secrets.json');
  replaced = true;
  await writeFile(builtConfigPath, builtConfig.replaceAll(sentinel, hyperdriveId));
  interrupted();
  await writeFile(secretsPath, JSON.stringify(secrets), { mode: 0o600 });
  interrupted();

  const wrangler = resolve(webDirectory, 'node_modules/wrangler/bin/wrangler.js');
  const deployArguments = [
    wrangler,
    'deploy',
    '--secrets-file',
    secretsPath,
  ];
  if (dryRun) deployArguments.push('--dry-run');
  await run(process.execPath, deployArguments);
  interrupted();
} catch (error) {
  deploymentError = error;
} finally {
  try {
    if (replaced) await writeFile(builtConfigPath, builtConfig);
  } catch (error) {
    cleanupError = error;
  }
  try {
    await rm(temporaryDirectory, { recursive: true, force: true });
  } catch (error) {
    cleanupError ??= error;
  }
}

for (const [signal, handler] of signalHandlers) process.off(signal, handler);
if (receivedSignal) process.kill(process.pid, receivedSignal);
if (cleanupError) throw cleanupError;
if (deploymentError) throw deploymentError;
