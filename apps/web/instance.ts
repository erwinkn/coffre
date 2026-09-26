import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Where one copy of coffre runs, kept apart from what coffre is.
 *
 * `wrangler.jsonc` beside this file describes coffre: its entry point, its
 * compatibility date, and the Hyperdrive binding and Cron schedule the code
 * relies on. A deployment adds its Worker name, its domain, how people sign
 * in and which secrets it needs, in a file of its own that names no code:
 *
 *   COFFRE_INSTANCE=deploy/erwinkn.jsonc pnpm --dir apps/web deploy
 *
 * The file uses Wrangler's own keys. Each key it sets replaces coffre's value
 * outright instead of merging into it, so its `vars` and `secrets` are the
 * whole list, readable in one place.
 */

/** The keys an instance may set. Everything else describes the code. */
const INSTANCE_KEYS = new Set(['name', 'routes', 'workers_dev', 'vars', 'secrets']);

/** Values that are only ever secrets. As a var, one would sit in plain text in the file and the dashboard. */
const SECRET_ONLY = /^COFFRE_(KEK_LOCAL(_PREVIOUS)?|AUDIT_CHAIN_KEY|SIGNIN_\w+_CLIENT_SECRET)$/;

const WORKER_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export type Instance = {
  name: string;
  routes?: unknown[];
  workers_dev?: boolean;
  vars?: Record<string, string>;
  secrets?: { required: string[] };
};

/** JSON with comments and trailing commas, which is how Wrangler reads `.jsonc`. */
export function parseJsonc(text: string): unknown {
  let json = '';
  // Where in `json` a comma waits for the value after it, if one does.
  let comma = -1;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === '/' && text[i + 1] === '/') {
      while (i + 1 < text.length && text[i + 1] !== '\n') i++;
    } else if (char === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end === -1) throw new SyntaxError('unterminated /* comment');
      json += ' ';
      i = end + 1;
    } else if (char === '"') {
      let end = i + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      json += text.slice(i, end + 1);
      comma = -1;
      i = end;
    } else if ((char === '}' || char === ']') && comma !== -1) {
      json = json.slice(0, comma) + json.slice(comma + 1) + char;
      comma = -1;
    } else {
      if (char === ',') comma = json.length;
      else if (!/\s/.test(char)) comma = -1;
      json += char;
    }
  }
  return JSON.parse(json);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Check an instance file's contents, failing on the first problem. */
export function parseInstance(value: unknown): Instance {
  if (!isRecord(value)) throw new Error('must be an object');
  // An editor hint, not a setting.
  const { $schema: _schema, ...instance } = value;

  for (const key of Object.keys(instance)) {
    if (!INSTANCE_KEYS.has(key)) {
      throw new Error(
        `"${key}" is not an instance setting. An instance sets ${[...INSTANCE_KEYS].join(', ')}; the rest is coffre's wrangler.jsonc`,
      );
    }
  }

  const { name, routes, workers_dev: workersDev, vars, secrets } = instance;
  if (typeof name !== 'string' || !WORKER_NAME.test(name)) {
    throw new Error('"name" must be a Worker name: lowercase letters, digits and dashes');
  }
  if (routes !== undefined && !Array.isArray(routes)) throw new Error('"routes" must be a list');
  if (workersDev !== undefined && typeof workersDev !== 'boolean') {
    throw new Error('"workers_dev" must be true or false');
  }

  // Auth mode and secrets decide each other: Access needs its issuer and
  // audience, sign-in its providers' client secrets.
  if ((vars === undefined) !== (secrets === undefined)) {
    throw new Error(
      '"vars" and "secrets" go together: set both, or neither to keep coffre\'s Cloudflare Access defaults',
    );
  }

  if (vars !== undefined) {
    if (!isRecord(vars)) throw new Error('"vars" must be an object');
    for (const [key, entry] of Object.entries(vars)) {
      if (typeof entry !== 'string') throw new Error(`vars.${key} must be a string`);
      if (entry.trim() === '') throw new Error(`vars.${key} is empty: fill it in, or leave it out`);
      if (SECRET_ONLY.test(key)) {
        throw new Error(`${key} must be a secret, listed in secrets.required, not a var`);
      }
    }
    // Replacing coffre's vars drops its auth mode, so the instance must say.
    const mode = vars.COFFRE_AUTH_MODE;
    if (mode !== 'cloudflare' && mode !== 'signin') {
      throw new Error('vars.COFFRE_AUTH_MODE must be "cloudflare" or "signin"');
    }
  }

  if (secrets !== undefined) {
    const required = isRecord(secrets) ? secrets.required : undefined;
    if (!Array.isArray(required) || !required.every((entry) => typeof entry === 'string')) {
      throw new Error('"secrets" must be { "required": [names] }');
    }
    for (const secret of required as string[]) {
      if (isRecord(vars) && secret in vars) {
        throw new Error(`${secret} is both a var and a secret`);
      }
    }
  }

  return instance as Instance;
}

/**
 * The Cloudflare Vite plugin's `config` hook for the file `COFFRE_INSTANCE`
 * names, or nothing when it names none.
 *
 * A relative path is relative to the coffre checkout, wherever the command
 * runs from: pnpm runs each package's scripts from its own directory.
 */
export function instanceConfig(
  env: Readonly<Record<string, string | undefined>>,
): ((config: Record<string, unknown>) => void) | undefined {
  const path = env.COFFRE_INSTANCE?.trim();
  if (!path) return undefined;
  const file = resolve(import.meta.dirname, '../..', path);

  let instance: Instance;
  try {
    instance = parseInstance(parseJsonc(readFileSync(file, 'utf8')));
  } catch (error) {
    throw new Error(`COFFRE_INSTANCE ${file}: ${(error as Error).message}`, { cause: error });
  }

  // The plugin deep-merges a returned object, which would append the
  // instance's routes and secrets to coffre's. Assigning replaces them.
  return (config) => {
    Object.assign(config, instance, { topLevelName: instance.name });
  };
}
