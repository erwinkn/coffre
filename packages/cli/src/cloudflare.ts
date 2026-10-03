// Cloudflare, for `coffre setup` on Workers. Signing in is wrangler's: its
// browser login, then its token, which setup reads from a pipe and never
// shows. With it, setup calls Cloudflare's API itself, so that a database
// password travels only in a request's body, never in a command's
// arguments. Deploying is wrangler's again, the secrets on its stdin.
import { spawn } from 'node:child_process';
import { get } from 'node:http';
import { join } from 'node:path';

import { localCallback, openBrowser } from './browser.ts';
import type { Step } from './steps.ts';

/** Where wrangler's login listens for its callback, unless its link says otherwise. */
const WRANGLER_CALLBACK = 'http://localhost:8976/oauth/callback';

export type Run = { code: number | null; stdout: string; stderr: string };

/** wrangler as a deployment has it, run in its directory: `input` on its stdin, never in its arguments; `signal` stops it. */
export type Wrangler = (
  args: string[],
  options?: { input?: string; env?: NodeJS.ProcessEnv; onOutput?: (text: string) => void; signal?: AbortSignal },
) => Promise<Run>;

export function deploymentWrangler(dir: string): Wrangler {
  const bin = join(dir, 'node_modules', '.bin', process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler');
  return (args, { input, env, onOutput, signal } = {}) =>
    new Promise((resolve, reject) => {
      const child = spawn(bin, args, {
        cwd: dir,
        env: { ...process.env, ...env, WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' },
        stdio: ['pipe', 'pipe', 'pipe'],
        signal,
      });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8').on('data', (chunk: string) => {
        stdout += chunk;
        onOutput?.(chunk);
      });
      child.stderr.setEncoding('utf8').on('data', (chunk: string) => {
        stderr += chunk;
        onOutput?.(chunk);
      });
      child.on('error', reject);
      child.on('close', (code) => resolve({ code, stdout, stderr }));
      child.stdin.on('error', () => {});
      child.stdin.end(input ?? '');
    });
}

/** The tail of what a command said, for an error, without its banner. */
function said(run: Run): string {
  return `${run.stderr}\n${run.stdout}`.trim().split('\n').filter((line) => line.trim() !== '').slice(-3).join(' ');
}

/** Show an address to open, after what it is for. */
export type Link = (label: string, address: string) => void;

/**
 * A token for Cloudflare's API: CLOUDFLARE_API_TOKEN when set, else
 * wrangler's own, after its browser login when there is none yet.
 */
export async function cloudflareToken(wrangler: Wrangler, step: Step, link: Link): Promise<string> {
  const read = async () => {
    const run = await wrangler(['auth', 'token', '--json']);
    if (run.code !== 0) return null;
    try {
      return (JSON.parse(run.stdout) as { token?: string }).token ?? null;
    } catch {
      return null;
    }
  };
  const ready = await read();
  if (ready !== null) return ready;
  await login(wrangler, step, link);
  const token = await read();
  if (token === null) throw new Error('signed in to Cloudflare, but wrangler gave no token');
  return token;
}

/** Where a sign-in link sends the browser back to: its `redirect_uri`, when that is on this machine. */
export function callbackOf(link: string): URL {
  try {
    const redirect = new URL(new URL(link).searchParams.get('redirect_uri') ?? '');
    if (redirect.protocol === 'http:' && (redirect.hostname === 'localhost' || redirect.hostname === '127.0.0.1')) return redirect;
  } catch {
    // Not one: wrangler's own.
  }
  return new URL(WRANGLER_CALLBACK);
}

/**
 * wrangler's browser login, finished by whichever comes first: its own
 * listener hearing the browser's callback, or the callback address pasted
 * here, which setup requests itself, on this machine, where the listener is.
 */
async function login(wrangler: Wrangler, step: Step, link: Link): Promise<void> {
  step.note('Cloudflare: approve the sign-in in your browser');
  let callback: URL | null = null;
  const done = new AbortController();
  const stop = new AbortController();
  const running = wrangler(['login', '--browser=false'], {
    signal: stop.signal,
    onOutput: (text) => {
      const address = /Visit this link to authenticate: (\S+)/.exec(text)?.[1];
      if (address === undefined || callback !== null) return;
      callback = callbackOf(address);
      link('If no browser opened, sign in to Cloudflare at', address);
      openBrowser(address);
    },
  }).finally(() => done.abort());
  const pasted = step.paste(
    'If your browser shows an error at a localhost address, paste that address here:',
    async (text) => {
      const listening = callback ?? new URL(WRANGLER_CALLBACK);
      const url = localCallback(text, Number(listening.port), listening.pathname, ['code', 'state']);
      if (typeof url === 'string') return url;
      // To wrangler's listener, as its link names it: the browser's spelling of localhost does not matter.
      url.host = listening.host;
      try {
        // A connection that closes after it, so that wrangler, done, exits at once.
        await new Promise((resolve, reject) => get(url, { agent: false }, (response) => response.resume().on('end', resolve)).on('error', reject));
        return null;
      } catch {
        return "wrangler's sign-in is no longer waiting for that address: run setup again";
      }
    },
    done.signal,
  );
  try {
    await pasted;
  } catch (error) {
    // Cancelled at the prompt: wrangler, still listening, goes too.
    stop.abort();
    await running.catch(() => {});
    throw error;
  }
  const run = await running;
  if (run.code !== 0) throw new Error(`Cloudflare sign-in failed: ${said(run)}`);
}

export type Account = { id: string; name: string };
export type Zone = { id: string; name: string };
export type Origin = { host: string; port: number; database: string; user: string; password: string };
export type HyperdriveConfig = {
  id: string;
  name: string;
  origin: { host: string; port?: number; database: string; user: string };
  caching?: { disabled?: boolean };
};

export class CloudflareError extends Error {}

/** Cloudflare's API, under a token it never logs nor shows. */
export class CloudflareApi {
  readonly #token: string;
  readonly #base: string;

  /** `base`, Cloudflare's, or what CLOUDFLARE_API_BASE_URL names, as wrangler reads it too. */
  constructor(token: string, base = process.env.CLOUDFLARE_API_BASE_URL ?? 'https://api.cloudflare.com/client/v4') {
    this.#token = token;
    this.#base = base.replace(/\/$/, '');
  }

  async #send<T>(method: string, path: string, body?: unknown): Promise<{ result: T; pages: number }> {
    const response = await fetch(`${this.#base}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.#token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const answer = (await response.json().catch(() => ({}))) as {
      success?: boolean;
      result?: T;
      result_info?: { total_pages?: number };
      errors?: { code?: number; message?: string }[];
    };
    if (!response.ok || answer.success === false) {
      const why = (answer.errors ?? []).map((error) => `${error.message ?? 'error'}${error.code === undefined ? '' : ` (${error.code})`}`).join('; ');
      throw new CloudflareError(`Cloudflare answered ${response.status} to ${method} ${path.replace(/\?.*$/, '')}${why === '' ? '' : `: ${why}`}`);
    }
    return { result: answer.result as T, pages: answer.result_info?.total_pages ?? 1 };
  }

  async #call<T>(method: string, path: string, body?: unknown): Promise<T> {
    return (await this.#send<T>(method, path, body)).result;
  }

  /** Every page of a list: Cloudflare gives 50 at most to a page. */
  async #all<T>(path: string): Promise<T[]> {
    const all: T[] = [];
    for (let page = 1; ; page += 1) {
      const { result, pages } = await this.#send<T[]>('GET', `${path}${path.includes('?') ? '&' : '?'}per_page=50&page=${page}`);
      all.push(...result);
      if (page >= pages || result.length === 0) return all;
    }
  }

  accounts(): Promise<Account[]> {
    return this.#all('/accounts');
  }

  zones(account: string): Promise<Zone[]> {
    return this.#all(`/zones?account.id=${account}`);
  }

  /** The signed-in person's email, when the token may read it. */
  async email(): Promise<string | null> {
    try {
      return (await this.#call<{ email?: string }>('GET', '/user')).email ?? null;
    } catch {
      return null;
    }
  }

  hyperdriveConfigs(account: string): Promise<HyperdriveConfig[]> {
    return this.#call('GET', `/accounts/${account}/hyperdrive/configs`);
  }

  /** A Hyperdrive config with caching off: a revoked session must stop at once. The password goes in the body. */
  async createHyperdrive(account: string, name: string, origin: Origin): Promise<string> {
    const made = await this.#call<{ id: string }>('POST', `/accounts/${account}/hyperdrive/configs`, {
      name,
      origin: { scheme: 'postgres', ...origin },
      caching: { disabled: true },
    });
    return made.id;
  }

  async updateHyperdrive(account: string, id: string, name: string, origin: Origin): Promise<void> {
    await this.#call('PUT', `/accounts/${account}/hyperdrive/configs/${id}`, {
      name,
      origin: { scheme: 'postgres', ...origin },
      caching: { disabled: true },
    });
  }

  async disableCaching(account: string, id: string): Promise<void> {
    await this.#call('PATCH', `/accounts/${account}/hyperdrive/configs/${id}`, { caching: { disabled: true } });
  }

  /** The names of a Worker's secrets, never their values; null when the Worker does not exist yet. */
  async secretNames(account: string, script: string): Promise<string[] | null> {
    try {
      const listed = await this.#call<{ name: string }[]>('GET', `/accounts/${account}/workers/scripts/${script}/secrets`);
      return listed.map(({ name }) => name);
    } catch (error) {
      if (error instanceof CloudflareError && /answered 404/.test(error.message)) return null;
      throw error;
    }
  }
}

/** A login's URL as a Hyperdrive origin: Hyperdrive makes its own TLS connection, so the URL's parameters stay behind. */
export function originOf(url: string): Origin {
  const parsed = new URL(url);
  return {
    host: parsed.hostname,
    port: Number(parsed.port || 5432),
    database: decodeURIComponent(parsed.pathname.slice(1)),
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
  };
}

/**
 * Deploy a Worker with wrangler, under the account chosen. `secrets`, when
 * given, go on wrangler's stdin, as its secrets file: never in a file, nor
 * in its arguments. A new Worker needs them at its first deploy.
 */
export async function deployWorker(wrangler: Wrangler, config: string, account: string, secrets: Record<string, string>): Promise<void> {
  const some = Object.keys(secrets).length > 0;
  const run = await wrangler(['deploy', '-c', config, ...(some ? ['--secrets-file', '/dev/stdin'] : [])], {
    input: some ? JSON.stringify(secrets) : undefined,
    env: { CLOUDFLARE_ACCOUNT_ID: account },
  });
  if (run.code !== 0) throw new Error(`wrangler could not deploy ${config}: ${said(run)}`);
}
