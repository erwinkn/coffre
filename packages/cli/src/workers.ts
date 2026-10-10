// `coffre setup` on a Workers deployment, the Cloudflare half: it signs in
// to Cloudflare through wrangler, points a Hyperdrive config at each login,
// makes the GitHub App people sign in with, fills in both wrangler.jsonc,
// and, once the keys have been shown, deploys both Workers with them as
// secrets. Nothing is written but the two configs. Cloudflare and the
// database are the record: a second run finds what the first made, keeps
// it, and carries on where it stopped. It never makes a key for a Worker
// that has one, nor for a database already in use.
//
// An address whose DNS is elsewhere is served through one of the account's
// domains, with Cloudflare for SaaS (hostname.ts); with no domain on the
// account, setup offers to add one, or the Worker's workers.dev address.
//
// When the deployment is a GitHub repository, setup then has it deploy on
// every push to main (deploy-on-push.ts): a Cloudflare token for the deploys,
// and the repository's secrets, which .github/workflows/deploy.yml reads.
//
// An account may hold other deployments of coffre. A Worker or a Hyperdrive
// config is this deployment's only when this directory says so, and setup
// never touches another's: when one already has this deployment's names,
// it asks for new ones.
import {
  type Account,
  type Binding,
  CloudflareApi,
  cloudflareToken,
  denied,
  deploymentWrangler,
  deployWorker,
  type HyperdriveConfig,
  type Link,
  originOf,
  type Wrangler,
  type Zone,
} from './cloudflare.ts';
import { cappedLimit } from './connections.ts';
import { deployOnPush, gitRemote, repositoryOf, SECRETS, WORKFLOW } from './deploy-on-push.ts';
import { BUILT_APP, buildApp, editWorker, placeholder, readWorker, type Change, type WorkerConfig } from './deployment.ts';
import { createGitHubApp, GITHUB, type GitHub, logoPath } from './github-app.ts';
import { recordLines, recordsToAdd, Refused, saasZone, type Served, serveThrough, standing, tokenNeeded, waitForRecords, zoneOf } from './hostname.ts';
import { generateKeys, keyValues, type Keys } from './keys.ts';
import type { Screen } from './secrets.ts';
import type { Login } from './setup.ts';
import { type Outcome, type Step, Steps } from './steps.ts';
import { hiddenLine, type Keyboard, listed, type Output, paragraph, row, select, style, textLine } from './tty.ts';

export type Component = 'app' | 'vault';
const COMPONENTS = ['app', 'vault'] as const;

/** How long a new deployment has to answer, its domain's certificate perhaps still on its way. */
const ANSWER_WITHIN_MS = 90_000;

/** An address such as secrets.example.com, from what was typed: no scheme, no path, lower case. */
export function addressOf(answer: string): string {
  return answer.trim().replace(/^https?:\/\//i, '').replace(/[/?#].*$/, '').toLowerCase();
}

/** Why an address will not do: not a host name. Null when it will. */
export function addressProblem(address: string): string | null {
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(address) ? null : 'an address such as secrets.example.com';
}

/** A Worker's workers.dev address: `<name>.<subdomain>.workers.dev`. */
export const workersDev = (name: string, subdomain: string) => `${name}.${subdomain}.workers.dev`;

/** The domain to add for an address: its last two labels, `example.com` for secrets.example.com, to change where that is not it. */
export const domainOf = (address: string) => address.split('.').slice(-2).join('.');

/**
 * Setup stopped for what only its user can do, such as setting a domain's
 * nameservers at its registrar: nothing failed, and a run after carries on.
 */
export class Later extends Error {}

/**
 * How the app Worker is reached: at a custom domain, under one of the
 * account's zones; as a custom hostname of one, for an address whose DNS is
 * elsewhere; or at its workers.dev address.
 */
export type Serving = { kind: 'domain' } | ({ kind: 'saas' } & Served) | { kind: 'workers.dev' };

/** What this directory's wrangler.jsonc records of the deployment it is: the Hyperdrive configs it binds, and a vault ID setup made. */
export type Records = { hyperdrive: Record<Component, string | null>; vaultKeyId: string | null };

/** A vault ID as setup makes them, which names one vault; not the template's `vault-1`, which any deployment may keep. */
const MADE_VAULT_ID = /^vault-\d{4}-\d{2}-\d{2}-[a-z2-7]{6}$/;

export function recordsOf(workers: Record<Component, WorkerConfig>): Records {
  const id = workers.vault.vars.VAULT_KEY_ID;
  return {
    hyperdrive: { app: workers.app.hyperdrive, vault: workers.vault.hyperdrive },
    vaultKeyId: id !== undefined && MADE_VAULT_ID.test(id) ? id : null,
  };
}

/** Whether a Worker that exists is this deployment's: it binds a Hyperdrive config this directory records, or, the vault, its vault ID. */
export function isOurs(component: Component, bindings: readonly Binding[], records: Records): boolean {
  const config = records.hyperdrive[component];
  if (config !== null && bindings.some(({ type, id }) => type === 'hyperdrive' && id === config)) return true;
  return (
    component === 'vault' &&
    records.vaultKeyId !== null &&
    bindings.some(({ type, name, text }) => type === 'plain_text' && name === 'VAULT_KEY_ID' && text === records.vaultKeyId)
  );
}

/** Whether a Hyperdrive config points at this run's database: the same host, the same database. */
export function sameDatabase(origin: HyperdriveConfig['origin'], administrator: URL): boolean {
  return origin.host === administrator.hostname && origin.database === decodeURIComponent(administrator.pathname.slice(1));
}

/**
 * A Worker's Hyperdrive config: the one this directory records; else one
 * named after the Worker that points at this run's database, made by a
 * run that stopped before recording it. One under the name that points
 * elsewhere is another deployment's.
 */
export function ourConfig(configs: readonly HyperdriveConfig[], name: string, recorded: string | null, administrator: URL): HyperdriveConfig | undefined {
  return configs.find(({ id }) => id === recorded) ?? configs.find((config) => config.name === name && sameDatabase(config.origin, administrator));
}

/**
 * A name for this deployment, from its address: `coffre-` and its first
 * label, `coffre-secrets` for secrets.example.com, the prefix not doubled:
 * `coffre-try` for coffre-try.example.com.
 */
export function nameFrom(address: string): string {
  const label = address.split('.')[0]!.replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
  return (label === 'coffre' || label.startsWith('coffre-') ? label : `coffre-${label}`.replace(/-$/, '')).slice(0, 57).replace(/-+$/, '');
}

/** Why a deployment's name will not do as a Worker's, with `-vault` after it for the vault's. Null when it will. */
export function nameProblem(name: string): string | null {
  return /^[a-z0-9]([a-z0-9-]{0,55}[a-z0-9])?$/.test(name) ? null : 'lower-case letters, digits and dashes, at most 57';
}

/** Why a list of root admins will not do. Null when it will. */
export function adminsProblem(answer: string): string | null {
  const wrong = answer.split(',').map((email) => email.trim()).filter((email) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));
  return wrong.length === 0 ? null : `not an email: ${wrong.map((email) => email || '(empty)').join(', ')}`;
}

/**
 * The database, as setup read it before Cloudflare: its administrator,
 * whether it holds data, and each runtime login, by what it logs in as,
 * and whether it exists.
 */
export type Database = { administrator: URL; used: boolean; logins: Record<Component, { login: string; exists: boolean }> };

/** What setup found on Cloudflare, before it changes anything. */
type Found = {
  api: CloudflareApi;
  account: Account;
  zones: Zone[];
  configs: HyperdriveConfig[];
  /** What under this deployment's names is another deployment's, in a few words each. */
  others: string[];
  /** Each Worker's secrets, by name: none for a Worker not deployed yet. */
  secrets: Record<Component, Set<string>>;
  email: string | null;
};

/** What under these names, on the account, is another deployment's: its Workers, and its Hyperdrive configs. */
async function othersUnder(
  api: CloudflareApi,
  account: string,
  configs: readonly HyperdriveConfig[],
  names: Record<Component, string>,
  records: Records,
  administrator: URL,
): Promise<string[]> {
  const others: string[] = [];
  for (const component of COMPONENTS) {
    const bindings = await api.bindings(account, names[component]);
    if (bindings !== null && !isOurs(component, bindings, records)) others.push(`the Worker ${names[component]}`);
    const named = configs.find(({ name }) => name === names[component]);
    if (named !== undefined && named !== ourConfig(configs, names[component], records.hyperdrive[component], administrator)) {
      others.push(`the Hyperdrive config ${names[component]}`);
    }
  }
  return others;
}

/** Whether a Hyperdrive config points at this run's database server: the same host, the same port. */
function sameServer(origin: HyperdriveConfig['origin'], administrator: URL): boolean {
  return origin.host === administrator.hostname && (origin.port ?? 5432) === Number(administrator.port || 5432);
}

/**
 * Which logins get a new password: Hyperdrive must have it, and the
 * database keeps only its verifier. So each whose config is missing, or
 * logs in elsewhere, or both, when asked. Setup stops before a login that
 * exists gets one, when it is also the login of another deployment's
 * Hyperdrive config, on the same server: a login is the server's, not a
 * database's, and that deployment would be cut off. On PlanetScale, a
 * login names its branch, and never is.
 */
function newPasswords(configs: readonly HyperdriveConfig[], workers: Record<Component, WorkerConfig>, database: Database, all: boolean): Record<Component, boolean> {
  const { administrator } = database;
  const ourOwn = (component: Component) => ourConfig(configs, workers[component].name, workers[component].hyperdrive, administrator);
  const ours = new Set(COMPONENTS.map(ourOwn));
  const resets = {} as Record<Component, boolean>;
  // Both checked before either changes.
  for (const component of COMPONENTS) {
    const { login, exists } = database.logins[component];
    const origin = ourOwn(component)?.origin;
    resets[component] = all || origin === undefined || !sameServer(origin, administrator) || !sameDatabase(origin, administrator) || origin.user !== login;
    if (!resets[component] || !exists) continue;
    const other = configs.find((config) => !ours.has(config) && sameServer(config.origin, administrator) && config.origin.user === login);
    if (other === undefined) continue;
    throw new Error(
      `${login} is also the login of the Hyperdrive config ${other.name}, another deployment's, on this database server: ` +
        `a new password for the ${component}'s config would cut that deployment off. Two deployments can't share a server's logins: ` +
        'give this one a server of its own. Nothing was changed.',
    );
  }
  return resets;
}

/**
 * Which Workers have no key, for which this run makes one: for a database
 * that holds no data yet. One that does has its keys already, and a new
 * one would leave what it holds unreadable: setup stops, before changing
 * anything.
 */
function missingKeys(workers: Record<Component, WorkerConfig>, secrets: Record<Component, Set<string>>, used: boolean): Record<Component, boolean> {
  const missing = { app: !secrets.app.has('APP_KEY'), vault: !secrets.vault.has('VAULT_KEY') };
  for (const component of COMPONENTS) {
    if (!used || !missing[component]) continue;
    const { name, path } = workers[component];
    const key = component === 'app' ? 'APP_KEY' : 'VAULT_KEY';
    throw new Error(
      `The ${component} Worker ${name} has no ${key}, but the database already holds data, which needs the key it was set up with. ` +
        `Put that key back, with pnpm exec wrangler secret put ${key} -c ${path}, then run setup again. Setup never makes a new key for a database in use.`,
    );
  }
  return missing;
}

export class Cloudflare {
  readonly #dir: string;
  readonly #wrangler: Wrangler;
  readonly #found: Found;
  readonly #administrator: URL;
  readonly #github: GitHub;
  /** Each secret this run handles, to take out of any error shown. */
  readonly #secrets: string[];
  readonly workers: Record<Component, WorkerConfig>;
  readonly address: string;
  readonly rootAdmins: string;
  readonly serving: Serving;
  /** The keys this run makes, for the Workers without theirs. */
  readonly keys: Keys | null;
  readonly #missing: Record<Component, boolean>;
  /** Which logins this run gives a new password (`newPasswords`). */
  readonly newPasswords: Record<Component, boolean>;
  /** The GitHub App's client secret, when this run has it to install. */
  #clientSecret: string | null = null;
  /** The Cloudflare API token setup was given, for what wrangler's login was refused: its wranglers deploy under it. */
  readonly #token: string | null;
  /** What this run changed in each wrangler.jsonc, in a few words each. */
  readonly #wrote: Record<Component, Set<string>> = { app: new Set(), vault: new Set() };
  /** The deployment's GitHub repository, `owner/name`, from its remote: what deploys on every push. */
  readonly repository: string | null;
  /** Whether the repository deploys on every push now; null until the deploy has asked. */
  pushes: boolean | null = null;

  private constructor(
    dir: string,
    wrangler: Wrangler,
    workers: Record<Component, WorkerConfig>,
    found: Found,
    administrator: URL,
    answers: { address: string; rootAdmins: string; serving: Serving; token: string | null },
    checked: { missing: Record<Component, boolean>; newPasswords: Record<Component, boolean> },
    secrets: string[],
  ) {
    this.#dir = dir;
    this.#wrangler = wrangler;
    this.workers = workers;
    this.#found = found;
    this.#administrator = administrator;
    this.address = answers.address;
    this.rootAdmins = answers.rootAdmins;
    this.serving = answers.serving;
    this.#secrets = secrets;
    this.#token = answers.token;
    this.#missing = checked.missing;
    this.newPasswords = checked.newPasswords;
    this.keys = checked.missing.app || checked.missing.vault ? generateKeys() : null;
    if (this.keys !== null) secrets.push(this.keys.APP_KEY, this.keys.VAULT_KEY);
    const vars = workers.app.vars;
    this.#github = { web: vars.GITHUB_URL ?? GITHUB.web, api: vars.GITHUB_API_URL ?? GITHUB.api };
    const remote = gitRemote(dir);
    this.repository = remote === null ? null : repositoryOf(remote, this.#github);
  }

  /**
   * Sign in to Cloudflare, choose the account, read what is there, and ask
   * what setup cannot know: coffre's address, its root admins, and, when
   * another deployment has its names, a name of its own. Every refusal
   * comes before its first change, a domain added or a custom hostname
   * made: a run refused leaves nothing behind.
   */
  static async connect(
    dir: string,
    out: Output,
    keys: Keyboard,
    describe: (error: unknown) => string,
    secrets: string[],
    database: Database,
    options: { resetPasswords: boolean },
  ): Promise<Cloudflare> {
    const s = style(out);
    const { administrator } = database;
    const workers = { app: readWorker(dir, 'app/wrangler.jsonc'), vault: readWorker(dir, 'vault/wrangler.jsonc') };
    const records = recordsOf(workers);
    const wrangler = deploymentWrangler(dir);
    const steps = new Steps(out, ['Sign in to Cloudflare'], () => keys, describe);
    let found!: Found;
    try {
      await steps.run(0, async (step) => {
        const token = await cloudflareToken(wrangler, step, (label, address) => steps.link(label, address));
        secrets.push(token);
        const api = new CloudflareApi(token);
        step.note('Reading your Cloudflare account');
        const accounts = await api.accounts();
        if (accounts.length === 0) throw new Error('this Cloudflare login has no account');
        const account =
          accounts.find(({ id }) => id === workers.app.accountId) ??
          (accounts.length === 1 ? accounts[0]! : accounts[await step.choose('Which Cloudflare account?', accounts.map(({ name }) => name))]!);
        const [zones, configs, email] = await Promise.all([api.zones(account.id), api.hyperdriveConfigs(account.id), api.email()]);
        const names = { app: workers.app.name, vault: workers.vault.name };
        const others = await othersUnder(api, account.id, configs, names, records, administrator);
        found = { api, account, zones, configs, others, secrets: { app: new Set(), vault: new Set() }, email };
        return `Signed in to Cloudflare${email === null ? '' : ` as ${email}`}, account ${account.name}`;
      });
    } finally {
      steps.end();
    }

    const { api, account } = found;
    // A domain serves coffre once Cloudflare serves its DNS: one still waiting for its nameservers does not, yet.
    const active = found.zones.filter(({ status }) => status === undefined || status === 'active');
    const zones = active.map(({ name }) => name);
    const url = workers.app.vars.PUBLIC_URL;
    let subdomain: string | null | undefined;
    const ownSubdomain = async () => (subdomain === undefined ? (subdomain = await api.workersSubdomain(account.id)) : subdomain);
    let address = addressOf(
      await textLine(keys, out, s, "coffre's address", zones.length === 0 ? 'such as secrets.example.com' : `under ${listed(zones, 'or')}, or a domain elsewhere`, {
        initial: placeholder(url) ? '' : new URL(url!).host,
        check: async (answer) => {
          const address = addressOf(answer);
          if (!address.endsWith('.workers.dev')) return addressProblem(address);
          const own = await ownSubdomain();
          return own !== null && address === workersDev(workers.app.name, own) ? null : `the app Worker's workers.dev address is ${own === null ? 'not set up yet' : workersDev(workers.app.name, own)}`;
        },
      }),
    );
    const under = zoneOf(address, found.zones);
    if (!address.endsWith('.workers.dev') && under?.status !== undefined && under.status !== 'active') {
      throw new Later(nameservers(out, under, 'is on Cloudflare, waiting for its nameservers'));
    }
    if (found.others.length > 0) {
      // Another deployment's, under these names: setup leaves it be, and this one takes names of its own.
      const one = found.others.length === 1;
      out.write(`${s.dim(paragraph(out, `On this account, ${listed(found.others, 'and')} ${one ? 'is' : 'are'} another deployment's. Setup leaves ${one ? 'it as it is' : 'them as they are'}.`, 2))}\n`);
      const name = await textLine(keys, out, s, "This deployment's name", 'its Workers are <name> and <name>-vault', {
        initial: nameFrom(address),
        check: async (answer) => {
          const problem = nameProblem(answer);
          if (problem !== null) return problem;
          const others = await othersUnder(found.api, found.account.id, found.configs, { app: answer, vault: `${answer}-vault` }, records, administrator);
          return others.length === 0 ? null : `${listed(others, 'and')}: another deployment's too`;
        },
      });
      workers.app.name = name;
      workers.vault.name = `${name}-vault`;
    }
    for (const component of COMPONENTS) {
      found.secrets[component] = new Set((await found.api.secretNames(found.account.id, workers[component].name)) ?? []);
    }
    // Its names settled, what this deployment has on Cloudflare is known: whatever refuses the run does so here, before anything changes.
    const checked = {
      missing: missingKeys(workers, found.secrets, database.used),
      newPasswords: newPasswords(found.configs, workers, database, options.resetPasswords),
    };
    let kind: Serving['kind'] = 'domain';
    if (address.endsWith('.workers.dev')) {
      kind = 'workers.dev';
    } else if (under === undefined) {
      out.write(`${s.dim(paragraph(out, `${address}'s DNS isn't on this Cloudflare account.`, 2))}\n`);
      if (active.length > 0) {
        out.write(
          `${s.dim(paragraph(out, `Setup serves it through ${active.length === 1 ? active[0]!.name : 'one of your domains'}, with Cloudflare for SaaS: you add a CNAME and TXT records where its DNS is, and setup waits for them.`, 2))}\n`,
        );
        kind = 'saas';
      } else {
        kind = await noDomain(api, account, address, workers.app.name, ownSubdomain, out, keys, secrets);
      }
    }
    // The workers.dev address names the app Worker: its name, once settled.
    if (kind === 'workers.dev') address = workersDev(workers.app.name, (await ownSubdomain())!);
    const admins = workers.vault.vars.ROOT_ADMINS;
    const prefilled = placeholder(admins) && found.email !== null;
    const rootAdmins = (
      await textLine(keys, out, s, 'Root admins', 'their GitHub emails, comma-separated: the first people in', {
        initial: placeholder(admins) ? (found.email ?? '') : admins,
        // Sign-in checks the GitHub account's emails: one that is not among them leaves nobody able to sign in as root.
        note: `${prefilled ? "That's your Cloudflare email. " : ''}Each must be an email on the GitHub account its admin will sign in with, or root is locked out.`,
        check: adminsProblem,
      })
    )
      .split(',')
      .map((email) => email.trim())
      .join(',');
    out.write('\n');
    const { serving, token } = kind === 'saas' ? await serveElsewhere(found, active, address, out, keys, describe, secrets) : { serving: { kind }, token: null };
    return new Cloudflare(dir, wrangler, workers, found, administrator, { address, rootAdmins, serving, token }, checked, secrets);
  }

  /** A Worker's Hyperdrive config, when there is one of this deployment's (`ourConfig`). */
  #config(component: Component): HyperdriveConfig | undefined {
    const worker = this.workers[component];
    return ourConfig(this.#found.configs, worker.name, worker.hyperdrive, this.#administrator);
  }

  /** What each Cloudflare step does while it runs. */
  static readonly TITLES = ['Point Hyperdrive at the database', "Make coffre's GitHub App", 'Fill in app/ and vault/wrangler.jsonc'];

  /**
   * Make `changes`, each named in a few words, to a Worker's wrangler.jsonc,
   * and with them, what this deployment is: its account, its names, and, the
   * app, the vault it binds.
   */
  #edit(component: Component, changes: (Change & { what: string })[]): void {
    const worker = this.workers[component];
    const all = [
      { path: ['name'], value: worker.name, what: 'its name' },
      { path: ['account_id'], value: this.#found.account.id, after: 'name', what: 'the account' },
      ...(component === 'app' ? [{ path: ['services', 0, 'service'], value: this.workers.vault.name, what: "the vault's name" }] : []),
      ...changes,
    ];
    const changed = editWorker(this.#dir, worker.path, all);
    all.forEach(({ what }, i) => changed[i] && this.#wrote[component].add(what));
    worker.accountId = this.#found.account.id;
  }

  /**
   * A Hyperdrive config for each login, made, given its new password, or
   * kept; with caching off, always, and opening at most `limit` connections
   * to the database, or fewer when someone set it lower. Setup listed the
   * configs as it began: one deleted since is made again when its login has
   * a new password, and stops the run when it does not, Hyperdrive needing
   * a password setup can't read.
   */
  async hyperdrive(logins: Record<Component, Login>, limit: number): Promise<{ text: string; details: string[] }> {
    const { api, account } = this.#found;
    const width = Math.max(...COMPONENTS.map((component) => this.workers[component].name.length)) + 2;
    const details: string[] = [];
    /** Each config's connection limit, as this run leaves it. */
    const limits = {} as Record<Component, number>;
    for (const component of COMPONENTS) {
      const { name } = this.workers[component];
      const login = logins[component];
      let config = this.#config(component);
      let what: string;
      if (login.url !== null) {
        const origin = originOf(login.url);
        // A PUT replaces the whole config: the limit it has goes back in, lowered to `limit` when above it.
        const kept = cappedLimit(config?.origin_connection_limit, limit) ?? config?.origin_connection_limit ?? limit;
        if (config !== undefined && (await api.updateHyperdrive(account.id, config.id, name, origin, kept))) {
          what = `given ${login.login}'s new password`;
          limits[component] = kept;
        } else {
          what = config === undefined ? `made, for ${login.login}` : `made again: the config ${config.name} was deleted during this run`;
          config = { id: await api.createHyperdrive(account.id, name, origin, limit), name, origin };
          limits[component] = limit;
        }
      } else {
        const now = config === undefined ? null : await api.hyperdriveConfig(account.id, config.id);
        if (now === null) {
          throw new Error(
            `The Hyperdrive config ${config?.name ?? name} was deleted during this run. ${login.login} kept its password, which setup can't read, ` +
              `so it can't make the config again: run setup again, which gives ${login.login} a new password and makes the config with it.`,
          );
        }
        config = now;
        const lower = cappedLimit(config.origin_connection_limit, limit) !== null;
        const cache = config.caching?.disabled !== true;
        if (cache || lower) {
          await api.patchHyperdrive(account.id, config.id, {
            ...(cache ? { caching: { disabled: true } } : {}),
            ...(lower ? { origin_connection_limit: limit } : {}),
          });
        }
        limits[component] = lower ? limit : config.origin_connection_limit!;
        const changed = [...(cache ? ['its caching turned off'] : []), ...(lower ? [`its connections capped at ${limit}`] : [])];
        what = changed.length === 0 ? 'kept' : `kept, ${changed.join(' and ')}`;
      }
      details.push(`${name.padEnd(width)}${what}`);
      this.#edit(component, [{ path: ['hyperdrive', 0, 'id'], value: config.id, what: 'Hyperdrive' }]);
      this.workers[component].hyperdrive = config.id;
    }
    // A limit someone set lower is kept: each config's own, then.
    const each = limits.app === limits.vault ? `a connection limit of ${limits.app} each` : `connection limits of ${limits.app} and ${limits.vault}`;
    return { text: `Hyperdrive configs ${this.workers.app.name} and ${this.workers.vault.name}, caching off, ${each}`, details };
  }

  /**
   * The GitHub App people sign in with: kept when the app Worker has its
   * secret; made, in the browser, when there is none yet. One made before
   * whose secret never reached Cloudflare takes a new secret, from its page.
   */
  async github(step: Step, say: { aside: (text: string) => void; link: Link }): Promise<Outcome> {
    const id = this.workers.app.vars.GITHUB_CLIENT_ID;
    const url = `https://${this.address}`;
    const moved = !placeholder(this.workers.app.vars.PUBLIC_URL) && this.workers.app.vars.PUBLIC_URL !== url;
    if (!placeholder(id) && this.#found.secrets.app.has('GITHUB_CLIENT_SECRET')) {
      return {
        text: `Kept coffre's GitHub App, client ID ${id}`,
        details: moved ? [`On GitHub, change its callback URL to ${url}/auth/callback/github`] : [],
      };
    }
    if (!placeholder(id)) {
      say.aside(`coffre's GitHub App, client ID ${id}, has no client secret on Cloudflare yet.`);
      say.link('Generate a new one on its page, under', `${this.#github.web}/settings/apps`);
      step.note("GitHub: a new client secret for coffre's app");
      await step.paste(
        'Paste the new client secret, hidden as you paste it:',
        async (text) => {
          if (!/^\S{20,}$/.test(text)) return "that is not a client secret: copy it whole, from the app's page";
          this.#clientSecret = text;
          this.#secrets.push(text);
          return null;
        },
        new AbortController().signal,
      );
      return { text: `Took a new client secret for coffre's GitHub App, client ID ${id}`, details: [] };
    }
    const app = await createGitHubApp(step, say, this.#github, url);
    this.#clientSecret = app.clientSecret;
    this.#secrets.push(app.clientSecret);
    this.#edit('app', [{ path: ['vars', 'GITHUB_CLIENT_ID'], value: app.clientId, what: "GitHub's client ID" }]);
    this.workers.app.vars.GITHUB_CLIENT_ID = app.clientId;
    // Its logo is the one thing neither the manifest nor GitHub's API can set: uploaded on its page, by hand.
    say.link(`For its logo, upload ${logoPath(this.#dir)}, under Display information, at`, app.settings);
    return { text: `Made coffre's GitHub App, ${app.slug}`, details: app.url === '' ? [] : [app.url] };
  }

  /** The rest of each wrangler.jsonc: the address and its route, the root admins, and the vault ID of a new vault key. */
  write(): Outcome {
    const url = `https://${this.address}`;
    const app = this.workers.app;
    const serving = this.serving;
    // A custom hostname is served by a route on the zone it goes through, the zone named by its id: the address is under none of the account's.
    const [route, what] =
      serving.kind === 'saas'
        ? [{ pattern: `${this.address}/*`, zone_id: serving.zone.id }, `its route through ${serving.zone.name}`]
        : [{ pattern: this.address, custom_domain: true }, 'its custom domain'];
    this.#edit('app', [
      { path: ['vars', 'PUBLIC_URL'], value: url, what: 'the address' },
      ...(serving.kind === 'workers.dev'
        ? [
            { path: ['workers_dev'], value: true, what: 'its workers.dev address' },
            { path: ['routes'], value: [], after: 'workers_dev', what: 'its workers.dev address' },
          ]
        : [
            { path: ['workers_dev'], value: false, what },
            app.route === null ? { path: ['routes'], value: [route], after: 'workers_dev', what } : { path: ['routes', 0], value: route, what },
          ]),
    ]);
    this.#edit('vault', [
      { path: ['vars', 'ROOT_ADMINS'], value: this.rootAdmins, what: 'the root admins' },
      ...(this.keys !== null && this.#missing.vault ? [{ path: ['vars', 'VAULT_KEY_ID'], value: this.keys.VAULT_KEY_ID, what: 'the vault ID' }] : []),
    ]);
    const changed = COMPONENTS.filter((component) => this.#wrote[component].size > 0);
    const files = listed(changed.map((component) => this.workers[component].path), 'and');
    return changed.length === 0
      ? 'app/ and vault/wrangler.jsonc, as they were'
      : { text: `Filled in ${files}`, details: changed.map((component) => `${component.padEnd(7)}${listed([...this.#wrote[component]], 'and')}`) };
  }

  /**
   * The keys to save, before they go to Cloudflare: only the ones this run
   * made. A set half installed, or a vault ID setup wrote for a key the
   * vault never got, says an earlier run showed keys that never reached
   * Cloudflare: these replace them.
   */
  screen(): Screen {
    const values = keyValues(this.keys!);
    const app = this.#missing.app ? values.app : [];
    const vault = this.#missing.vault ? values.vault : [];
    const one = app.length + vault.length === 1;
    const where = [
      ...(this.#missing.app ? ['APP_KEY goes in the app Worker'] : []),
      ...(this.#missing.vault ? [`VAULT_KEY ${this.#missing.app ? '' : 'goes '}in the vault Worker`] : []),
    ];
    const before = this.#missing.app !== this.#missing.vault || (this.#missing.vault && /^vault-\d{4}-\d{2}-\d{2}-[a-z2-7]{6}$/.test(this.workers.vault.vars.VAULT_KEY_ID ?? ''));
    return {
      title: 'coffre setup',
      intro:
        `Save ${one ? 'it' : 'each one'} in your password manager now${before ? `, in place of ${one ? 'the one' : 'any'} an earlier run showed, which never reached Cloudflare` : ''}. ` +
        `Next, setup gives ${one ? 'it' : 'them'} to Cloudflare, which never shows ${one ? 'it' : 'them'} again.`,
      sections: [...(app.length > 0 ? [{ title: 'App', values: app }] : []), ...(vault.length > 0 ? [{ title: 'Vault', values: vault }] : [])],
      guide: [
        {
          title: 'On Cloudflare',
          lines: [
            `${listed(where, 'and')}, as ${where.length === 1 ? 'a secret' : 'secrets'}: setup puts ${where.length === 1 ? 'it' : 'them'} there as it deploys, next.`,
            ...(this.#missing.vault ? ['VAULT_KEY_ID is in vault/wrangler.jsonc already.'] : []),
            "Cloudflare never shows a secret again: your password manager holds the only copy. A restored database can't be read without the vault key.",
          ],
        },
      ],
    };
  }

  /**
   * Deploy the vault, then the app, which binds to it, each with the secrets
   * it lacks; have the repository deploy on every push, when there is one;
   * then wait for coffre to answer.
   */
  async deploy(out: Output, describe: (error: unknown) => string, keys: Keyboard, options: { rotateDeployToken: boolean }): Promise<string> {
    const url = `https://${this.address}`;
    const serving = this.serving;
    const repository = this.repository;
    const titles = [
      'Deploy the vault',
      'Deploy the app',
      ...(repository === null ? [] : [`Have ${repository} deploy on every push`]),
      ...(serving.kind === 'saas' ? [`Wait for ${this.address}'s DNS records`] : []),
      `Wait for ${url} to answer`,
    ];
    const steps = new Steps(out, titles, () => keys, describe);
    const account = this.#found.account.id;
    let answered = false;
    try {
      await steps.run(0, async () => {
        const secrets: Record<string, string> = this.#missing.vault ? { VAULT_KEY: this.keys!.VAULT_KEY } : {};
        await deployWorker(this.#wrangler, this.workers.vault.path, account, secrets, this.#token);
        return `Deployed the vault, ${this.workers.vault.name}${this.#missing.vault ? ', with its key' : ''}`;
      });
      await steps.run(1, async (step) => {
        // The app as Vite builds it, which wrangler then uploads as it is.
        step.note('Build the app, with Vite');
        await buildApp(this.#dir);
        step.note('Deploy the app');
        const secrets = {
          ...(this.#missing.app ? { APP_KEY: this.keys!.APP_KEY } : {}),
          ...(this.#clientSecret === null ? {} : { GITHUB_CLIENT_SECRET: this.#clientSecret }),
        };
        await deployWorker(this.#wrangler, BUILT_APP, account, secrets, this.#token);
        const what = [...(this.#missing.app ? ['its key'] : []), ...(this.#clientSecret === null ? [] : ["GitHub's secret"])];
        return `Deployed the app, ${this.workers.app.name}${what.length === 0 ? '' : `, with ${listed(what, 'and')}`}`;
      });
      if (repository !== null) {
        await steps.run(2, async (step) => {
          const zone = serving.kind === 'saas' ? serving.zone : serving.kind === 'domain' ? (zoneOf(this.address, this.#found.zones) ?? null) : null;
          const done = await deployOnPush(
            {
              dir: this.#dir,
              repository,
              github: this.#github,
              api: this.#found.api,
              account: this.#found.account,
              zone,
              owner: this.#administrator,
              rotate: options.rotateDeployToken,
              secrets: this.#secrets,
            },
            step,
            { aside: (text) => steps.aside(text), link: (label, address) => steps.link(label, address) },
          );
          this.pushes = done !== null;
          return done ?? { text: `${repository} does not deploy on push yet`, details: [`Its Actions secrets, ${listed([...SECRETS], 'and')}, aren't set: setup sets them when run again`] };
        });
      }
      if (serving.kind === 'saas') {
        await steps.run(titles.length - 2, async (step) => {
          await waitForRecords(this.#found.api, serving, {
            records: (lines) => {
              steps.print(records(out, this.address, lines));
              steps.aside('Setup asks Cloudflare every 10 seconds. You can stop it with Ctrl-C, and run setup again once the records are in: it picks up here.');
            },
            note: (text) => step.note(text),
            under: (lines) => step.under(lines),
          });
          return `Cloudflare has seen ${this.address}'s records, and its certificate is out`;
        });
      }
      await steps.run(titles.length - 1, async (step) => {
        answered = await answers(`${url}/livez`, (seconds) => step.note(`Wait for ${url} to answer: its certificate can take a minute (${seconds}s)`));
        const why =
          serving.kind === 'saas'
            ? `Check the CNAME: ${this.address} must point to ${serving.target}, where its DNS is.`
            : "A new domain's certificate can take a few minutes more. Nothing else is left to do.";
        return answered ? `coffre answers at ${url}` : { text: `${url} does not answer yet`, details: [why] };
      });
    } finally {
      steps.end();
    }
    return url;
  }
}

/** The records to add where an address's DNS is, under what they are for, to copy as they are. */
function records(out: Output, address: string, lines: string[]): string {
  const s = style(out);
  return [`  ${s.bold(`Add these records where ${address}'s DNS is:`)}`, ...lines.map((line) => `    ${line}`)].join('\n');
}

/** A domain waiting for its nameservers: which to set, at its registrar, and what then. */
function nameservers(out: Output, zone: Zone, state: string): string {
  const s = style(out);
  return [
    '',
    `  ${s.accent('→')} ${s.bold(`${zone.name} ${state}.`)} At your registrar, set its nameservers to:`,
    ...(zone.name_servers ?? []).map((server) => `      ${server}`),
    s.dim(paragraph(out, 'Cloudflare activates the domain once it sees them, often within the hour, at most within a day. Then run coffre setup again.', 4)),
    '',
    '',
  ].join('\n');
}

/**
 * No domain on the account to serve an address through: the two ways on,
 * neither taken unless chosen. Add the address's domain to Cloudflare,
 * which then serves its DNS, setup stopping until its nameservers move; or
 * use the app Worker's workers.dev address for now.
 */
async function noDomain(
  api: CloudflareApi,
  account: Account,
  address: string,
  name: string,
  ownSubdomain: () => Promise<string | null>,
  out: Output,
  keys: Keyboard,
  secrets: string[],
): Promise<'workers.dev'> {
  const s = style(out);
  const domain = domainOf(address);
  const subdomain = await ownSubdomain();
  out.write(
    `${s.dim(
      paragraph(
        out,
        `The account has no domain to serve it through, and a Worker answers only at an address Cloudflare serves. Either add ${domain} to Cloudflare, ` +
          "which then serves its DNS once you set the nameservers it gives at your registrar; or use the Worker's workers.dev address for now, " +
          'and run setup again for your own address later.',
        2,
      ),
    )}\n`,
  );
  const choice = await select(keys, out, s, 'How should coffre be reached?', [
    `Add ${domain} to this Cloudflare account`,
    `At its workers.dev address for now${subdomain === null ? '' : `, ${workersDev(name, subdomain)}`}`,
  ]);
  if (choice === 1) {
    if (subdomain === null) {
      throw new Error("This account has no workers.dev subdomain yet: choose one on Cloudflare's dashboard, under Workers & Pages, then run setup again.");
    }
    return 'workers.dev';
  }
  const chosen = addressOf(await textLine(keys, out, s, 'The domain to add', 'the one you registered', { initial: domain, check: (answer) => addressProblem(addressOf(answer)) }));
  // Refused, as wrangler's login is: a token that may, asked for, and the domain added under it.
  let zone: Zone | null = null;
  let refused = false;
  while (zone === null) {
    try {
      zone = await api.createZone(account.id, chosen);
      break;
    } catch (error) {
      if (!denied(error)) throw error;
    }
    const why = refused
      ? 'Cloudflare refused that token as well.'
      : `Cloudflare refused this login adding ${chosen}: wrangler's login may not. Make a token at https://dash.cloudflare.com/profile/api-tokens ` +
        "with Zone: Zone Edit, for all zones of the account. Or stop here, add it on Cloudflare's dashboard, under Add a domain, and run setup again.";
    out.write(`${s.dim(paragraph(out, why, 2))}\n`);
    refused = true;
    const token = await hiddenLine(keys, out, s, 'Cloudflare API token', 'Hidden as you paste it. Ctrl-C stops here.');
    secrets.push(token);
    api.use(token);
  }
  throw new Later(nameservers(out, zone, 'is on this Cloudflare account now'));
}

/**
 * Serve an address whose DNS is elsewhere through one of the account's
 * domains, and show the records to add there. Refused, as wrangler's login
 * may be, it asks for a token that may, and goes on under it: so does
 * every wrangler it runs after.
 */
async function serveElsewhere(
  found: Found,
  zones: readonly Zone[],
  address: string,
  out: Output,
  keys: Keyboard,
  describe: (error: unknown) => string,
  secrets: string[],
): Promise<{ serving: Serving; token: string | null }> {
  const steps = new Steps(out, [`Serve ${address} through ${zones.length === 1 ? zones[0]!.name : 'one of your domains'}`], () => keys, describe);
  let served!: Served;
  let token: string | null = null;
  try {
    await steps.run(0, async (step) => {
      // Chosen once: a run of the rest under a token asks no second time.
      let zone: Zone | undefined;
      for (;;) {
        try {
          zone ??= await saasZone(found.api, found.account.id, zones, address, (question, options) => step.choose(question, options));
          const { details, ...rest } = await serveThrough(found.api, zone, address);
          served = rest;
          return { text: `${address} is a custom hostname of ${zone.name}`, details };
        } catch (error) {
          if (!(error instanceof Refused)) throw error;
          steps.aside(token === null ? tokenNeeded(error.zones) : 'Cloudflare refused that token as well: it needs the permissions above.');
        }
        await step.paste(
          'Paste a Cloudflare API token, hidden as you paste it:',
          async (text) => {
            if (!/^\S{20,}$/.test(text)) return 'that is not a Cloudflare API token: copy it whole';
            token = text;
            secrets.push(text);
            found.api.use(text);
            return null;
          },
          new AbortController().signal,
        );
      }
    });
    // Once Cloudflare has seen them, a run after has none to show.
    if (!standing(served.hostname).done) {
      steps.print(records(out, address, recordLines(recordsToAdd(served.hostname, served.target))));
      steps.aside('Setup carries on meanwhile, and waits for Cloudflare to see them once coffre is deployed.');
    }
  } finally {
    steps.end();
  }
  out.write('\n');
  return { serving: { kind: 'saas', ...served }, token };
}

/** Whether `url` answers 200 within ANSWER_WITHIN_MS, asking every few seconds. */
async function answers(url: string, waiting: (seconds: number) => void): Promise<boolean> {
  const start = Date.now();
  for (;;) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(5_000), redirect: 'manual' });
      if (response.status === 200) return true;
    } catch {
      // Not yet: no address, no certificate, or no Worker behind it.
    }
    const elapsed = Date.now() - start;
    if (elapsed >= ANSWER_WITHIN_MS) return false;
    waiting(Math.round(elapsed / 1000));
    await new Promise((resolve) => setTimeout(resolve, 3_000));
  }
}

/** How the deployment deploys from now on: on every push, or what to do for it. */
function deploys(cloudflare: Cloudflare): string {
  const secrets = `its Actions secrets ${listed([...SECRETS], 'and')}`;
  if (cloudflare.pushes === true) return `Every push to main migrates the database, then deploys both Workers, with ${WORKFLOW}.`;
  if (cloudflare.repository !== null) {
    return `To deploy on every push, run coffre setup again here: it sets ${cloudflare.repository}'s secrets, which ${WORKFLOW} needs. Or connect Workers Builds (docs/deploy.md).`;
  }
  return (
    `This directory has no GitHub remote. To deploy on every push, push it to a GitHub repository, with ${WORKFLOW}, and run coffre setup again: ` +
    `it sets ${secrets}. Or set them yourself, or connect Workers Builds (docs/deploy.md).`
  );
}

/** After the deploy: where coffre is, and what is left, with no secret in it. */
export function deployedSummary(cloudflare: Cloudflare, out: Output): string {
  const s = style(out);
  const url = `https://${cloudflare.address}`;
  const first = cloudflare.rootAdmins.split(',')[0]!;
  return [
    '',
    `  ${s.green('✓')} ${s.bold(`coffre is at ${url}`)}`,
    ...(cloudflare.keys === null ? [] : [s.dim(paragraph(out, "The keys shown are only in your password manager now, and in Cloudflare, which won't show them again.", 4))]),
    '',
    `    ${s.bold('Next')}`,
    row(out, s, 'Sign in', `${url}, with GitHub, as ${first}.`),
    row(out, s, 'CLI', `coffre login ${url}`),
    row(out, s, 'Monitor', `${url}/readyz turns green at the first scheduled run, within 5 minutes.`),
    row(out, s, 'Deploys', deploys(cloudflare)),
    s.dim(
      paragraph(
        out,
        'After every upgrade of coffre, commit and push: the workflow migrates the database, then deploys. By hand, pnpm exec coffre migrate --yes first, then pnpm run deploy. docs/deploy.md has each step.',
        4,
      ),
    ),
    '',
    '',
  ].join('\n');
}
