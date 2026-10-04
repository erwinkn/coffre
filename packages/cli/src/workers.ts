// `coffre setup` on a Workers deployment, the Cloudflare half: it signs in
// to Cloudflare through wrangler, points a Hyperdrive config at each login,
// makes the GitHub App people sign in with, fills in both wrangler.jsonc,
// and, once the keys have been shown, deploys both Workers with them as
// secrets. Nothing is written but the two configs. Cloudflare and the
// database are the record: a second run finds what the first made, keeps
// it, and carries on where it stopped. It never makes a key for a Worker
// that has one, nor for a database already in use.
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
  deploymentWrangler,
  deployWorker,
  type HyperdriveConfig,
  type Link,
  originOf,
  type Wrangler,
  type Zone,
} from './cloudflare.ts';
import { editWorker, placeholder, readWorker, type Change, type WorkerConfig } from './deployment.ts';
import { createGitHubApp, GITHUB, type GitHub } from './github-app.ts';
import { generateKeys, keyValues, type Keys } from './keys.ts';
import type { Screen } from './secrets.ts';
import type { Login } from './setup.ts';
import { type Outcome, type Step, Steps } from './steps.ts';
import { type Keyboard, listed, type Output, paragraph, row, style, textLine } from './tty.ts';

export type Component = 'app' | 'vault';
const COMPONENTS = ['app', 'vault'] as const;

/** How long a new deployment has to answer, its domain's certificate perhaps still on its way. */
const ANSWER_WITHIN_MS = 90_000;

/** An address such as secrets.example.com, from what was typed: no scheme, no path, lower case. */
export function addressOf(answer: string): string {
  return answer.trim().replace(/^https?:\/\//i, '').replace(/[/?#].*$/, '').toLowerCase();
}

/** Why an address will not do: not a host name, or under none of the account's domains. Null when it will. */
export function addressProblem(address: string, zones: readonly string[]): string | null {
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(address)) return 'an address such as secrets.example.com';
  if (!zones.some((zone) => address === zone || address.endsWith(`.${zone}`))) return `not under a domain of this account: ${listed(zones, 'or')}`;
  return null;
}

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
  /** The keys this run makes, for the Workers without theirs, once `checkKeys` has run. */
  keys: Keys | null = null;
  #missing: Record<Component, boolean> = { app: false, vault: false };
  /** The GitHub App's client secret, when this run has it to install. */
  #clientSecret: string | null = null;
  /** What this run changed in each wrangler.jsonc, in a few words each. */
  readonly #wrote: Record<Component, Set<string>> = { app: new Set(), vault: new Set() };

  private constructor(
    dir: string,
    wrangler: Wrangler,
    workers: Record<Component, WorkerConfig>,
    found: Found,
    administrator: URL,
    answers: { address: string; rootAdmins: string },
    secrets: string[],
  ) {
    this.#dir = dir;
    this.#wrangler = wrangler;
    this.workers = workers;
    this.#found = found;
    this.#administrator = administrator;
    this.address = answers.address;
    this.rootAdmins = answers.rootAdmins;
    this.#secrets = secrets;
    const vars = workers.app.vars;
    this.#github = { web: vars.GITHUB_URL ?? GITHUB.web, api: vars.GITHUB_API_URL ?? GITHUB.api };
  }

  /**
   * Sign in to Cloudflare, choose the account, read what is there, and ask
   * what setup cannot know: coffre's address, its root admins, and, when
   * another deployment has its names, a name of its own.
   */
  static async connect(
    dir: string,
    out: Output,
    keys: Keyboard,
    describe: (error: unknown) => string,
    secrets: string[],
    administrator: URL,
  ): Promise<Cloudflare> {
    const s = style(out);
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
        if (zones.length === 0) throw new Error(`the account ${account.name} has no domain, and coffre needs one for its address: add one to Cloudflare first`);
        const names = { app: workers.app.name, vault: workers.vault.name };
        const others = await othersUnder(api, account.id, configs, names, records, administrator);
        found = { api, account, zones, configs, others, secrets: { app: new Set(), vault: new Set() }, email };
        return `Signed in to Cloudflare${email === null ? '' : ` as ${email}`}, account ${account.name}`;
      });
    } finally {
      steps.end();
    }

    const zones = found.zones.map(({ name }) => name);
    const url = workers.app.vars.PUBLIC_URL;
    const address = addressOf(
      await textLine(keys, out, s, "coffre's address", zones.length === 1 ? `under ${zones[0]}` : `under ${listed(zones, 'or')}`, {
        initial: placeholder(url) ? '' : new URL(url!).host,
        check: (answer) => addressProblem(addressOf(answer), zones),
      }),
    );
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
    return new Cloudflare(dir, wrangler, workers, found, administrator, { address, rootAdmins }, secrets);
  }

  /** A Worker's Hyperdrive config, when there is one of this deployment's (`ourConfig`). */
  #config(component: Component): HyperdriveConfig | undefined {
    const worker = this.workers[component];
    return ourConfig(this.#found.configs, worker.name, worker.hyperdrive, this.#administrator);
  }

  /**
   * Whether a login needs a new password: Hyperdrive must have it, and the
   * database keeps only its verifier. So when its config is missing, or
   * points elsewhere, or when asked.
   */
  needsPassword(component: Component, administrator: URL, login: string): boolean {
    const origin = this.#config(component)?.origin;
    return (
      origin === undefined ||
      origin.host !== administrator.hostname ||
      (origin.port ?? 5432) !== Number(administrator.port || 5432) ||
      origin.database !== decodeURIComponent(administrator.pathname.slice(1)) ||
      origin.user !== login
    );
  }

  /**
   * Stop before a login that exists gets a new password, when it is also
   * the login of another deployment's Hyperdrive config, on the same
   * server: a login is the server's, not a database's, and that deployment
   * would be cut off. On PlanetScale, a login names its branch, and never is.
   */
  refuseShared(component: Component, administrator: URL, login: string): void {
    const ours = new Set(COMPONENTS.map((each) => this.#config(each)));
    const other = this.#found.configs.find(
      (config) =>
        !ours.has(config) &&
        config.origin.host === administrator.hostname &&
        (config.origin.port ?? 5432) === Number(administrator.port || 5432) &&
        config.origin.user === login,
    );
    if (other === undefined) return;
    throw new Error(
      `${login} is also the login of the Hyperdrive config ${other.name}, another deployment's, on this database server: ` +
        `a new password for the ${component}'s config would cut that deployment off. Two deployments can't share a server's logins: ` +
        'give this one a server of its own. Nothing was changed.',
    );
  }

  /**
   * The keys this run makes: one for each Worker without its own, for a
   * database that holds no data yet. One that does has its keys already,
   * and a new one would leave what it holds unreadable: setup stops, before
   * changing anything.
   */
  checkKeys(used: boolean): void {
    const missing = { app: !this.#found.secrets.app.has('APP_KEY'), vault: !this.#found.secrets.vault.has('VAULT_KEY') };
    for (const component of COMPONENTS) {
      if (!used || !missing[component]) continue;
      const { name, path } = this.workers[component];
      const key = component === 'app' ? 'APP_KEY' : 'VAULT_KEY';
      throw new Error(
        `The ${component} Worker ${name} has no ${key}, but the database already holds data, which needs the key it was set up with. ` +
          `Put that key back, with pnpm exec wrangler secret put ${key} -c ${path}, then run setup again. Setup never makes a new key for a database in use.`,
      );
    }
    this.#missing = missing;
    if (missing.app || missing.vault) {
      this.keys = generateKeys();
      this.#secrets.push(this.keys.APP_KEY, this.keys.VAULT_KEY);
    }
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

  /** A Hyperdrive config for each login, made, given its new password, or kept; with caching off, always. */
  async hyperdrive(logins: Record<Component, Login>): Promise<Outcome> {
    const { api, account } = this.#found;
    const width = Math.max(...COMPONENTS.map((component) => this.workers[component].name.length)) + 2;
    const details: string[] = [];
    for (const component of COMPONENTS) {
      const { name } = this.workers[component];
      const login = logins[component];
      let config = this.#config(component);
      let what: string;
      if (login.url !== null) {
        const origin = originOf(login.url);
        if (config === undefined) {
          config = { id: await api.createHyperdrive(account.id, name, origin), name, origin };
          what = `made, for ${login.login}`;
        } else {
          await api.updateHyperdrive(account.id, config.id, name, origin);
          what = `given ${login.login}'s new password`;
        }
      } else if (config!.caching?.disabled !== true) {
        await api.disableCaching(account.id, config!.id);
        what = 'kept, its caching turned off';
      } else {
        what = 'kept';
      }
      details.push(`${name.padEnd(width)}${what}`);
      this.#edit(component, [{ path: ['hyperdrive', 0, 'id'], value: config!.id, what: 'Hyperdrive' }]);
      this.workers[component].hyperdrive = config!.id;
    }
    return { text: `Hyperdrive configs ${this.workers.app.name} and ${this.workers.vault.name}, caching off`, details };
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
    return { text: `Made coffre's GitHub App, ${app.slug}`, details: app.url === '' ? [] : [app.url] };
  }

  /** The rest of each wrangler.jsonc: the address and its route, the root admins, and the vault ID of a new vault key. */
  write(): Outcome {
    const url = `https://${this.address}`;
    const app = this.workers.app;
    const route = { pattern: this.address, custom_domain: true };
    this.#edit('app', [
      { path: ['vars', 'PUBLIC_URL'], value: url, what: 'the address' },
      app.route === null
        ? { path: ['routes'], value: [route], after: 'workers_dev', what: 'its custom domain' }
        : { path: ['routes', 0], value: route, what: 'its custom domain' },
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

  /** Deploy the vault, then the app, which binds to it, each with the secrets it lacks; then wait for coffre to answer. */
  async deploy(out: Output, describe: (error: unknown) => string): Promise<string> {
    const url = `https://${this.address}`;
    const steps = new Steps(out, ['Deploy the vault', 'Deploy the app', `Wait for ${url} to answer`], () => null, describe);
    const account = this.#found.account.id;
    let answered = false;
    try {
      await steps.run(0, async () => {
        const secrets: Record<string, string> = this.#missing.vault ? { VAULT_KEY: this.keys!.VAULT_KEY } : {};
        await deployWorker(this.#wrangler, this.workers.vault.path, account, secrets);
        return `Deployed the vault, ${this.workers.vault.name}${this.#missing.vault ? ', with its key' : ''}`;
      });
      await steps.run(1, async () => {
        const secrets = {
          ...(this.#missing.app ? { APP_KEY: this.keys!.APP_KEY } : {}),
          ...(this.#clientSecret === null ? {} : { GITHUB_CLIENT_SECRET: this.#clientSecret }),
        };
        await deployWorker(this.#wrangler, this.workers.app.path, account, secrets);
        const what = [...(this.#missing.app ? ['its key'] : []), ...(this.#clientSecret === null ? [] : ["GitHub's secret"])];
        return `Deployed the app, ${this.workers.app.name}${what.length === 0 ? '' : `, with ${listed(what, 'and')}`}`;
      });
      await steps.run(2, async (step) => {
        answered = await answers(`${url}/livez`, (seconds) => step.note(`Wait for ${url} to answer: its certificate can take a minute (${seconds}s)`));
        return answered
          ? `coffre answers at ${url}`
          : { text: `${url} does not answer yet`, details: ["A new domain's certificate can take a few minutes more. Nothing else is left to do."] };
      });
    } finally {
      steps.end();
    }
    return url;
  }
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
    row(
      out,
      s,
      'Builds',
      'With Workers Builds, the vault Worker builds with pnpm exec coffre migrate --yes, and its secret build variable ' +
        'COFFRE_MIGRATE_DATABASE_URL is the database URL you gave setup; the app builds as it is.',
    ),
    s.dim(paragraph(out, 'After every upgrade of coffre, pnpm exec coffre migrate --yes, then pnpm run deploy, or a push to Workers Builds. docs/deploy.md has each step.', 4)),
    '',
    '',
  ].join('\n');
}
