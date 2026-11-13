/**
 * What a deployment chooses, in one object (docs/design/config.md):
 * the file `deployment.ts` beside `app/` and `vault/`, which `coffre init`
 * writes and both sides import as they build. The app enforces its part
 * and the vault its own; neither takes these from the other at run time,
 * so a compromised app cannot loosen what the vault holds.
 *
 * Not the instance's access policy (`Policy`, `@coffre/core/access`): that
 * one is data, roles and protected environments an Owner edits in the UI,
 * which the vault keeps in its log. This one is code, fixed by the
 * deployment's build, and nobody edits it at run time.
 *
 *   export const deployment = defineDeployment({
 *     services: { tokenMaxDays: 90 },
 *     audit: { keepUsesDays: 400 },
 *   });
 *
 * Every field has a default; `defineDeployment()` is today's behavior.
 */

/** The longest a service token may last anywhere, in days. */
export const MOST_TOKEN_DAYS = 365;

/** The window `signInsPerAddress` counts in, which Cloudflare's rate-limiting bindings take as 10 or 60 seconds: 10. */
export const SIGN_IN_PERIOD_SECONDS = 10;

/**
 * The shortest `proxy.revokedWithinSeconds`: a use's own deadline
 * (`USE_DEADLINE_MS`, 3 s). A request may send up to that long after its
 * use was decided, or every cold request whose use took longer would fail
 * (docs/design/config.md, `proxy.revokedWithinSeconds`).
 */
export const LEAST_REVOKED_WITHIN_SECONDS = 3;

/** The most any of the proxy's or the audit's windows may be: an hour. */
const HOUR_SECONDS = 3_600;

/** The longest bulk window: a day, as long as the releases it counts are kept (`prune_vault_releases`). */
export const MOST_BULK_WINDOW_MINUTES = 24 * 60;

/** Each field, as a deployment writes it: every one may be left out, for its default. */
export type DeploymentOptions = {
  people?: {
    /** How long a browser session lasts, in hours: above 0, at most 168 (a week). 12 unless set. */
    browserSessionHours?: number;
    /** How long a `coffre login` session lasts, in days: above 0, at most 365. 30 unless set. */
    cliSessionDays?: number;
  };
  services?: {
    /** The longest a service token may last, in whole days, 1 to 365; the app and the vault both hold it. 365 unless set. */
    tokenMaxDays?: number;
    /**
     * Sign-ins one address may start in 10 s, each entry point that takes
     * anyone counted apart (`/api/auth/oidc`, `/api/auth/workload`, the MCP
     * OAuth endpoints). 10,000 unless set: 1,000 a second, a fleet
     * behind one NAT being one address. On Workers, Cloudflare reads the
     * number from `app/wrangler.jsonc`'s `SIGN_IN_PER_SOURCE` binding, and
     * the build (`@coffre/ui/vite`) fails unless the two agree; on Node,
     * `processLimits({ perSource: deployment.services.signInsPerAddress })`
     * counts to it.
     */
    signInsPerAddress?: number;
    /** No service token issued or taken: services sign in with a key, into key-bound sessions (docs/design/workload-access.md, 6.3). */
    useOnly?: boolean;
    /** No binding may list `reads`: key-bound sessions get plain values only. With `useOnly`, services read nothing but plain values. */
    noReads?: boolean;
  };
  reads?: {
    /** At most `count` distinct data keys opened per principal in any `windowMinutes`; the window a day at most. 1,000 in 15 unless set. */
    bulkLimit?: { count: number; windowMinutes: number };
  };
  values?: {
    /** Days a value may go unchanged before the UI and `coffre list` flag it for rotation; null for no flag. 365 unless set. */
    rotateAfterDays?: number | null;
  };
  proxy?: {
    /**
     * How long a revoked credential may keep working through the credential
     * proxy, in seconds, 3 to 3,600: values it opened serve requests for at
     * most this long, a request sends at most this long after its use was
     * decided, and an open database tunnel's checks fit inside it. 60 unless set.
     */
    revokedWithinSeconds?: number;
    /** False: every request asks the vault, and no opened value serves another. True unless set. */
    cacheValues?: boolean;
    /** Owners may add and change proxy definitions in the UI, beside those the deployment's code names. False unless set. */
    editable?: boolean;
  };
  audit?: {
    /** Full days of uses kept before today's; null keeps every day. Null unless set (docs/deploy.md, "Retention"). */
    keepUsesDays?: number | null;
    /** The longest a repeat of a use may ride the earlier one's log entry, in seconds, 0 to 3,600; 0 logs every use. 60 unless set. */
    repeatsWithinSeconds?: number;
  };
};

/** The object, checked, every field set. Made only by `defineDeployment`. */
export type Deployment = {
  readonly people: { readonly browserSessionHours: number; readonly cliSessionDays: number };
  readonly services: { readonly tokenMaxDays: number; readonly signInsPerAddress: number; readonly useOnly: boolean; readonly noReads: boolean };
  readonly reads: { readonly bulkLimit: { readonly count: number; readonly windowMinutes: number } };
  readonly values: { readonly rotateAfterDays: number | null };
  readonly proxy: { readonly revokedWithinSeconds: number; readonly cacheValues: boolean; readonly editable: boolean };
  readonly audit: { readonly keepUsesDays: number | null; readonly repeatsWithinSeconds: number };
};

const FIELDS: Record<keyof Deployment, readonly string[]> = {
  people: ['browserSessionHours', 'cliSessionDays'],
  services: ['tokenMaxDays', 'signInsPerAddress', 'useOnly', 'noReads'],
  reads: ['bulkLimit'],
  values: ['rotateAfterDays'],
  proxy: ['revokedWithinSeconds', 'cacheValues', 'editable'],
  audit: ['keepUsesDays', 'repeatsWithinSeconds'],
};

/** Check what a deployment chose, failing on the first problem, a field nobody knows included; each default filled in. */
export function defineDeployment(options: DeploymentOptions = {}): Deployment {
  if (typeof options !== 'object' || options === null) throw new Error('defineDeployment takes an object');
  for (const [group, value] of Object.entries(options)) {
    const fields = FIELDS[group as keyof Deployment];
    if (fields === undefined) throw new Error(`deployment: ${group} is not a group of its fields; they are ${Object.keys(FIELDS).join(', ')}`);
    if (value === undefined) continue;
    if (typeof value !== 'object' || value === null) throw new Error(`deployment.${group} is an object`);
    for (const field of Object.keys(value)) {
      if (!fields.includes(field)) throw new Error(`deployment.${group}.${field} is not a field; ${group}'s are ${fields.join(', ')}`);
    }
  }
  const { people = {}, services = {}, reads = {}, values = {}, proxy = {}, audit = {} } = options;
  return Object.freeze({
    people: Object.freeze({
      browserSessionHours: above0('people.browserSessionHours', people.browserSessionHours, 12, 24 * 7),
      cliSessionDays: above0('people.cliSessionDays', people.cliSessionDays, 30, 365),
    }),
    services: Object.freeze({
      tokenMaxDays: whole('services.tokenMaxDays', services.tokenMaxDays, MOST_TOKEN_DAYS, 1, MOST_TOKEN_DAYS),
      signInsPerAddress: whole('services.signInsPerAddress', services.signInsPerAddress, 10_000, 1, Number.MAX_SAFE_INTEGER),
      useOnly: flag('services.useOnly', services.useOnly, false),
      noReads: flag('services.noReads', services.noReads, false),
    }),
    reads: Object.freeze({ bulkLimit: Object.freeze(bulkLimit(reads.bulkLimit)) }),
    values: Object.freeze({
      rotateAfterDays: values.rotateAfterDays === null ? null : whole('values.rotateAfterDays', values.rotateAfterDays, 365, 1, Number.MAX_SAFE_INTEGER, ', or null for no flag'),
    }),
    proxy: Object.freeze({
      revokedWithinSeconds: within('proxy.revokedWithinSeconds', proxy.revokedWithinSeconds, 60, LEAST_REVOKED_WITHIN_SECONDS, HOUR_SECONDS),
      cacheValues: flag('proxy.cacheValues', proxy.cacheValues, true),
      editable: flag('proxy.editable', proxy.editable, false),
    }),
    audit: Object.freeze({
      keepUsesDays: audit.keepUsesDays === null || audit.keepUsesDays === undefined ? null : whole('audit.keepUsesDays', audit.keepUsesDays, 0, 1, Number.MAX_SAFE_INTEGER, ', or null to keep every day'),
      repeatsWithinSeconds: within('audit.repeatsWithinSeconds', audit.repeatsWithinSeconds, 60, 0, HOUR_SECONDS),
    }),
  });
}

function bulkLimit(given: { count: number; windowMinutes: number } | undefined): { count: number; windowMinutes: number } {
  if (given === undefined) return { count: 1_000, windowMinutes: 15 };
  const { count, windowMinutes } = given;
  // A whole number of milliseconds: what the log's policy holds (`bulk.limit` in the vault's inputs.ts).
  if (!Number.isSafeInteger(count) || count < 1 || !(windowMinutes > 0) || windowMinutes > MOST_BULK_WINDOW_MINUTES || !Number.isInteger(windowMinutes * 60_000)) {
    throw new Error(`deployment.reads.bulkLimit needs a whole count of at least 1 and a window above 0 minutes, a day (${MOST_BULK_WINDOW_MINUTES}) at most, a whole number of milliseconds`);
  }
  return { count, windowMinutes };
}

function above0(name: string, value: number | undefined, fallback: number, most: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > most) throw new Error(`deployment.${name} is a number above 0, at most ${most}`);
  return value;
}

function within(name: string, value: number | undefined, fallback: number, least: number, most: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < least || value > most) throw new Error(`deployment.${name} is a number of seconds, ${least} to ${most.toLocaleString('en-US')}`);
  return value;
}

function whole(name: string, value: number | undefined, fallback: number, least: number, most: number, more = ''): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < least || value > most) {
    throw new Error(`deployment.${name} is a whole number, at least ${least}${most === Number.MAX_SAFE_INTEGER ? '' : `, at most ${most}`}${more}`);
  }
  return value;
}

function flag(name: string, value: boolean | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new Error(`deployment.${name} is true or false`);
  return value;
}

/**
 * A setting 0.15 took where 0.16's object now holds it, as the deployment
 * still writes it: `old`, its old place, and `options`, the same choice as
 * the object's fields. Read in 0.16, with a warning; refused in 0.17.
 */
export type MovedSetting = { old: string; options: DeploymentOptions };

/**
 * The deployment's object: `given`, as it passed it, or else the defaults
 * with the settings it still writes in their old places (`moved`), each
 * warned of once. Both at once fail: one of the two would be ignored.
 */
export function resolveDeployment(given: DeploymentOptions | undefined, moved: readonly MovedSetting[], warn: (message: string) => void = console.warn): Deployment {
  if (given !== undefined) {
    if (moved.length > 0) {
      throw new Error(`${moved.map((one) => one.old).join(', ')}: in deployment.ts now, which this deployment passes too; set ${moved.length === 1 ? 'it' : 'them'} there alone (docs/deploy.md, "deployment.ts")`);
    }
    return defineDeployment(given);
  }
  const merged: Record<string, Record<string, unknown>> = {};
  for (const { options } of moved) {
    for (const [group, fields] of Object.entries(options)) merged[group] = { ...merged[group], ...fields };
  }
  const deployment = defineDeployment(merged as DeploymentOptions);
  const message = `coffre: ${moved.map((one) => one.old).join(', ')} moved to deployment.ts in 0.16, read until 0.17, which refuses ${moved.length === 1 ? 'it' : 'them'} there (docs/deploy.md, "deployment.ts")`;
  // Once per isolate or process: a Worker resolves its configuration once per env, and its checkpointer again.
  if (moved.length > 0 && !WARNED.has(message)) {
    WARNED.add(message);
    warn(message);
  }
  return deployment;
}

const WARNED = new Set<string>();
