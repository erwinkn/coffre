import type { Database } from '@coffre/db';

import type { Key } from './rows.ts';
import { Signer, type Finding, type Store } from './signer.ts';

/**
 * What runs the signer (docs/design/0.16.md, "The signer"): its storage,
 * its clock, and where a finding goes. On Workers, a Durable Object of the
 * vault's (`signerObject` in cloudflare-signer.ts), whose alarm is the
 * clock.
 *
 * - **A second after the vault tells of an entry**, a run: what waits is
 *   signed and moved. More than a run takes, and the next comes at once.
 * - **Each minute**, a run that also checks the rows and the log's end.
 * - **After each run**, what it found is sent, and let go once sent.
 *
 * One alarm does all three: it is always set, for the next of them.
 */

/**
 * The part of a Durable Object's storage the host uses, as Cloudflare
 * names it, SQLite-backed: the synchronous key-value calls, which a
 * transaction can hold together, and the one alarm.
 */
export type Storage = {
  kv: {
    get(key: string): unknown;
    list(): Iterable<[string, unknown]>;
    put(key: string, value: unknown): void;
    delete(key: string): boolean;
  };
  /** All of what `run` writes, or none of it if it throws. */
  transactionSync<T>(run: () => T): T;
  /** Resolves once everything written is on disk. */
  sync(): Promise<void>;
  /** One alarm at a time: setting it replaces the one set before. Null once it fires, until it is set again. */
  getAlarm(): Promise<number | null>;
  setAlarm(at: number): Promise<void>;
};

/** A finding of the signer's, or the host's own: no check completed since `of`, an ISO date. */
export type Alerted = Finding | { found: 'stopped'; of: string };

/** What a deployment's `alert` is given: `text` to post as it is, and what it says, one by one. */
export type SignerAlert = { text: string; findings: Alerted[] };

export type Hosting = {
  storage: Storage;
  /** Runs `run` with nothing else of the object running meanwhile: a Durable Object's `blockConcurrencyWhile`. */
  alone<T>(run: () => Promise<T>): Promise<T>;
  keys: readonly Key[];
  /** The signer's database, for as long as the host lasts: on Workers, a client that opens with a query and closes once idle. */
  db: Database;
  now(): number;
  /** Where an alert goes. Without one, the process's log. */
  alert?: ((alert: SignerAlert) => void | Promise<void>) | undefined;
};

/** How long after the vault told of an entry the signer runs: the entries of that second are one run's. */
export const TICK_MS = 1000;
/** How often a run checks the rows and the log's end. */
export const CHECK_MS = 60_000;
/** How old the last completed check may be before the signer is said to be stopped: its runs fail, or wait behind entries that keep coming. */
export const STOPPED_MS = 5 * CHECK_MS;
/** How many findings wait for an alert that cannot be sent. Past it they go to the process's log, and are let go: the signer's storage holds them in one value. */
export const KEEP = 1000;

/** What a check finds again each minute for as long as it holds, and is said once. */
const STANDS = new Set<Alerted['found']>(['row', 'cut']);
const nameOf = (each: Alerted) => (each.found === 'stopped' ? 'stopped' : `${each.found} ${each.of}`);

const SAYS: Record<Alerted['found'], string> = {
  forged: 'an entry that waited to be signed was not the vault\'s. Removed',
  replayed: 'an entry already signed was put back to be signed again. Removed',
  stale: 'an entry of the vault\'s was dated before anything the signer still takes, and it does not remember signing it. Removed',
  missing: 'an entry the vault committed was gone before it was signed',
  rewritten: 'a change replaced this row, or was decided on it, and it was not the row the log says',
  row: 'this row is not what the log says: changed, put back, deleted, or written behind the vault',
  cut: 'this tree of the log does not end with the entry signed last',
  lost: 'an entry signed is not in the log as it was signed',
  stopped: 'the signer has completed no check of the database since then: its runs fail, or entries keep it waiting',
};
/** How many findings an alert's text names: the rest are counted, and all are in `findings`. */
const NAMED = 10;

export function alertOf(findings: Alerted[]): SignerAlert {
  const lines = findings.slice(0, NAMED).map(({ found, of }) => `- ${found} ${of}: ${SAYS[found]}`);
  if (findings.length > NAMED) lines.push(`and ${findings.length - NAMED} more`);
  return { text: `coffre's signer found what the vault did not write (${findings.length}):\n${lines.join('\n')}`, findings };
}

/** The signer's storage in a Durable Object's: a step's changes in one transaction, on disk before the step is done. */
export const storeOf = (storage: Storage): Store => ({
  read: async () => new Map(storage.kv.list()),
  async write(changes) {
    storage.transactionSync(() => {
      for (const [key, value] of changes) {
        if (value === undefined) storage.kv.delete(key);
        else storage.kv.put(key, value);
      }
    });
    await storage.sync();
  },
});

/** What the host keeps beside the signer's own, under a key the signer does not read: what stands, and was said. */
const ALERTED = 'alerted';

export class SignerHost {
  readonly #on: Hosting;
  readonly #store: Store;
  #signer: Signer | null = null;
  /** When a check was last asked for, done or not: one that fails is asked again a minute on. In memory only: a host that starts asks by the last one completed. */
  #asked = 0;
  /** When the alarm is set for: read once from the storage, since an object that starts again may have one, then kept as this host sets it. */
  #alarm: number | null = null;

  constructor(on: Hosting) {
    this.#on = on;
    this.#store = storeOf(on.storage);
  }

  /** The signer, opened from its storage: once, and again after one failed a step. Alone, so that no two are opened. */
  async #open(): Promise<Signer> {
    if (this.#signer === null || this.#signer.dead) {
      await this.#on.alone(async () => {
        if (this.#signer !== null && !this.#signer.dead) return;
        this.#signer = await Signer.open({ db: this.#on.db, keys: this.#on.keys, now: this.#on.now, store: this.#store });
        this.#alarm = await this.#on.storage.getAlarm();
      });
    }
    return this.#signer!;
  }

  /** The alarm no later than `at`: one already set for sooner stays. */
  async #by(at: number): Promise<void> {
    if (this.#alarm !== null && this.#alarm <= at) return;
    this.#alarm = at;
    try {
      await this.#on.storage.setAlarm(at);
    } catch (error) {
      this.#alarm = null;
      throw error;
    }
  }

  /** The vault's word that an entry was committed: expected from now, and signed within a second. */
  async wake(hash: Uint8Array): Promise<void> {
    await (await this.#open()).wake(hash);
    await this.#by(this.#on.now() + TICK_MS);
  }

  /**
   * When the last check completed, and what stands of what the checks
   * found. Whoever asks also sets the alarm, if it was not: a signer nobody
   * told of anything checks all the same.
   */
  async status(): Promise<{ checked: number; standing: Alerted[] }> {
    const signer = await this.#open();
    await this.#by(this.#on.now() + CHECK_MS);
    return { checked: signer.checked, standing: this.#alerted() };
  }

  #alerted(): Alerted[] {
    return (this.#on.storage.kv.get(ALERTED) as Alerted[] | undefined) ?? [];
  }

  /**
   * The alarm: one run, what it found sent, and the alarm set for the next.
   * A run that fails is tried again a second on, for as long as it takes:
   * it does not throw, since the runtime gives up on an alarm that threw a
   * few times. An alert that fails is sent again after the next run.
   */
  async alarm(): Promise<void> {
    // It fired: none is set, until a wake-up or this sets one.
    this.#alarm = null;
    const now = this.#on.now();
    let next = now + TICK_MS;
    try {
      const signer = await this.#open();
      const was = signer.checked;
      try {
        next = (await this.#run(signer, now)) ? now : this.#due(signer);
      } catch (error) {
        console.error('coffre: a run of the signer failed, and the next tries again', error);
      }
      // One that failed a step says what it found once it is opened again, by the next run.
      if (!signer.dead) await this.#tell(signer, now, signer.checked !== was);
    } catch (error) {
      console.error('coffre: the signer could not send what it found, and tries again after its next run', error);
    }
    await this.#by(next);
  }

  /** When the next check is: a minute after the last completed, or the last asked for. */
  #due(signer: Signer): number {
    return Math.max(signer.checked, this.#asked) + CHECK_MS;
  }

  /** One run, with the check when it is due. Its answer: whether to run again at once. */
  #run(signer: Signer, now: number): Promise<boolean> {
    const full = now >= this.#due(signer);
    if (full) this.#asked = now;
    return signer.run(full);
  }

  /**
   * What the signer found is sent, then let go. A row or a tree that is
   * wrong is found again by every check: it is said when first found, and
   * again only once a check has found it right in between. `checked`: this
   * run's check completed, so what it found of them is all that stands.
   */
  async #tell(signer: Signer, now: number, checked: boolean): Promise<void> {
    await signer.take(async (found) => {
      const alerted = this.#alerted();
      const stands = new Map<string, Alerted>();
      if (!checked) for (const each of alerted) if (each.found !== 'stopped') stands.set(nameOf(each), each);
      for (const each of found) if (STANDS.has(each.found)) stands.set(nameOf(each), each);
      if (now - signer.checked > STOPPED_MS) stands.set('stopped', { found: 'stopped', of: new Date(signer.checked).toISOString() });

      const said = new Set(alerted.map(nameOf));
      const news = [...found.filter((each) => !STANDS.has(each.found)), ...[...stands].filter(([name]) => !said.has(name)).map(([, each]) => each)];
      if (news.length > 0) await this.#send(alertOf(news), found.length);

      if (stands.size === said.size && [...stands.keys()].every((name) => said.has(name))) return;
      this.#on.storage.kv.put(ALERTED, [...stands.values()]);
      await this.#on.storage.sync();
    });
  }

  /** To the deployment's `alert`. One that fails throws, and the findings wait for the next run, unless `waiting` of them already do. */
  async #send(alert: SignerAlert, waiting: number): Promise<void> {
    if (this.#on.alert === undefined) {
      console.error(`${alert.text}\n(no alert is configured: the vault's \`alert\`)`);
      return;
    }
    try {
      await this.#on.alert(alert);
    } catch (error) {
      if (waiting <= KEEP) throw error;
      console.error(`coffre: an alert could not be sent, and ${waiting} findings waited for it. They are let go, and here is what it said:\n${alert.text}`, alert.findings, error);
    }
  }
}
