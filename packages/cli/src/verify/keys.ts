// `coffre verify keys`: whether the keys in escrow are this instance's,
// checked on this machine. The instance gives what they are checked
// against, which is no secret (`GET /audit/keys`, owners and root admins
// only): each vault key's check, a known value the vault wrapped under it,
// and the id the log records for the app key, a fingerprint of it. The vault
// key is right if it opens the check of the key the vault wraps under now;
// the app key, if it makes the same fingerprint. Neither key is sent, shown
// or written down: they come from hidden prompts, or the files flags name,
// stdin for `-`, never the command line.
import { parseArgs } from 'node:util';

import type { CoffreClient, RouteOutput } from '@coffre/client';
import { appLogKeyId, opensKeyCheck } from '@coffre/core/kek';

import { secretFile } from '../flags.ts';
import { hiddenLine, openTerminal, release, style, type Output } from '../tty.ts';
import { Checks, Failure, Skip, stop } from './checks.ts';

export const KEYS_USAGE = `usage:
  coffre verify keys [--vault-key-file <path|->] [--app-key-file <path|->] [--vault-id <id>]

Asks for the vault key, then the app key, without showing them, and checks
each against the current instance, on this machine: neither is sent. Enter
alone skips one. As an owner or a root admin.

  --vault-key-file   the vault key, from this file, or stdin for -, instead
                     of asking for it
  --app-key-file     the app key, the same way; one of the two at most
                     reads stdin
  --vault-id         the vault ID kept with the vault key, to check as well.
                     It is shown either way

In a script, the keys come in files, never as arguments; one not given is
not checked. Exits 1 when a key is not the instance's.`;

/** What the keys are checked against, as the instance gives it. */
export type KeyMaterial = RouteOutput<'GET /audit/keys'>;

/**
 * A key's text, as an operator pastes it: 32 bytes in base64, and nothing
 * more. Node's decoder, which the deployment uses, stops where it can, so a
 * key pasted twice would decode to the key: the text must be the key's own.
 */
function decoded(text: string): Buffer | null {
  const key = Buffer.from(text, 'base64');
  const unpadded = text.replace(/=+$/, '');
  return key.length === 32 && (unpadded === key.toString('base64').replace(/=+$/, '') || unpadded === key.toString('base64url')) ? key : null;
}

function malformed(what: string, text: string): Failure {
  return new Failure(`not ${what}: one is 32 bytes in base64, 44 characters, and these ${text.length} characters are not`);
}

/**
 * The vault key: the one the vault wraps under now if it opens that key's
 * check; a key the vault replaced if it opens an older one's, which is said;
 * otherwise none of this instance's. The vault ID is bound into every
 * check, so the one opened names the key's.
 */
export async function vaultKeyVerdict(text: string, material: KeyMaterial['vault'], vaultId?: string): Promise<string> {
  if (text === '') throw new Skip('not given: not checked');
  const key = decoded(text);
  if (key === null) throw malformed('a vault key', text);
  try {
    const { current, checks } = material;
    let opened: KeyMaterial['vault']['checks'][number] | undefined;
    for (const check of checks) {
      const wrapped = { kekProvider: check.provider, kekId: check.vaultId, kekVersion: check.version, bytes: Buffer.from(check.wrapped, 'base64') };
      if (await opensKeyCheck(key, wrapped)) {
        opened = check;
        break;
      }
    }
    const now = current.provider === 'local' ? `vault ID ${current.vaultId}` : `${current.vaultId}, in ${current.provider}`;
    if (opened === undefined) {
      if (checks.length === 0) throw new Failure(`the vault holds no check to hold a key to yet. It wraps under ${now}`);
      const opens = checks.length === 1 ? "it does not open the vault key's check" : `it opens none of the checks of its ${checks.length} vault keys, current or replaced`;
      throw new Failure(`not this instance's vault key: ${opens}. The vault wraps under ${now}`);
    }
    if (opened.vaultId !== current.vaultId || opened.provider !== current.provider) {
      throw new Failure(`this is a previous vault key (vault ID ${opened.vaultId}), not the current one: the vault wraps under ${now}`);
    }
    if (vaultId !== undefined && vaultId !== opened.vaultId) {
      throw new Failure(`the key is right, but its vault ID is ${opened.vaultId}, not ${vaultId}: keep the right one with it`);
    }
    return `the current one, vault ID ${opened.vaultId}${vaultId === undefined ? '' : ', as given'}`;
  } finally {
    key.fill(0);
  }
}

/** The app key: right if the log's entries the app signs now would carry the fingerprint it makes. */
export function appKeyVerdict(text: string, material: KeyMaterial['app']): string {
  if (text === '') throw new Skip('not given: not checked');
  const key = decoded(text);
  if (key === null) throw malformed('an app key', text);
  try {
    if (appLogKeyId(key) !== material.keyId) throw new Failure("not this instance's app key: the app signs with another");
    return 'the one the app signs with now';
  } finally {
    key.fill(0);
  }
}

type Source = { text: string; from: string };

/**
 * The two keys, from where they are: the files their flags name, then, for
 * those not given, hidden prompts on a terminal. Without one, a key not
 * given is not checked; with neither given, there is nothing to do.
 */
async function readKeys(files: { vault?: string; app?: string }): Promise<{ vault: Source; app: Source }> {
  const given: Partial<Record<'vault' | 'app', Source>> = {};
  for (const which of ['vault', 'app'] as const) {
    const path = files[which];
    if (path === undefined) continue;
    const flag = `--${which}-key-file`;
    try {
      given[which] = { text: secretFile(flag, path), from: path === '-' ? 'stdin' : flag };
    } catch (error) {
      stop(2, `coffre: ${(error as Error).message}`);
    }
  }
  const missing = (['vault', 'app'] as const).filter((which) => given[which] === undefined);
  const terminal = missing.length > 0 ? openTerminal() : null;
  if (terminal === null && missing.length === 2) {
    stop(2, 'coffre: no terminal to ask for the keys on: pass them in --vault-key-file and --app-key-file, a path or - for stdin');
  }
  if (terminal !== null) {
    const s = style(terminal.out);
    try {
      for (const which of missing) {
        const name = which === 'vault' ? 'Vault key' : 'App key';
        const text = await hiddenLine(terminal.keys, terminal.out, s, `${name}?`, 'Paste it: it stays hidden, and on this machine. Enter alone skips it.');
        given[which] = { text, from: 'the prompt' };
      }
    } finally {
      release(terminal.keys);
    }
  }
  const source = (which: 'vault' | 'app'): Source => given[which] ?? { text: '', from: 'the prompt' };
  return { vault: source('vault'), app: source('app') };
}

export async function verifyKeys(args: string[], api: CoffreClient, origin: string, out: Output = process.stdout): Promise<void> {
  const { values } = parseArgs({
    args,
    allowPositionals: false,
    options: {
      'vault-key-file': { type: 'string' },
      'app-key-file': { type: 'string' },
      'vault-id': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help) stop(0, KEYS_USAGE);
  const vaultId = values['vault-id']?.trim() || undefined;
  // What they are checked against comes first: someone who may not read it is told before pasting a key.
  const material = await api.audit.keys();
  const s = style(out);
  out.write(`${s.bold(`Checking your keys against ${origin}`)}\n`);
  out.write(s.dim("  On this machine: what they're checked against was read from the instance, and the keys go nowhere.\n\n"));
  const keys = await readKeys({ vault: values['vault-key-file'], app: values['app-key-file'] });
  const report = new Checks(out);
  await report.check('vault key', {}, () => said(keys.vault, () => vaultKeyVerdict(keys.vault.text, material.vault, vaultId)));
  await report.check('app key', {}, () => said(keys.app, () => appKeyVerdict(keys.app.text, material.app)));
  const { failed, results } = report;
  const right = results.filter(({ status }) => status === 'ok').map(({ name }) => name);
  out.write(
    failed.length > 0
      ? `\n${s.red('✗')} ${s.bold(failed.length === 2 ? `Neither key is ${origin}'s.` : `The ${failed[0]} is not ${origin}'s.`)}\n`
      : right.length === 0
        ? `\n${s.red('✗')} ${s.bold('No key given: nothing checked.')}\n`
        : `\n${s.green('✓')} ${s.bold(right.length === 2 ? `Both keys are ${origin}'s.` : `The ${right[0]} is ${origin}'s.`)}\n`,
  );
  process.exitCode = failed.length > 0 || right.length === 0 ? 1 : 0;
}

/** A key's verdict, and where the key came from when not a prompt: so that a script's run says which it read. */
async function said(source: Source, verdict: () => string | Promise<string>): Promise<string> {
  const where = source.from === 'the prompt' ? '' : ` (from ${source.from})`;
  try {
    return `${await verdict()}${where}`;
  } catch (error) {
    if (error instanceof Failure) throw new Failure(`${error.message}${where}`, error.detail);
    throw error;
  }
}
