// `coffre verify keys`: whether the key in escrow is this instance's,
// checked on this machine. The instance gives what it is checked against,
// which is no secret (`GET /audit/keys`, for admins and owners of the whole
// instance): the vault's keys by ID, and a check of each key it signs with
// (`keyCheckOf`), the one it signs with now first. A pasted key is right if
// its check, taken as the signing key or as the vault key it stands for, is
// that first one. The key is never sent, shown or written down: it comes
// from a hidden prompt or stdin, never the command line.
import { parseArgs } from 'node:util';

import type { CoffreClient, RouteOutput } from '@coffre/client';
import { derivedSigningKey, keyCheckOf } from '@coffre/core/kek';

import { hiddenLine, style, type Output } from '../tty.ts';
import { Checks, Failure, Skip, stop } from './checks.ts';

export const KEYS_USAGE = `usage:
  coffre verify keys [--vault-id <id>]

Asks for the vault key you keep, or the signing key you gave the vault,
without showing it, and checks it against the current instance, on this
machine: it is not sent. As an admin or owner of the whole instance.

  --vault-id   the vault ID kept with the key, compared with the one the
               instance wraps under. It is shown either way

In a script, the key comes on stdin's first line; never as an argument.
Exits 1 when it is not the key the instance signs with now.`;

/** What the keys are checked against, as the instance gives it. */
export type KeyMaterial = RouteOutput<'GET /audit/keys'>;

/**
 * A key's text, as an operator pastes it: 32 bytes in base64, and nothing
 * more. Node's decoder, which the deployment uses, stops where it can, so a
 * key pasted twice would decode to the key: the text must be the key's own.
 */
export function decoded(text: string): Buffer | null {
  const key = Buffer.from(text, 'base64');
  const unpadded = text.replace(/=+$/, '');
  return key.length === 32 && (unpadded === key.toString('base64').replace(/=+$/, '') || unpadded === key.toString('base64url')) ? key : null;
}

function malformed(what: string, text: string): Failure {
  return new Failure(`not ${what}: one is 32 bytes in base64, 44 characters, and these ${text.length} characters are not`);
}

/**
 * The key: right if its check is the first, that of the key the vault signs
 * with now, taken as that signing key or as the local vault key it is
 * derived from; one the vault only verifies with if it is a later one,
 * which is said; otherwise none of this instance's. A check proves a
 * signing key, never a vault ID: the ID is the instance's word, shown to be
 * compared with the one kept beside the key.
 */
export function keyVerdict(text: string, about: KeyMaterial, vaultId?: string): string {
  if (text === '') throw new Skip('not given: not checked');
  const key = decoded(text);
  if (key === null) throw malformed('a key', text);
  const derived = derivedSigningKey(key);
  try {
    const asVaultKey = about.checks.indexOf(keyCheckOf(derived));
    const at = asVaultKey >= 0 ? asVaultKey : about.checks.indexOf(keyCheckOf(key));
    const what = asVaultKey >= 0 ? 'vault key' : 'signing key';
    const now = about.kek.provider === 'local' ? `vault ID ${about.kek.id}` : `${about.kek.id}, in ${about.kek.provider}`;
    if (at < 0) throw new Failure(`not this instance's: no key the vault signs or verifies with, taken as a vault key or as a signing key. The vault wraps under ${now}`);
    if (at > 0) {
      throw new Failure(`a ${what} the vault only verifies with, not the one it signs with now: a previous one, or a vault key beside the signingKey it was given, which is the one to check. The vault wraps under ${now}`);
    }
    if (vaultId !== undefined && vaultId !== about.kek.id) throw new Failure(`the ${what} is right, but the vault wraps under ${about.kek.id}, not ${vaultId}: keep the right ID with it`);
    return `the ${what} the vault signs with now; it wraps under ${now}${vaultId === undefined ? '' : ', as given'}`;
  } finally {
    key.fill(0);
    derived.fill(0);
  }
}

type Source = { text: string; from: string; more: boolean };

/** The key: stdin's first line when it is piped, or a hidden prompt on a terminal. */
async function readKey(): Promise<Source> {
  if (!process.stdin.isTTY) {
    let text = '';
    for await (const chunk of process.stdin) text += String(chunk);
    const [first = '', ...rest] = text.split(/\r?\n/);
    return { text: first.trim(), from: 'stdin', more: rest.some((line) => line.trim() !== '') };
  }
  // On the terminal stdin is, as every prompt: stdout may be a pipe, as `coffre verify keys | tee report`.
  const s = style(process.stderr);
  const text = await hiddenLine(process.stdin, process.stderr, s, 'Vault key, or signing key?', 'Paste it: it stays hidden, and on this machine.');
  return { text, from: 'the prompt', more: false };
}

export async function verifyKeys(args: string[], api: CoffreClient, origin: string, out: Output = process.stdout): Promise<void> {
  const { values } = parseArgs({
    args,
    allowPositionals: false,
    options: { 'vault-id': { type: 'string' }, help: { type: 'boolean', short: 'h' } },
  });
  if (values.help) stop(0, KEYS_USAGE);
  const vaultId = values['vault-id']?.trim() || undefined;
  // What it is checked against comes first: someone who may not read it is told before pasting a key.
  const material = await api.audit.keys();
  const s = style(out);
  out.write(`${s.bold(`Checking your key against ${origin}`)}\n`);
  out.write(s.dim("  On this machine: what it's checked against was read from the instance, and the key goes nowhere.\n\n"));
  const key = await readKey();
  const report = new Checks(out);
  await report.check('key', {}, () => said(key, () => keyVerdict(key.text, material, vaultId)));
  // 0.14 asked for the app key on the second line: 0.16's signs nothing a copy of it would be checked against.
  if (key.more) out.write(s.dim("  stdin's other lines are not read: the app key has nothing to be checked against since 0.16, as it signs nothing.\n"));
  const [result] = report.results;
  out.write(
    report.failed.length > 0
      ? `\n${s.red('✗')} ${s.bold(`The key is not the one ${origin} signs with.`)}\n`
      : result?.status !== 'ok'
        ? `\n${s.red('✗')} ${s.bold('No key given: nothing checked.')}\n`
        : `\n${s.green('✓')} ${s.bold(`The key is ${origin}'s.`)}\n`,
  );
  process.exitCode = result?.status === 'ok' ? 0 : 1;
}

/** A key's verdict, and where the key came from when not a prompt: so that a script's run says it read stdin. */
async function said(source: Source, verdict: () => string | Promise<string>): Promise<string> {
  const where = source.from === 'the prompt' ? '' : ` (from ${source.from})`;
  try {
    return `${await verdict()}${where}`;
  } catch (error) {
    if (error instanceof Failure) throw new Failure(`${error.message}${where}`, error.detail);
    throw error;
  }
}
