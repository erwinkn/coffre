// `coffre keys`: a deployment's keys, made here and shown once, on a screen
// of their own. Nothing is uploaded, written or left in the scrollback: the
// operator copies each into a password manager, then hands it to the
// component that needs it. For a new deployment whose database is set up by
// hand, and for the vault's half of a rotation; `coffre setup` makes them
// with everything else.
import { randomBytes } from 'node:crypto';
import { parseArgs } from 'node:util';

import { type GuideBlock, type Screen, showSecrets, type Value } from './secrets.ts';
import { openTerminal, paragraph, release, row, style, type Output } from './tty.ts';

/** A deployment's keys, under the names the examples give them: one for each component. */
export type Keys = {
  /** The app's: it signs the app's sessions, tokens and log entries. */
  APP_KEY: string;
  /** Names the vault key in everything it wraps. Not secret. */
  VAULT_KEY_ID: string;
  /** The vault's: it decrypts every value, and the vault derives the key it signs its records with from it. */
  VAULT_KEY: string;
};

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

/**
 * A vault ID: the day, so that ids read in order, and six random base32
 * characters, so that two made the same day differ. The vault refuses two
 * keys under one id.
 */
export function vaultKeyId(now = new Date()): string {
  // 256 is a multiple of 32: each character is uniform.
  const suffix = [...randomBytes(6)].map((byte) => BASE32[byte % 32]).join('');
  return `vault-${now.toISOString().slice(0, 10)}-${suffix}`;
}

/** Two fresh keys, each 32 random bytes in base64, and the vault key's id. */
export function generateKeys(now = new Date()): Keys {
  const key = () => randomBytes(32).toString('base64');
  return { APP_KEY: key(), VAULT_KEY_ID: vaultKeyId(now), VAULT_KEY: key() };
}

/** The keys as values to save, each with what it is for and where it goes. */
export function keyValues(keys: Keys): { app: Value[]; vault: Value[] } {
  return {
    app: [{ label: 'App key', value: keys.APP_KEY, mask: 'all', about: "Signs the app's sessions, tokens and log entries. Goes in the app, as APP_KEY." }],
    vault: [
      { label: 'Vault ID', value: keys.VAULT_KEY_ID, mask: 'none', about: "Names the vault key, and isn't secret. Goes in the vault, as VAULT_KEY_ID." },
      { label: 'Vault key', value: keys.VAULT_KEY, mask: 'all', about: "Decrypts every value: lose it, and they're lost for good. Goes in the vault, as VAULT_KEY." },
    ],
  };
}

/** Where the keys go: the vault ID as a var and the keys as secrets on Workers, the env files on Node. */
export function keyGuide(): { workers: GuideBlock['lines']; node: GuideBlock['lines'] } {
  return {
    workers: [
      'The vault ID goes under vars in vault/wrangler.jsonc, as VAULT_KEY_ID. The keys are secrets; each command asks for its value:',
      { command: 'pnpm exec wrangler secret put APP_KEY -c app/wrangler.jsonc' },
      { command: 'pnpm exec wrangler secret put VAULT_KEY -c vault/wrangler.jsonc' },
    ],
    node: ['server.env takes APP_KEY; vault.env takes VAULT_KEY_ID and VAULT_KEY.'],
  };
}

export function keysScreen(keys: Keys): Screen {
  const { app, vault } = keyValues(keys);
  const guide = keyGuide();
  return {
    title: 'coffre keys',
    sections: [
      { title: 'App', values: app },
      { title: 'Vault', values: vault },
    ],
    guide: [
      { title: 'On Cloudflare Workers', lines: guide.workers },
      { title: 'On Node', lines: guide.node },
      {
        title: 'For a rotation',
        lines: [
          'Take only the vault ID and key. The vault key they replace moves to previousKeks, and stays there: what it wrapped still needs it. The app key cannot change. docs/keys.md has the steps.',
        ],
      },
    ],
  };
}

/** Why a command that shows secrets will not print them to a pipe or a file. */
export function needsTerminal(command: string): string {
  return (
    `${command} shows the values it makes on a screen of their own, so that they never reach a file, a pipe ` +
    'or the scrollback, and that needs a terminal. In a script, --json prints them to stdout instead.'
  );
}

/** The stderr warning before --json prints secrets. */
export function jsonWarning(out: Output, secrets: string): void {
  const s = style(out);
  out.write(`${s.red('!')} ${s.bold(`--json prints ${secrets} to stdout.`)} ${s.dim('Keep it out of logs, and out of files others can read.')}\n`);
}

export async function keys(args: string[]): Promise<void> {
  const { values } = parseArgs({ args, options: { json: { type: 'boolean', default: false } }, allowPositionals: false });
  if (values.json) {
    jsonWarning(process.stderr, 'the app key and the vault key');
    process.stdout.write(`${JSON.stringify(generateKeys())}\n`);
    return;
  }
  const terminal = openTerminal();
  if (terminal === null) {
    process.stderr.write(`coffre keys: ${needsTerminal('coffre keys')}\n`);
    process.exit(1);
  }
  const fresh = generateKeys();
  try {
    await showSecrets(terminal, keysScreen(fresh));
  } finally {
    release(terminal.keys);
  }
  const { out } = terminal;
  const s = style(out);
  out.write(
    [
      '',
      `  ${s.green('✓')} ${s.bold('The app key and the vault key were shown once.')}`,
      s.dim(paragraph(out, "They aren't stored anywhere: a lost key can't be recovered.", 4)),
      '',
      row(out, s, 'Vault ID', `${fresh.VAULT_KEY_ID}, not a secret`),
      '',
      '',
    ].join('\n'),
  );
}
