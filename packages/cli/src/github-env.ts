import { randomUUID } from 'node:crypto';
import { EOL } from 'node:os';

import { assertEnvironmentEntry } from '@coffre/core/dotenv';

type Entries = Iterable<readonly [key: string, value: string]>;

/** The runner decodes %, CR and LF in command data, in this escaping order.
 * https://github.com/actions/toolkit/blob/main/packages/core/src/command.ts
 */
export function githubMasks(entries: Entries): string {
  let out = '';
  for (const [, value] of entries) {
    // Register the whole value and each nonempty line, including a PEM key
    // printed one line at a time. Command-shaped text remains command data.
    for (const mask of new Set([value, ...value.split(/\r\n|\r|\n/)])) {
      if (mask === '') continue;
      out += `::add-mask::${mask.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A')}\n`;
    }
  }
  return out;
}

/** Multiline-safe environment records, consumed by GitHub after the step.
 * https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#multiline-strings
 * Match the host's framing newline, including on Windows, so a trailing CR
 * in the value is not mistaken for part of that newline.
 */
export function githubEnvironment(
  entries: Entries,
  nextDelimiter: () => string = () => `coffre_${randomUUID()}`,
  newline = EOL,
): string {
  let out = '';
  for (const [key, value] of entries) {
    assertEnvironmentEntry(key, value);
    if (key.toUpperCase() === 'NODE_OPTIONS') {
      throw new Error(`${key} cannot be set through GITHUB_ENV`);
    }
    let delimiter: string;
    do { delimiter = nextDelimiter(); } while (value.includes(delimiter));
    out += `${key}<<${delimiter}${newline}${value}${newline}${delimiter}${newline}`;
  }
  return out;
}
