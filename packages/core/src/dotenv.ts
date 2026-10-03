/**
 * A small .env parser, for bulk import, and its inverse, for export.
 *
 * Deliberately hand-written rather than pulled from npm: this runs inside the
 * service that holds every credential we own, and the whole grammar is about
 * thirty lines. The server parses and the CLI formats with this one module,
 * so `coffre export` output always imports back unchanged.
 *
 * Supported: `KEY=value`, `export KEY=value`, single and double quoting,
 * escapes inside double quotes, `#` comments, blank lines, and surrounding
 * whitespace. NOT supported: multi-line values and variable interpolation --
 * both are reported as errors rather than being silently mangled.
 */

export type ParsedEntry = { key: string; value: string; line: number };
export type ParseProblem = { line: number; text: string; reason: string };

export type ParseResult = {
  entries: ParsedEntry[];
  problems: ParseProblem[];
};

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

export function parseDotenv(input: string): ParseResult {
  const entries: ParsedEntry[] = [];
  const problems: ParseProblem[] = [];
  const seen = new Set<string>();

  // Split on all three line-ending conventions. Splitting on /\r?\n/ alone
  // leaves a lone \r inside the value, which silently swallows the following
  // key into the preceding secret -- corruption with no error.
  const lines = input.split(/\r\n|\n|\r/);

  for (let index = 0; index < lines.length; index++) {
    const lineNumber = index + 1;
    const raw = lines[index];
    const trimmed = raw.trim();

    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const withoutExport = trimmed.startsWith('export ')
      ? trimmed.slice('export '.length).trim()
      : trimmed;

    const equals = withoutExport.indexOf('=');
    if (equals === -1) {
      problems.push({ line: lineNumber, text: trimmed, reason: 'no "=" on this line' });
      continue;
    }

    const key = withoutExport.slice(0, equals).trim();
    if (!KEY_RE.test(key)) {
      problems.push({
        line: lineNumber,
        text: key,
        reason: 'key must match ^[A-Za-z_][A-Za-z0-9_]*$',
      });
      continue;
    }

    let rest = withoutExport.slice(equals + 1).trim();
    let value: string;

    if (rest.startsWith('"')) {
      const closing = findClosingQuote(rest, '"');
      if (closing === -1) {
        problems.push({
          line: lineNumber,
          text: key,
          reason: 'unterminated double quote (multi-line values are not supported)',
        });
        continue;
      }
      value = unescapeDoubleQuoted(rest.slice(1, closing));
      // Anything other than whitespace or a comment after the closing quote
      // means the line is not what its author thought it was. Rejecting beats
      // silently discarding part of a credential.
      if (trailingIsSignificant(rest.slice(closing + 1))) {
        problems.push({
          line: lineNumber,
          text: key,
          reason: 'unexpected text after the closing quote',
        });
        continue;
      }
    } else if (rest.startsWith("'")) {
      const closing = rest.indexOf("'", 1);
      if (closing === -1) {
        problems.push({
          line: lineNumber,
          text: key,
          reason: 'unterminated single quote (multi-line values are not supported)',
        });
        continue;
      }
      // Single quotes are literal, as in a shell: no escapes inside them.
      value = rest.slice(1, closing);
      if (trailingIsSignificant(rest.slice(closing + 1))) {
        problems.push({
          line: lineNumber,
          text: key,
          reason: 'unexpected text after the closing quote',
        });
        continue;
      }
    } else {
      // Unquoted: strip a trailing comment, then trailing whitespace.
      const comment = rest.indexOf(' #');
      if (comment !== -1) rest = rest.slice(0, comment);
      value = rest.trim();
    }

    // A NUL byte cannot survive being put in a process environment: execve
    // truncates at the first one, so `coffre run` would inject a silently
    // shortened secret. Refuse it here rather than store something that will
    // be wrong only at the point of use.
    if (value.includes('\u0000')) {
      problems.push({
        line: lineNumber,
        text: key,
        reason: 'value contains a NUL byte, which cannot be passed in an environment',
      });
      continue;
    }

    if (seen.has(key)) {
      problems.push({ line: lineNumber, text: key, reason: 'duplicate key in this file' });
      continue;
    }
    seen.add(key);

    entries.push({ key, value, line: lineNumber });
  }

  return { entries, problems };
}

/** True when what follows a closing quote is neither whitespace nor a comment. */
function trailingIsSignificant(rest: string): boolean {
  const trimmed = rest.trim();
  return trimmed !== '' && !trimmed.startsWith('#');
}

function findClosingQuote(text: string, quote: string): number {
  for (let index = 1; index < text.length; index++) {
    if (text[index] === '\\') {
      index++;
      continue;
    }
    if (text[index] === quote) return index;
  }
  return -1;
}

/**
 * Expand escapes inside a double-quoted value.
 *
 * Deliberately minimal: only the escapes that are necessary. `\n` and `\r`
 * because multi-line values (PEM keys) cannot otherwise be expressed on one
 * line, and `\\` `\"` `\'` because quoting needs them.
 *
 * EVERYTHING ELSE IS PRESERVED VERBATIM, backslash included. The obvious
 * implementation -- returning the character and dropping the backslash for
 * unknown escapes -- silently mangles credentials: `"C:\path\to\file"` came
 * out as `C:path<TAB>ofile`, and `"\d+\w"` as `d+w`. A secrets store that
 * quietly rewrites what you gave it is worse than one that refuses.
 *
 * A value that should contain no interpretation at all belongs in single
 * quotes, which are literal.
 */
function unescapeDoubleQuoted(text: string): string {
  return text.replace(/\\(.)/g, (match, character: string) => {
    switch (character) {
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case '\\':
      case '"':
      case "'":
        return character;
      default:
        return match;
    }
  });
}

/** Values that read the same unquoted: no spaces, quotes, `#`, `$` or backslashes. */
const PLAIN_VALUE = /^[A-Za-z0-9_./:@+,=%?-]*$/;

/**
 * Write entries as a .env file that `parseDotenv` reads back exactly.
 *
 * Plain values stay bare; anything else is single-quoted, which is literal;
 * values holding a quote or a line break are double-quoted with the four
 * escapes the parser knows (`\\`, `\"`, `\n`, `\r`).
 */
export function formatDotenv(entries: Iterable<readonly [key: string, value: string]>): string {
  let out = '';
  for (const [key, value] of entries) {
    assertEnvironmentEntry(key, value);
    out += `${key}=${quoteDotenv(value)}\n`;
  }
  return out;
}

/** Reject names and values that cannot be passed intact in an environment. */
export function assertEnvironmentEntry(key: string, value: string): void {
  if (!KEY_RE.test(key)) throw new Error(`${JSON.stringify(key)} is not a valid variable name`);
  if (value.includes('\u0000')) throw new Error(`${key} contains a NUL byte`);
}

function quoteDotenv(value: string): string {
  if (PLAIN_VALUE.test(value)) return value;
  if (!/['\n\r]/.test(value)) return `'${value}'`;
  const escaped = value.replace(/[\\"\n\r]/g, (character) => {
    switch (character) {
      case '\n':
        return '\\n';
      case '\r':
        return '\\r';
      default:
        return `\\${character}`;
    }
  });
  return `"${escaped}"`;
}

/**
 * Write entries as POSIX shell `export` statements, for
 * `eval "$(coffre export … --format shell)"`. Single quotes are the only
 * shell quoting with no expansion inside; a single quote itself is written
 * as `'\''`.
 */
export function formatShellExports(entries: Iterable<readonly [key: string, value: string]>): string {
  let out = '';
  for (const [key, value] of entries) {
    assertEnvironmentEntry(key, value);
    out += `export ${key}='${value.replaceAll("'", "'\\''")}'\n`;
  }
  return out;
}
