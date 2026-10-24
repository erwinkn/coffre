import { randomUUID } from 'node:crypto';
import { EOL } from 'node:os';

import { assertEnvironmentEntry } from '@coffre/core/dotenv';

type Entries = Iterable<readonly [key: string, value: string]>;

/**
 * Names that a later step's shell, loader, runtime or git reads as code to
 * run, or as where to load it from. Set through GITHUB_ENV, one secret
 * would run code in every later step of the job, so these are refused. A
 * trailing `*` covers a whole family, and names compare case-blind, as on
 * Windows. GitHub refuses NODE_OPTIONS itself.
 */
export const RUNS_CODE: readonly string[] = [
  // The shell and the dynamic loader.
  'PATH', 'ENV', 'BASH_ENV', 'SHELLOPTS', 'BASHOPTS', 'PS4', 'IFS', 'ZDOTDIR', 'LD_*', 'DYLD_*', 'GCONV_PATH',
  // Git, ssh and the programs they start.
  'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_EXEC_PATH', 'GIT_PROXY_COMMAND', 'GIT_EXTERNAL_DIFF',
  'GIT_EDITOR', 'GIT_SEQUENCE_EDITOR', 'GIT_PAGER', 'GIT_TEMPLATE_DIR', 'GIT_DIR', 'GIT_CONFIG', 'GIT_CONFIG_*',
  'EDITOR', 'VISUAL', 'PAGER',
  // Language runtimes and package managers.
  'NODE_OPTIONS', 'NODE_PATH', 'NPM_CONFIG_*',
  'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONUSERBASE', 'PYTHONBREAKPOINT',
  'PERL5OPT', 'PERL5LIB', 'PERLLIB', 'PERL5DB', 'RUBYOPT', 'RUBYLIB', 'LUA_INIT*', 'PHPRC', 'PHP_INI_SCAN_DIR',
  'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH',
  'DOTNET_STARTUP_HOOKS', 'DOTNET_ADDITIONAL_DEPS', 'COR_ENABLE_PROFILING', 'COR_PROFILER*', 'CORECLR_ENABLE_PROFILING', 'CORECLR_PROFILER*',
  'GOFLAGS', 'RUSTC_WRAPPER',
];

/** Whether a later step would run code that `key` names (`RUNS_CODE`). */
export function runsCode(key: string): boolean {
  const name = key.toUpperCase();
  return RUNS_CODE.some((pattern) => (pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern));
}

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
    if (runsCode(key)) throw new Error(`${key} cannot be set through GITHUB_ENV: a later step's shell, loader or runtime would take code to run from it`);
    let delimiter: string;
    do { delimiter = nextDelimiter(); } while (value.includes(delimiter));
    out += `${key}<<${delimiter}${newline}${value}${newline}${delimiter}${newline}`;
  }
  return out;
}
