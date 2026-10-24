import { randomUUID } from 'node:crypto';
import { EOL } from 'node:os';

import { assertEnvironmentEntry } from '@coffre/core/dotenv';

type Entries = Iterable<readonly [key: string, value: string]>;

/**
 * Names that a later step's shell, loader, runtime, build tool or git reads
 * as code to run, or as where to load it from. Set through GITHUB_ENV, one
 * secret would run code in every later step of the job, so these are
 * refused. A `*` stands for any run of letters, digits and underscores, so
 * that a family is one pattern, and names compare case-blind, as on
 * Windows. GitHub refuses NODE_OPTIONS itself. What only points a tool at
 * another registry (NPM_CONFIG_REGISTRY, PIP_INDEX_URL: the latter can run
 * an sdist's build without --require-hashes, but it is also how a private
 * index is authenticated) is no part of this,
 * nor what only names a directory to read files from (HOME, CARGO_HOME),
 * nor what only an interactive shell reads (ENV, PROMPT_COMMAND), nor a
 * credential (NPM_CONFIG_OTP, CARGO_REGISTRIES_*_TOKEN).
 *
 * A tripwire, not a boundary: it blocks the common one-variable hijacks and
 * is not exhaustive. Anyone who may write keys to an environment the Action
 * exports is trusted with code execution in that job.
 */
export const RUNS_CODE: readonly string[] = [
  // The shell and the dynamic loader.
  'PATH', 'BASH_ENV', 'SHELLOPTS', 'BASHOPTS', 'PS4', 'IFS', 'ZDOTDIR', 'GCONV_PATH',
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'DYLD_*',
  // Git, ssh and the programs they start.
  'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_EXEC_PATH', 'GIT_PROXY_COMMAND', 'GIT_EXTERNAL_DIFF',
  'GIT_EDITOR', 'GIT_SEQUENCE_EDITOR', 'GIT_PAGER', 'GIT_TEMPLATE_DIR', 'GIT_DIR', 'GIT_CONFIG', 'GIT_CONFIG_*',
  'EDITOR', 'VISUAL', 'PAGER', 'BROWSER',
  // Node and its package managers: npm's settings that run a program, as npm and as pnpm 11 read them.
  'NODE_OPTIONS', 'NODE_PATH', 'YARN_YARN_PATH',
  ...['SCRIPT_SHELL', 'SHELL', 'NODE_OPTIONS', 'NODE_GYP', 'GIT', 'EDITOR', 'BROWSER', 'VIEWER', 'ONLOAD_SCRIPT', 'INIT_MODULE', 'USERCONFIG', 'GLOBALCONFIG', 'PNPMFILE', 'GLOBAL_PNPMFILE']
    .flatMap((setting) => [`NPM_CONFIG_${setting}`, `PNPM_CONFIG_${setting}`]),
  // Other language runtimes.
  'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONUSERBASE', 'PYTHONBREAKPOINT', 'PYTHONWARNINGS',
  'PERL5OPT', 'PERL5LIB', 'PERLLIB', 'PERL5DB', 'RUBYOPT', 'RUBYLIB', 'LUA_INIT*', 'PHPRC', 'PHP_INI_SCAN_DIR',
  'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'JAVA_OPTS', 'MAVEN_OPTS', 'MAVEN_ARGS', 'GRADLE_OPTS', 'SBT_OPTS', 'ANT_OPTS', 'CATALINA_OPTS', 'CLASSPATH',
  // MSBuild reads every variable as a property, so these are the ones its common targets run; it cannot be denylisted whole.
  'DOTNET_STARTUP_HOOKS', 'DOTNET_ADDITIONAL_DEPS', 'PREBUILDEVENT', 'POSTBUILDEVENT', 'RUNCOMMAND', 'COR_ENABLE_PROFILING', 'COR_PROFILER*', 'CORECLR_ENABLE_PROFILING', 'CORECLR_PROFILER*',
  // Build tools: the compilers, linkers, wrappers and runners they start, and their flags (make pastes them into a shell line; gcc's -wrapper runs a program).
  'CC', 'CXX', 'CPP', 'AR', 'LD', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'MAKEFLAGS', 'MFLAGS', 'GOFLAGS', 'GOCACHEPROG', 'GOAUTH', 'CGO_*FLAGS',
  'RUSTC', 'RUSTC_*', 'RUSTDOC', 'RUSTDOC_*', 'RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS',
  'CARGO_BUILD_*', 'CARGO_TARGET_*_RUNNER', 'CARGO_TARGET_*_LINKER', 'CARGO_TARGET_*_RUSTFLAGS', 'CARGO_HOST_*',
  'CARGO_REGISTRY_CREDENTIAL_PROVIDER', 'CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS', 'CARGO_REGISTRIES_*_CREDENTIAL_PROVIDER', 'CARGO_CREDENTIAL_ALIAS_*',
];

const RUNS_CODE_PATTERN = new RegExp(`^(?:${RUNS_CODE.map((pattern) => pattern.replaceAll('*', '\\w*')).join('|')})$`);

/** Whether a later step would run code that `key` names (`RUNS_CODE`). */
export function runsCode(key: string): boolean {
  return RUNS_CODE_PATTERN.test(key.toUpperCase());
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
