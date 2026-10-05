#!/usr/bin/env bash
# Hold the last release to this checkout's schema: its code on a database
# this checkout's migrations brought up to date, as a deployment runs
# between `coffre migrate` and its deploy. Every migration must keep the
# previous release working (AGENTS.md, "Migrations: expand, then
# contract"); this is that, tested.
#
# The release is installed as `coffre init` writes a deployment, from npm,
# and held to its own conformance. That conformance migrates the database it
# makes through the deployment's own bins; here they apply this checkout's
# migrations instead (scripts/compat-migrate.mjs). Then the check is shown
# able to fail: the same run with a synthetic destructive migration after
# them must not be conformant.
#
#   pnpm test:compat [--kind workers|node] [--release <version>] [--schema <version>] [--port <n>] [<dir>]
#
#   --release  the release to hold; by default the newest on npm
#   --schema   a published version's migrations instead of this checkout's,
#              to check past releases: --release 0.1.11 --schema 0.1.12
#
# Temporary directories are removed on success and kept on failure.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
kinds=(workers node)
release=""
schema=""
port=3082
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --kind)
            case "${2:-}" in workers | node) kinds=("$2") ;; *) echo 'compat-check: --kind must be workers or node' >&2; exit 2 ;; esac
            shift 2 ;;
        --release) release="${2:?--release needs a version}"; shift 2 ;;
        --schema) schema="${2:?--schema needs a version}"; shift 2 ;;
        --port) port="${2:?--port needs a number}"; shift 2 ;;
        *) echo "compat-check: unknown option $1" >&2; exit 2 ;;
    esac
done
release="${release:-$(npm view @coffre/cli version)}"
temporary=false
if [[ -n "${1:-}" ]]; then
    work="$1"
else
    work="$(mktemp -d "${TMPDIR:-/tmp}/coffre-compat.XXXXXX")"
    temporary=true
fi
case "$work" in
"$root" | "$root"/*)
    echo "compat-check: $work is inside the workspace; give it a directory outside" >&2
    exit 2
    ;;
esac
mkdir -p "$work"
work="$(cd "$work" && pwd)"

# A step's output kept in the work directory, and its end shown when it fails.
quietly() {
    local what="$1" log="$2"
    shift 2
    if ! "$@" >"$log" 2>&1; then
        tail -n 20 "$log" >&2
        echo "compat-check: $what failed; see $log" >&2
        exit 1
    fi
}

finish() {
    result=$?
    if ((result != 0)); then
        echo "compat check failed; kept work directory for inspection: $work" >&2
    elif [[ "$temporary" == true ]]; then
        rm -rf -- "$work"
    fi
}
trap finish EXIT

"$root/scripts/ensure-postgres.sh"
node "$root/scripts/ensure-database.mjs" coffre
postgres=postgresql://coffre_owner:local-dev-only@127.0.0.1:55432
runtime=postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432
vault_runtime=postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:55432
store="$(pnpm --dir "$root" store path)"

# What applies the schema: this checkout's migrations, from its sources, or
# a published server's own.
if [[ -n "$schema" ]]; then
    mkdir -p "$work/schema"
    echo '{ "private": true }' >"$work/schema/package.json"
    quietly "installing @coffre/server@$schema" "$work/schema.log" \
        pnpm --dir "$work/schema" add --save-exact --store-dir "$store" "@coffre/server@$schema"
    migrator="'$work/schema/node_modules/.bin/coffre-server' migrate"
    against="coffre $schema's migrations"
else
    migrator="node --conditions=coffre:source '$root/scripts/compat-migrate.mjs'"
    against="this checkout's migrations"
fi
export HOME="$work/home" npm_config_update_notifier=false COREPACK_ENABLE_DOWNLOAD_PROMPT=0
mkdir -p "$HOME"

# The release's own CLI, to write its deployments.
mkdir -p "$work/cli"
echo '{ "private": true }' >"$work/cli/package.json"
quietly "installing @coffre/cli@$release" "$work/cli.log" \
    pnpm --dir "$work/cli" add --save-exact --store-dir "$store" "@coffre/cli@$release"

# The ways the release's conformance migrates, each replaced by one that
# migrates with $against and leaves a mark, so that a release migrating some
# other way fails here rather than passing unchecked:
#
# - its coffre-server bin, which it runs as `coffre-server migrate <url>`:
#   every kind up to 0.1.16, and Node's after;
# - its CLI's entry, which its Workers conformance runs with node, as
#   `coffre migrate --yes`, from 0.1.17 on: found from the deployment's
#   folder, as that conformance finds it. Every other command of the CLI
#   runs as the release's own, in the same process.
#
# Each replaced file moves aside and a new one takes its place, never written
# through: pnpm links them from its store. Its children get no COFFRE_* of
# the shell's, so all a shim needs is written into it. The owner's URL comes
# as the release gives it: an argument, piped in, or, in the releases before
# 0.3, COFFRE_MIGRATE_DATABASE_URL.
migration() {
    cat <<EOF
url="\${COFFRE_MIGRATE_DATABASE_URL:-\${DATABASE_URL:-}}"
for arg in "\$@"; do case "\$arg" in postgres*|file:*) url="\$arg" ;; esac; done
if [ -z "\$url" ] && [ ! -t 0 ]; then url="\$(cat)"; fi
$migrator "\$url"
[ -z "$1" ] || node '$root/scripts/compat-migrate.mjs' --only "\$url" '$1'
touch '$work/migrated'
EOF
}

shim_bin() {
    local bin="$1" extra="$2"
    [[ -e "$bin" || -e "$bin.release" ]] || return 0
    [[ -e "$bin.release" ]] || mv "$bin" "$bin.release"
    rm -f "$bin"
    {
        echo '#!/bin/sh'
        echo "# pnpm test:compat: migrate with $against, not the release's own."
        echo "[ \"\$1\" = migrate ] || exec '$bin.release' \"\$@\""
        migration "$extra"
    } >"$bin"
    chmod +x "$bin"
}

shim_cli() {
    local project="$1" extra="$2" manifest entry
    manifest="$(cd "$project" && node -e "process.stdout.write(require.resolve('@coffre/cli/package.json'))" 2>/dev/null)" || return 0
    entry="$(dirname "$manifest")/$(node -e "process.stdout.write(require(process.argv[1]).bin.coffre)" "$manifest")"
    [[ -e "${entry%.js}.release.js" ]] || mv "$entry" "${entry%.js}.release.js"
    rm -f "$entry"
    { echo '#!/bin/sh'; migration "$extra"; } >"$entry.compat.sh"
    cat >"$entry" <<EOF
// pnpm test:compat: \`coffre migrate\` migrates with $against; every other command is the release's own.
if (process.argv[2] === 'migrate') {
  const { spawnSync } = await import('node:child_process');
  process.exit(spawnSync('/bin/sh', ['$entry.compat.sh', ...process.argv.slice(3)], { stdio: 'inherit' }).status ?? 1);
}
await import('./$(basename "${entry%.js}").release.js');
EOF
}

shim() {
    shim_bin "$1/node_modules/.bin/coffre-server" "$2"
    shim_cli "$1" "$2"
}

conformance() {
    local project="$1" kind="$2" log="$3"
    rm -f "$work/migrated"
    local code=0
    if [[ "$kind" == workers ]]; then
        pnpm --dir "$project" conformance --postgres "$postgres" --runtime "$runtime" --vault-runtime "$vault_runtime" --port "$port" >"$log" 2>&1 || code=$?
    else
        pnpm --dir "$project" conformance --port "$port" >"$log" 2>&1 || code=$?
    fi
    if [[ ! -e "$work/migrated" ]]; then
        echo "compat-check: coffre $release's conformance did not migrate through the shim; see $log" >&2
        exit 1
    fi
    return "$code"
}

for kind in "${kinds[@]}"; do
    project="$work/coffre-$kind"
    echo "==> coffre $release, as init writes it (--$kind), on $against"
    rm -rf "$project"
    quietly "coffre $release init --$kind" "$work/$kind-init.log" "$work/cli/node_modules/.bin/coffre" init "--$kind" "$project"
    quietly "installing coffre-$kind" "$work/$kind-install.log" pnpm --dir "$project" install --store-dir "$store"
    engine="$([[ "$kind" == workers ]] && echo postgres || echo sqlite)"

    shim "$project" ''
    if conformance "$project" "$kind" "$work/$kind.log"; then
        echo "    conformant"
    else
        grep -E '^  FAIL|conformant' "$work/$kind.log" >&2 || true
        echo "compat-check: coffre $release is not conformant on $against: a migration breaks the code it must keep working; see $work/$kind.log" >&2
        exit 1
    fi

    # The check, shown able to fail: a destructive migration on top, which
    # renames a column the release writes at every sign-in.
    shim "$project" "$root/scripts/compat/destructive.$engine.sql"
    if conformance "$project" "$kind" "$work/$kind-destructive.log"; then
        echo "compat-check: coffre $release passed with a destructive migration applied; the check cannot fail, see $work/$kind-destructive.log" >&2
        exit 1
    fi
    failed="$(grep -cE '^  FAIL' "$work/$kind-destructive.log" || true)"
    echo "    and not conformant with a destructive migration on top: $failed failed, the checks after them skipped"
done
