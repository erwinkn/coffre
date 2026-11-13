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
#   --kind     by default workers: a Node deployment runs on Postgres from
#              the release after 0.15.0, and 0.15.0's on SQLite, which this
#              checkout cannot migrate; node joins the default once the
#              newest release is one of those
#   --release  the release to hold; by default the newest on npm
#   --schema   a published version's migrations instead of this checkout's,
#              to check past releases: --release 0.4.0 --schema 0.4.1
#
# Temporary directories are removed on success and kept on failure.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
kinds=(workers)
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
# Releases by their exact versions: npm resolves no range here.
for version in "$release" ${schema:+"$schema"}; do
    if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
        echo "compat-check: $version is not an exact version" >&2
        exit 2
    fi
done
# Whether a version predates 0.16.0, whose migrations renamed tables.
before_renames() {
    local major minor
    IFS=. read -r major minor _ <<<"$1"
    ((major == 0 && minor < 16))
}
# The release knows the old names, and the schema it is held to has the new.
renames=false
if before_renames "$release" && { [[ -z "$schema" ]] || ! before_renames "$schema"; }; then renames=true; fi
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

# shellcheck source=compat/release.sh
. "$root/scripts/compat/release.sh"

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
node --conditions=coffre:source "$root/scripts/ensure-database.mjs" coffre
postgres=postgresql://coffre_owner:local-dev-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}
runtime=postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}
vault_runtime=postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}
hot_runtime=postgresql://coffre_vault_hot:local-hot-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}
store="$(pnpm --dir "$root" store path)"

# What applies the schema: this checkout's migrations, from its sources, or
# a published server's own.
if [[ -n "$schema" ]]; then
    mkdir -p "$work/schema"
    echo '{ "private": true }' >"$work/schema/package.json"
    # unpinned: a published release at its exact version, checked above; what it depends on, as npm has it today.
    quietly "installing @coffre/server@$schema" "$work/schema.log" \
        pnpm --dir "$work/schema" add --save-exact --store-dir "$store" "@coffre/server@$schema"
    migrator="'$work/schema/node_modules/.bin/coffre-server' migrate"
    against="coffre $schema's migrations"
else
    migrator="node --conditions=coffre:source '$root/scripts/compat-migrate.mjs'"
    against="this checkout's migrations"
fi
export HOME="$work/home" npm_config_update_notifier=false
mkdir -p "$HOME"

# The ways the release's conformance migrates, each replaced by one that
# migrates with $against and leaves a mark, so that a release migrating some
# other way fails here rather than passing unchecked:
#
# - its coffre-server bin, which Node's runs as `coffre-server migrate <url>`;
# - its CLI's entry, which its Workers conformance runs with node, as
#   `coffre migrate --yes`: found from the deployment's folder, as that
#   conformance finds it. Every other command of the CLI runs as the
#   release's own, in the same process.
#
# Each replaced file moves aside and a new one takes its place, never written
# through: pnpm links them from its store. All a shim needs is written into
# it. The owner's URL comes as the release gives it: an argument, or piped in.
# After the migrations, the SQL files given as arguments, in order.
migration() {
    cat <<EOF
url="\${DATABASE_URL:-}"
for arg in "\$@"; do case "\$arg" in postgres*) url="\$arg" ;; esac; done
if [ -z "\$url" ] && [ ! -t 0 ]; then url="\$(cat)"; fi
$migrator "\$url"
EOF
    local file
    for file in "$@"; do
        echo "node --conditions=coffre:source '$root/scripts/compat-migrate.mjs' --only \"\$url\" '$file'"
    done
    echo "touch '$work/migrated'"
}

shim_bin() {
    local bin="$1"
    shift
    [[ -e "$bin" || -e "$bin.release" ]] || return 0
    [[ -e "$bin.release" ]] || mv "$bin" "$bin.release"
    rm -f "$bin"
    {
        echo '#!/bin/sh'
        echo "# pnpm test:compat: migrate with $against, not the release's own."
        echo "[ \"\$1\" = migrate ] || exec '$bin.release' \"\$@\""
        migration "$@"
    } >"$bin"
    chmod +x "$bin"
}

shim_cli() {
    local project="$1" manifest entry
    shift
    manifest="$(cd "$project" && node -e "process.stdout.write(require.resolve('@coffre/cli/package.json'))" 2>/dev/null)" || return 0
    entry="$(dirname "$manifest")/$(node -e "process.stdout.write(require(process.argv[1]).bin.coffre)" "$manifest")"
    [[ -e "${entry%.js}.release.js" ]] || mv "$entry" "${entry%.js}.release.js"
    rm -f "$entry"
    { echo '#!/bin/sh'; migration "$@"; } >"$entry.compat.sh"
    cat >"$entry" <<EOF
// pnpm test:compat: \`coffre migrate\` migrates with $against; every other command is the release's own.
if (process.argv[2] === 'migrate') {
  const { spawnSync } = await import('node:child_process');
  process.exit(spawnSync('/bin/sh', ['$entry.compat.sh', ...process.argv.slice(3)], { stdio: 'inherit' }).status ?? 1);
}
await import('./$(basename "${entry%.js}").release.js');
EOF
}

# shim <project> [<sql file>...]
shim() {
    local project="$1"
    shift
    shim_bin "$project/node_modules/.bin/coffre-server" "$@"
    shim_cli "$project" "$@"
}

conformance() {
    local project="$1" log="$3"
    rm -f "$work/migrated"
    local code=0
    # The hot path's login, for a release whose harness takes it, as it requires it; one before refuses the flag.
    local hot=()
    if grep -rqs -- 'hot-runtime' "$project/node_modules/@coffre/conformance/dist"; then hot=(--hot-runtime "$hot_runtime"); fi
    # 0.15.0's conformance holds the hot login to generic plans, which 0.16.0's migrations do not give it
    # (docs/design/planner-defaults.md): its URL asks for them, as that release's database did, so the
    # release is held to everything else. The driver sends a URL's `options` as the session's settings.
    if [[ ${#hot[@]} -gt 0 ]] && grep -rqs -- 'force_generic_plan' "$project/node_modules/@coffre/conformance/dist"; then
        hot=(--hot-runtime "$hot_runtime?options=-c%20plan_cache_mode%3Dforce_generic_plan")
    fi
    pnpm --dir "$project" conformance --postgres "$postgres" --runtime "$runtime" --vault-runtime "$vault_runtime" ${hot[@]+"${hot[@]}"} --port "$port" >"$log" 2>&1 || code=$?
    if [[ ! -e "$work/migrated" ]]; then
        echo "compat-check: coffre $release's conformance did not migrate through the shim; see $log" >&2
        exit 1
    fi
    return "$code"
}

for kind in "${kinds[@]}"; do
    project="$work/coffre-$kind"
    echo "==> coffre $release, as init writes it (--$kind), on $against"
    release "$release" "$kind" "$project"

    # 0.16.0 renamed tables (postgres/0076_table_renames.sql). On
    # Postgres a release before it runs through the views kept under the old
    # names, and its conformance is told the new ones where it names tables
    # (scripts/compat/renamed-tables.mjs). Delete it once 0.16.0 is the
    # newest release.
    if [[ "$renames" == true ]]; then
        node "$root/scripts/compat/renamed-tables.mjs" "$project/node_modules/@coffre/conformance/dist/main.js"
    fi

    shim "$project"
    if conformance "$project" "$kind" "$work/$kind.log"; then
        echo "    conformant"
    else
        grep -E '^  FAIL|conformant' "$work/$kind.log" >&2 || true
        echo "compat-check: coffre $release is not conformant on $against: a migration breaks the code it must keep working; see $work/$kind.log" >&2
        exit 1
    fi

    # The check, shown able to fail: a destructive migration on top, which
    # renames a column the release writes at every sign-in.
    shim "$project" "$root/scripts/compat/destructive.sql"
    if conformance "$project" "$kind" "$work/$kind-destructive.log"; then
        echo "compat-check: coffre $release passed with a destructive migration applied; the check cannot fail, see $work/$kind-destructive.log" >&2
        exit 1
    fi
    failed="$(grep -cE '^  FAIL' "$work/$kind-destructive.log" || true)"
    echo "    and not conformant with a destructive migration on top: $failed failed, the checks after them skipped"
done
