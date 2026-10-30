#!/usr/bin/env bash
# Use coffre as someone outside this repository would: pack every public
# package, let the packed CLI's `coffre init` write both deployments, check
# they are the examples to the byte, install the tarballs into them with no
# workspace in sight, then typecheck and build each one, and hold it to
# `coffre-conformance`, as its own `pnpm conformance`.
#
#   pnpm test:consumer [--kind workers|node] [<dir>]
# <dir> defaults to a new temporary one. Without --kind, exercise both kinds.
#
# The packed client also loads and calls on every Node it declares, 20 and up,
# as COFFRE_CLIENT_NODES lists them (Node binaries, space-separated; the
# current `node` when unset). CI names 20, 22 and 24.
#
# Temporary directories are removed on success and kept on failure. An explicit
# directory is always kept.
#
# The deployments pin coffre's packages at the CLI's version, which is not on
# npm yet, so each project's pnpm-workspace.yaml gets overrides pointing them
# at the tarballs: the only change to what `init` wrote.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
kinds=(workers node)
if [[ "${1:-}" == --kind ]]; then
    case "${2:-}" in
        workers | node) kinds=("$2"); shift 2 ;;
        *) echo 'consumer-test: --kind must be workers or node' >&2; exit 2 ;;
    esac
fi
temporary=false
if [[ -n "${1:-}" ]]; then
    work="$1"
else
    work="$(mktemp -d "${TMPDIR:-/tmp}/coffre-consumer.XXXXXX")"
    temporary=true
fi
case "$work" in
"$root" | "$root"/*)
    echo "consumer-test: $work is inside the workspace; give it a directory outside" >&2
    exit 2
    ;;
esac
mkdir -p "$work"
work="$(cd "$work" && pwd)"

finish() {
    result=$?
    if ((result != 0)); then
        echo "consumer test failed; kept work directory for inspection: $work" >&2
    elif [[ "$temporary" == true ]]; then
        rm -rf -- "$work"
        echo "consumer test passed; removed work directory: $work"
    else
        echo "consumer test passed: $work"
    fi
}
trap finish EXIT

rm -rf "$work/tarballs" "$work/cli" "$work/client" "$work/coffre-workers" "$work/coffre-node"

# The Workers deployment runs on the local Postgres, in a database the
# conformance run makes and drops; the logins it runs as must exist.
"$root/scripts/ensure-postgres.sh"
node --conditions=coffre:source "$root/scripts/ensure-database.mjs" coffre
postgres=postgresql://coffre_owner:local-dev-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}
runtime=postgresql://coffre_runtime:local-runtime-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}
vault_runtime=postgresql://coffre_vault_runtime:local-vault-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}
hot_runtime=postgresql://coffre_vault_hot:local-hot-only@127.0.0.1:${COFFRE_POSTGRES_PORT:-55432}

echo '==> build and pack'
pnpm --dir "$root" build
packages=(core db client ui server vault cli conformance)
for name in "${packages[@]}"; do
    pnpm --dir "$root/packages/$name" pack --pack-destination "$work/tarballs" >/dev/null
done
ls "$work/tarballs"

# The CLI bundles everything it runs, so its tarball unpacked is the CLI.
mkdir -p "$work/cli"
tar -xzf "$work"/tarballs/coffre-cli-*.tgz -C "$work/cli"
# Keep the dependency cache selected before isolating CLI/Workers state in HOME.
# Otherwise setup-node's restored store is ignored and downloads repeat.
consumer_store="$(pnpm --dir "$root" store path)"
export HOME="$work/home"

# `coffre setup` is a chunk of its own, with the Postgres driver and the
# migrations beside it. Without a terminal it refuses to show values; with
# --json it loads, and refuses a database it cannot reach without quoting
# the connection string.
echo "==> coffre setup, packed"
test -f "$work/cli/package/dist/migrations/postgres/meta/_journal.json"
unreachable="postgresql://smoke:smoke-only-password@127.0.0.1:9/coffre"
for args in "" "--json"; do
    if said="$(echo "$unreachable" | node "$work/cli/package/dist/main.js" setup $args 2>&1)"; then
        echo "consumer-test: coffre setup $args accepted a database it cannot reach" >&2
        exit 1
    fi
    expected="$([[ -z "$args" ]] && echo 'needs a terminal' || echo ECONNREFUSED)"
    if [[ "$said" != *"$expected"* || "$said" == *smoke-only-password* ]]; then
        echo "consumer-test: coffre setup $args answered: $said" >&2
        exit 1
    fi
done
# What setup sets on GitHub, sealed by the libsodium the CLI bundles.
node --conditions=coffre:source "$root/packages/cli/test/sealed.ts" "$work/cli/package/dist/deploy-on-push.js"
echo "    sealed a secret GitHub opens"

# The client has no dependency, so its tarball unpacked under node_modules is
# an install. `engines` says it runs from Node 20; each Node named loads it by
# `import` and by `require`, as a CommonJS app does, and calls an instance.
echo '==> @coffre/client, packed'
mkdir -p "$work/client/node_modules/@coffre/client"
tar -xzf "$work"/tarballs/coffre-client-*.tgz --strip-components=1 -C "$work/client/node_modules/@coffre/client"
cp "$root/scripts/client-smoke.cjs" "$work/client/"
for node in ${COFFRE_CLIENT_NODES:-node}; do
    (cd "$work/client" && "$node" client-smoke.cjs)
done

for kind in "${kinds[@]}"; do
    project="$work/coffre-$kind"
    echo "==> coffre init --$kind"
    node "$work/cli/package/dist/main.js" init "--$kind" "$project" >/dev/null

    # What init wrote is what the repository tracks under examples/<kind>.
    diff <(git -C "$root/examples/$kind" ls-files --cached --others --exclude-standard | sort) \
        <(cd "$project" && find . -type f | sed 's#^\./##' | sort)
    git -C "$root/examples/$kind" ls-files --cached --others --exclude-standard | while read -r file; do
        cmp "$root/examples/$kind/$file" "$project/$file"
    done
    echo "    identical to examples/$kind"

    {
        echo 'overrides:'
        for name in "${packages[@]}"; do
            echo "  '@coffre/$name': file:$(ls "$work"/tarballs/coffre-"$name"-*.tgz)"
        done
    } >>"$project/pnpm-workspace.yaml"

    echo "==> install, typecheck and build coffre-$kind"
    pnpm --dir "$project" install --store-dir "$consumer_store" --silent
    if [[ -L "$project/node_modules/@coffre/server" && "$(readlink -f "$project/node_modules/@coffre/server")" == "$root"/* ]]; then
        echo "consumer-test: @coffre/server resolved into the workspace" >&2
        exit 1
    fi
    pnpm --dir "$project" typecheck

    # Its pipeline's migrate: the CLI it pins, as `pnpm exec coffre`, takes
    # the folder for a deployment of its own version, and gets as far as
    # asking for the owner's URL, which no one gives it here.
    if said="$(pnpm --dir "$project" exec coffre migrate --yes </dev/null 2>&1)"; then
        echo "consumer-test: pnpm exec coffre migrate succeeded with no database" >&2
        exit 1
    fi
    if [[ "$said" != *'no connection string: pipe it in'* ]]; then
        echo "consumer-test: pnpm exec coffre migrate answered: $said" >&2
        exit 1
    fi
    if [[ "$kind" == workers ]]; then
        pnpm --dir "$project" build >"$work/$kind-build.log"
        grep -E 'Total Upload' "$work/$kind-build.log" | sed 's/^/    /'
    fi

    echo "==> conformance of coffre-$kind"
    if [[ "$kind" == workers ]]; then
        pnpm --dir "$project" conformance --postgres "$postgres" --runtime "$runtime" --vault-runtime "$vault_runtime" --hot-runtime "$hot_runtime"
    else
        pnpm --dir "$project" conformance
    fi
done
