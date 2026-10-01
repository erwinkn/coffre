#!/usr/bin/env bash
# Use coffre as someone outside this repository would: pack every public
# package, let the packed CLI's `coffre init` write both deployments, check
# they are the examples to the byte, install the tarballs into them with no
# workspace in sight, then typecheck and build each one, and hold it to
# `coffre-conformance`, as its own `pnpm conformance`.
#
#   pnpm test:consumer [<dir>]    <dir> defaults to a new temporary one
#
# Temporary directories are removed on success and kept on failure. An explicit
# directory is always kept.
#
# The deployments pin coffre's packages at the CLI's version, which is not on
# npm yet, so each project's pnpm-workspace.yaml gets overrides pointing them
# at the tarballs: the only change to what `init` wrote.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
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

rm -rf "$work/tarballs" "$work/cli" "$work/coffre-workers" "$work/coffre-node"

# The Workers deployment runs on the local Postgres, in a database the
# conformance run makes and drops; the login it runs as must exist.
"$root/scripts/ensure-postgres.sh"
node "$root/scripts/ensure-database.mjs" coffre
postgres=postgresql://coffre_owner:local-dev-only@127.0.0.1:55432
runtime=postgresql://coffre_runtime:local-runtime-only@127.0.0.1:55432

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
export HOME="$work/home"

for kind in workers node; do
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
    pnpm --dir "$project" install --silent
    if [[ -L "$project/node_modules/@coffre/server" && "$(readlink -f "$project/node_modules/@coffre/server")" == "$root"/* ]]; then
        echo "consumer-test: @coffre/server resolved into the workspace" >&2
        exit 1
    fi
    pnpm --dir "$project" typecheck
    if [[ "$kind" == workers ]]; then
        pnpm --dir "$project" build >"$work/$kind-build.log"
        grep -E 'Total Upload' "$work/$kind-build.log" | sed 's/^/    /'
    fi

    echo "==> conformance of coffre-$kind"
    if [[ "$kind" == workers ]]; then
        pnpm --dir "$project" conformance --postgres "$postgres" --runtime "$runtime"
    else
        pnpm --dir "$project" conformance
    fi
done
