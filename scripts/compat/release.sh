# A published release's deployment, as `coffre init` writes it: the
# installer `pnpm test:compat` (compat-check.sh) and `pnpm upgrade:check`
# (upgrade-check.sh) share. Sourced; the caller sets `store`, pnpm's store.

# A step's output kept in a log, and its end shown when it fails.
quietly() {
    local what="$1" log="$2"
    shift 2
    if ! "$@" >"$log" 2>&1; then
        tail -n 20 "$log" >&2
        echo "$(basename "$0" .sh): $what failed; see $log" >&2
        exit 1
    fi
}

# release <version> <kind> <dir>: coffre <version>'s own CLI in <dir>.cli,
# and the deployment it writes with `init --<kind>` in <dir>, installed;
# each step's log beside them.
release() {
    local version="$1" kind="$2" dir="$3"
    mkdir -p "$dir.cli"
    echo '{ "private": true }' >"$dir.cli/package.json"
    # unpinned: a published release at its exact version, checked by the caller; what it depends on, as npm has it today.
    quietly "installing @coffre/cli@$version" "$dir.cli.log" \
        pnpm --dir "$dir.cli" add --save-exact --store-dir "$store" "@coffre/cli@$version"
    rm -rf "$dir"
    quietly "coffre $version init --$kind" "$dir.init.log" "$dir.cli/node_modules/.bin/coffre" init "--$kind" "$dir"
    # unpinned: init writes no lockfile; this installs what a new deployment's first install does, under its own minimumReleaseAge.
    quietly "installing $(basename "$dir")" "$dir.install.log" pnpm --dir "$dir" install --store-dir "$store"
}
