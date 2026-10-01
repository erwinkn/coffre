#!/usr/bin/env bash
# Publish the seven packages to npm at the workspace's version, dependencies
# first, skipping any already there, so that a run which stopped halfway can
# simply run again.
#
#   ./scripts/publish.sh [v<version>]
#
# The release workflow runs it on a pushed tag, which must name the version.
# There npm signs in with GitHub's OIDC token (trusted publishing) and attaches
# provenance; no npm token is stored anywhere. npm sets up a trusted publisher
# only for a package that exists, so each package's first publish is from a
# laptop, after `npm login`.
set -euo pipefail

cd "$(dirname "$0")/.."

version=$(node -p "require('./packages/core/package.json').version")
if [[ -n "${1:-}" && "$1" != "v$version" ]]; then
    echo "the tag is $1, but the packages are at $version" >&2
    exit 1
fi
node scripts/check-pins.mjs

# A pre-release (0.2.0-rc.1) must not become what `npm install` picks.
tag=latest
[[ "$version" == *-* ]] && tag=next

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pnpm build
for name in core client ui server vault conformance cli; do
    package="@coffre/$name"
    if npm view "$package@$version" version >/dev/null 2>&1; then
        echo "$package@$version is already on npm"
        continue
    fi
    # pnpm writes each workspace:* dependency as the version it packs, so the
    # tarball is what npm publishes, as it is.
    mkdir "$work/$name"
    pnpm --dir "packages/$name" pack --pack-destination "$work/$name" >/dev/null
    npm publish "$work/$name"/*.tgz --access public --tag "$tag"
done
