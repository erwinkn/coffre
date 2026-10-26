#!/usr/bin/env bash
# Build the CLI's image (packages/cli/Dockerfile) from this revision's CLI,
# packed as scripts/publish.sh packs it, for each platform the release
# publishes, and hold the one this machine runs to what the image promises
# (packages/cli/scripts/image-smoke.ts). Needs Docker on Linux: the smoke
# test's container shares the host's network.
#
#   pnpm test:image
set -euo pipefail

cd "$(dirname "$0")/.."

version=$(node -p "require('./packages/cli/package.json').version")
# Of this run's own, so that runs in other checkouts keep theirs.
image="coffre-cli-test:$version-$$"
work=$(mktemp -d)
trap 'rm -rf "$work"; docker image rm -f "$image-amd64" "$image-arm64" >/dev/null 2>&1 || true' EXIT

# The CLI bundles core, client and db: their builds first, core's and
# client's in a run of their own, as `pnpm build` orders them.
pnpm -r --filter ./packages/core --filter ./packages/client run build
pnpm -r --filter ./packages/db --filter ./packages/cli run build
pnpm --filter @coffre/cli pack --pack-destination "$work" >/dev/null
mv "$work/coffre-cli-$version.tgz" "$work/coffre-cli.tgz"

for arch in amd64 arm64; do
    docker build --quiet --platform "linux/$arch" -f packages/cli/Dockerfile -t "$image-$arch" "$work"
    built=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image-$arch")
    [[ "$built" == "linux/$arch" ]] || { echo "test-image: the linux/$arch build is $built" >&2; exit 1; }
done
native=$(docker version --format '{{.Server.Arch}}')
node --conditions=coffre:source packages/cli/scripts/image-smoke.ts "$image-$native" "$version"
