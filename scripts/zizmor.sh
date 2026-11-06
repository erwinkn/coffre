#!/usr/bin/env bash
# zizmor, the GitHub Actions auditor, over every workflow and action here, the
# examples' included, with .github/zizmor.yml: an action not pinned to its
# commit fails, as does any finding of its other audits. With GH_TOKEN set
# (CI's), the audits that ask GitHub run too: a pinned commit that is no
# commit of its repository, a version comment the commit is not, a known
# vulnerable version.
#
#   pnpm check:workflows
#
# zizmor is downloaded once, its release archive checked against its pinned
# SHA-256, and cached under ~/.cache/coffre.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# zizmor 1.31.1 (2026-10-15). Each platform's archive and its SHA-256, from the
# release's own asset digests.
ZIZMOR_VERSION=1.31.1
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=x86_64-unknown-linux-gnu digest=d185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99 ;;
    Linux-aarch64) target=aarch64-unknown-linux-gnu digest=37eebbd5762a44f262d94875431b14a6d2402991e90a685113ea97b8b41be833 ;;
    Darwin-x86_64) target=x86_64-apple-darwin digest=72ae63bb85b67229c06242f04195cb43927e9fab5f43803c6434dc701a517d61 ;;
    Darwin-arm64) target=aarch64-apple-darwin digest=ad5aa633cd56215b11e6c51d51f90c7e6b22904a75047d1215abbd422f61d698 ;;
    *) echo "no zizmor $ZIZMOR_VERSION release pinned for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

cache="${XDG_CACHE_HOME:-$HOME/.cache}/coffre"
home="$cache/zizmor-$ZIZMOR_VERSION-$target"
if [ ! -x "$home/zizmor" ]; then
    archive="$cache/zizmor-$ZIZMOR_VERSION-$target.tar.gz"
    scripts/fetch.sh "https://github.com/zizmorcore/zizmor/releases/download/v$ZIZMOR_VERSION/zizmor-$target.tar.gz" "$digest" "$archive"
    rm -rf "$home.part"
    mkdir -p "$home.part"
    tar -xzf "$archive" -C "$home.part"
    rm -f "$archive"
    mv "$home.part" "$home"
fi

online=(--offline)
if [ -n "${GH_TOKEN:-}" ]; then online=(); fi
exec "$home/zizmor" "${online[@]}" --config .github/zizmor.yml --no-progress "$@" .
