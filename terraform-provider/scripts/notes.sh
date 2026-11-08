#!/usr/bin/env bash
# scripts/notes.sh <version>: CHANGELOG.md's notes for <version>, the lines
# under its `## <version>` heading (a date may follow) up to the next `## `,
# on stdout. Fails on a version that is not SemVer without build metadata
# (GoReleaser refuses one with a leading zero in a numeric prerelease part),
# or on a section with no notes. Coffre's `Terraform provider` workflow runs
# it before it pushes the tag, which cannot move; the mirror's `Release`
# workflow runs it again for the release's notes.
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:?usage: scripts/notes.sh <version>}"
id='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
if ! [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$id(\.$id)*)?$ ]]; then
    echo "$version is not a SemVer version" >&2
    exit 1
fi
notes="$(awk -v heading="## $version" '
    /^## / { inside = ($0 == heading || index($0, heading " ") == 1); next }
    inside' CHANGELOG.md)"
if ! grep -q '[^[:space:]]' <<< "$notes"; then
    echo "CHANGELOG.md has no notes under ## $version" >&2
    exit 1
fi
printf '%s\n' "$notes"
