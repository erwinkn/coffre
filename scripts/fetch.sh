#!/usr/bin/env bash
# fetch.sh <https url> <sha256> <file>: the file, downloaded once and held to
# its pinned SHA-256. A file already there with that hash is kept; otherwise
# the download goes to <file>.part, and becomes <file> only if its hash is the
# pinned one. A mismatch removes it and fails.
#
# This is the one place in the repository that downloads: `pnpm check:pins`
# fails on curl, wget or any other fetcher anywhere else (scripts/pins.mjs).
set -euo pipefail

if [ $# -ne 3 ]; then
    echo "usage: $0 <https url> <sha256> <file>" >&2
    exit 2
fi
url="$1" want="$2" file="$3"
case "$url" in https://*) ;; *) echo "$0: $url is not https" >&2; exit 2 ;; esac
if ! [[ "$want" =~ ^[0-9a-f]{64}$ ]]; then
    echo "$0: $want is not a SHA-256 (64 lowercase hex digits)" >&2
    exit 2
fi

# sha256sum on Linux, shasum on macOS.
sha256() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if [ -f "$file" ] && [ "$(sha256 "$file")" = "$want" ]; then exit 0; fi
mkdir -p "$(dirname "$file")"
rm -f "$file.part"
curl -fsSL --proto '=https' --retry 3 -o "$file.part" "$url"
got="$(sha256 "$file.part")"
if [ "$got" != "$want" ]; then
    rm -f "$file.part"
    echo "$url: SHA-256 $got, not the pinned $want" >&2
    exit 1
fi
mv "$file.part" "$file"
