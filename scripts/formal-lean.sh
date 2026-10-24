#!/usr/bin/env bash
# Checks the Lean proofs in formal/lean and holds the model they are about to
# the code (docs/formal.md): builds every proof and the oracle, then runs
# scripts/formal-lean.ts, which compares the oracle's answers with
# packages/core's and the vault's on generated cases.
#
#   scripts/formal-lean.sh                 the proofs, and about 120,000 cases
#   scripts/formal-lean.sh --long          ten times as many cases
#   scripts/formal-lean.sh --seed=42       another reproducible set of them
#
# It uses the Lean on PATH if it is the release formal/lean/lean-toolchain
# names, as elan installs it; otherwise it downloads that release once and
# checks it against its pinned SHA-256. Bash 3.2, as macOS ships, will do.
set -euo pipefail

LEAN_VERSION=4.35.0

root="$(cd "$(dirname "$0")/.." && pwd)"
project="$root/formal/lean"
if [ "$(cat "$project/lean-toolchain")" != "leanprover/lean4:v$LEAN_VERSION" ]; then
  echo "formal/lean/lean-toolchain and LEAN_VERSION in $0 name different releases" >&2
  exit 1
fi

# A file's SHA-256: sha256sum on Linux, shasum on macOS.
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if ! command -v lake >/dev/null || [ "$(lean --version 2>/dev/null | awk '{print $3}' | tr -d ,)" != "$LEAN_VERSION" ]; then
  # Each platform's release archive and its SHA-256, from the release's own metadata. macOS's tar may lack zstd: a zip.
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) platform=linux archive=tar.zst digest=7289597a44543246c9227b8cae501767e095ce17f6d448b95fc4a8dc97268f6d ;;
    Linux-aarch64) platform=linux_aarch64 archive=tar.zst digest=c8f0f8a3920e839718b1343e6781fd80a3e9b1024fbcd7078eb30f54e806b028 ;;
    Darwin-x86_64) platform=darwin archive=zip digest=67002270b63c6cb12d6024fd00a38aa1e5fc9dc9b6c91cd3bd6f5aa34ed333ef ;;
    Darwin-arm64) platform=darwin_aarch64 archive=zip digest=55132a570e3dfc6203626944b262793c0f0f6a8230c0d09344a06ac992fac4a9 ;;
    *) echo "no Lean $LEAN_VERSION release pinned for $(uname -s)-$(uname -m): install it with elan" >&2; exit 1 ;;
  esac
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/coffre"
  home="$cache/lean-$LEAN_VERSION-$platform"
  if [ ! -x "$home/bin/lake" ]; then
    file="$cache/lean-$LEAN_VERSION-$platform.$archive"
    if [ ! -f "$file" ] || [ "$(sha256 "$file")" != "$digest" ]; then
      mkdir -p "$cache"
      curl -fsSL --retry 3 -o "$file.part" \
        "https://github.com/leanprover/lean4/releases/download/v$LEAN_VERSION/lean-$LEAN_VERSION-$platform.$archive"
      if [ "$(sha256 "$file.part")" != "$digest" ]; then
        echo "lean-$LEAN_VERSION-$platform.$archive does not match its pinned SHA-256" >&2
        rm -f "$file.part"
        exit 1
      fi
      mv "$file.part" "$file"
    fi
    rm -rf "$home.part"
    mkdir -p "$home.part"
    if [ "$archive" = zip ]; then
      unzip -q "$file" -d "$home.part"
      mv "$home.part/lean-$LEAN_VERSION-$platform"/* "$home.part/"
      rmdir "$home.part/lean-$LEAN_VERSION-$platform"
    else
      tar --zstd -xf "$file" -C "$home.part" --strip-components=1
    fi
    mv "$home.part" "$home"
  fi
  export PATH="$home/bin:$PATH"
fi

# Every proof, then the oracle. A proof that no longer holds fails the build; one that rests on a sorry or an axiom
# of ours fails the check after it.
(cd "$project" && lake build && lake env lean CheckAxioms.lean)

node --conditions=coffre:source "$root/scripts/formal-lean.ts" "$project/.lake/build/bin/oracle" "$@"
