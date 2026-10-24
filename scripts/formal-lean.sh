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
# checks it against its pinned SHA-256.
set -euo pipefail

LEAN_VERSION=4.35.0
declare -A LEAN_SHA256=(
  [linux]=7289597a44543246c9227b8cae501767e095ce17f6d448b95fc4a8dc97268f6d
  [linux_aarch64]=c8f0f8a3920e839718b1343e6781fd80a3e9b1024fbcd7078eb30f54e806b028
  [darwin]=0b43be5c7ecfb36016566a41005ab62bdb04743e6bfd5837e45f796ef4750b4e
  [darwin_aarch64]=c0c6f34f35ba1dcc5c4a5fd106fefab9eb5e8469712624dd2c868d51b63177c2
)

root="$(cd "$(dirname "$0")/.." && pwd)"
project="$root/formal/lean"
if [ "$(cat "$project/lean-toolchain")" != "leanprover/lean4:v$LEAN_VERSION" ]; then
  echo "formal/lean/lean-toolchain and LEAN_VERSION in $0 name different releases" >&2
  exit 1
fi

if ! command -v lake >/dev/null || [ "$(lean --version 2>/dev/null | awk '{print $3}' | tr -d ,)" != "$LEAN_VERSION" ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) platform=linux ;;
    Linux-aarch64) platform=linux_aarch64 ;;
    Darwin-x86_64) platform=darwin ;;
    Darwin-arm64) platform=darwin_aarch64 ;;
    *) echo "no Lean $LEAN_VERSION release pinned for $(uname -s)-$(uname -m): install it with elan" >&2; exit 1 ;;
  esac
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/coffre"
  home="$cache/lean-$LEAN_VERSION-$platform"
  if [ ! -x "$home/bin/lake" ]; then
    archive="$cache/lean-$LEAN_VERSION-$platform.tar.zst"
    if ! echo "${LEAN_SHA256[$platform]}  $archive" | sha256sum -c --status 2>/dev/null; then
      mkdir -p "$cache"
      curl -fsSL --retry 3 -o "$archive.part" \
        "https://github.com/leanprover/lean4/releases/download/v$LEAN_VERSION/lean-$LEAN_VERSION-$platform.tar.zst"
      echo "${LEAN_SHA256[$platform]}  $archive.part" | sha256sum -c --quiet
      mv "$archive.part" "$archive"
    fi
    rm -rf "$home.part"
    mkdir -p "$home.part"
    tar --zstd -xf "$archive" -C "$home.part" --strip-components=1
    mv "$home.part" "$home"
  fi
  export PATH="$home/bin:$PATH"
fi

# Every proof, then the oracle. A proof that no longer holds fails the build.
(cd "$project" && lake build)
if grep -rnE '\b(sorry|admit)\b|^axiom ' "$project/Coffre" "$project/Oracle.lean"; then
  echo "formal/lean proves nothing it assumes in a sorry, an admit or an axiom" >&2
  exit 1
fi

node --conditions=coffre:source "$root/scripts/formal-lean.ts" "$project/.lake/build/bin/oracle" "$@"
