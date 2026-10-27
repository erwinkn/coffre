#!/usr/bin/env bash
# Holds 0.15's audit trees to Go's own implementation, golang.org/x/mod/sumdb
# (packages/core/test/go, docs/design/audit-tree.md, "Checked by Go"):
#
# 1. Go builds a tree from known leaves; its heads, proofs and tile bytes
#    must be the ones packages/core/test/vectors/audit-tree.json pins, which
#    the TypeScript tests hold the code to in every run (`--write` rewrites
#    them).
# 2. The vault's checkpointer seals a split log of about 70,000 uses and 400
#    changes; Go opens every pair's notes, rebuilds every tile byte for byte,
#    and checks sampled proofs and every head's consistency, then does the same
#    through uses-tree cuts that keep one tile per level below them.
#
# It uses the Go on PATH if it is GO_VERSION, else downloads that release once
# and checks it against its pinned SHA-256. Not part of CI: the vectors carry
# Go's answers there.
set -euo pipefail

GO_VERSION=1.27.3

root="$(cd "$(dirname "$0")/.." && pwd)"
sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if [ "$(go env GOVERSION 2>/dev/null || true)" != "go$GO_VERSION" ]; then
  # Each platform's archive and its SHA-256, from go.dev/dl's own metadata.
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) platform=linux-amd64 digest=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
    Linux-aarch64) platform=linux-arm64 digest=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
    Darwin-x86_64) platform=darwin-amd64 digest=b6f8e931e4ab497fcde6da8ae4499a58f9d258e55c8a80824a516eae5950a750 ;;
    Darwin-arm64) platform=darwin-arm64 digest=dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2 ;;
    *) echo "no Go $GO_VERSION release pinned for $(uname -s)-$(uname -m): install it" >&2; exit 1 ;;
  esac
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/coffre"
  home="$cache/go-$GO_VERSION-$platform"
  if [ ! -x "$home/bin/go" ]; then
    file="$cache/go$GO_VERSION.$platform.tar.gz"
    mkdir -p "$cache"
    curl -fsSL --retry 3 -o "$file.part" "https://go.dev/dl/go$GO_VERSION.$platform.tar.gz"
    if [ "$(sha256 "$file.part")" != "$digest" ]; then
      echo "go$GO_VERSION.$platform.tar.gz does not match its pinned SHA-256" >&2
      rm -f "$file.part"
      exit 1
    fi
    rm -rf "$home.part"
    mkdir -p "$home.part"
    tar -xzf "$file.part" -C "$home.part" --strip-components=1
    rm -f "$file.part"
    mv "$home.part" "$home"
  fi
  export PATH="$home/bin:$PATH" GOTOOLCHAIN=local
fi
# go.sum pins golang.org/x/mod; nothing here may change it.
export GOFLAGS=-mod=readonly

checker="$root/packages/core/test/go"
vectors="$root/packages/core/test/vectors/audit-tree.json"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$checker" && go run . vectors) > "$work/go.json"
node -e '
  const fs = require("node:fs");
  const [, vectorsPath, goPath, write] = process.argv;
  const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8"));
  const go = JSON.parse(fs.readFileSync(goPath, "utf8"));
  if (write === "--write") {
    fs.writeFileSync(vectorsPath, JSON.stringify({ ...vectors, go }, null, 2) + "\n");
    console.log("vectors: Go section rewritten");
  } else if (JSON.stringify(vectors.go) !== JSON.stringify(go)) {
    console.error("vectors: Go builds another tree than the one pinned (run with --write if the leaves changed)");
    process.exit(1);
  } else {
    console.log(`vectors: Go'"'"'s heads, proofs and ${Object.keys(go.tiles).length} tiles are the ones pinned`);
  }
' "$vectors" "$work/go.json" "${1:-}"

node --conditions=coffre:source "$root/packages/vault/scripts/audit-tree-fixture.ts" "$work/fixture.json"
(cd "$checker" && go run . check "$work/fixture.json")
