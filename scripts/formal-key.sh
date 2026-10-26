#!/usr/bin/env bash
# The key of everything the Formal model job's result depends on: the same
# models, run by the same script and TLC, on the same Java, give the same
# answer, so CI skips TLC for a key it already ran green (docs/formal.md).
# Prints what is hashed, then the key, `formal-<sha256>`, on the last line.
#
# formal.sh copies formal/*.tla and formal/*.cfg and reads nothing else of the
# repo (formal-trace.mjs only prints a counterexample), so those are the
# inputs; the TLC jar is pinned by the checksum inside formal.sh. The workflow
# is hashed whole: a change to how the job runs, its runner image, a shard or
# the cache lookup, runs TLC again.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."

manifest="$(
  sha256sum formal/*.tla formal/*.cfg scripts/formal.sh scripts/formal-trace.mjs scripts/formal-key.sh .github/workflows/validate.yml
  # TLC's JVM: its vendor and exact build, and the machine's architecture.
  java -XshowSettings:properties -version 2>&1 |
    sed -nE 's/^ *((java\.(vendor|version|runtime\.name|runtime\.version|vm\.name|vm\.version)|os\.arch)) = (.*)$/\1 = \4/p'
)"
printf '%s\n' "$manifest"
echo "formal-$(printf '%s\n' "$manifest" | sha256sum | cut -d' ' -f1)"
