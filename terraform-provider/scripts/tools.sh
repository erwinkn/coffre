# Sourced: the Go and GoReleaser the provider is built and released with,
# pinned by version and SHA-256 (each from its release's own sums), downloaded
# once into the cache below through fetch.sh, a copy of coffre's
# scripts/fetch.sh: this directory is also the root of the provider's mirror
# repository, which holds nothing else of coffre's.
#
#   use_go           Go on PATH, GOTOOLCHAIN=local and GOFLAGS=-mod=readonly
#   use_goreleaser   GoReleaser on PATH
#
# coffre's scripts/terraform-provider.sh sources it too, and pins Terraform
# and OpenTofu beside it for the acceptance tests.

GO_VERSION=1.27.3
GORELEASER_VERSION=2.19.0

tools_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools_cache="${XDG_CACHE_HOME:-$HOME/.cache}/coffre/terraform-provider"

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) tools_platform=linux_amd64 ;;
    Linux/aarch64 | Linux/arm64) tools_platform=linux_arm64 ;;
    Darwin/arm64) tools_platform=darwin_arm64 ;;
    Darwin/x86_64) tools_platform=darwin_amd64 ;;
    *) echo "no pinned tools for $(uname -s)/$(uname -m)" >&2; exit 2 ;;
esac

# tools_unpack <url> <sha256> <name> [tar option…]: the archive's tree in the
# cache as <name>, downloaded and unpacked once. Each run unpacks into a
# directory of its own, and the first to link it in as <name> wins: a symlink
# is made whole or not at all, and never over another (-n: nor inside the one
# there), so a run beside it never sees half a tree or loses its own
# (scripts/zizmor.sh in coffre does the same). Only a tree whose download
# and unpacking both succeeded is linked, and each step's failure is
# returned: a caller that tests this function (`use_go && …`, `if use_go`)
# turns errexit off inside it, which would otherwise carry on and cache an
# empty tree. The archive stays, for a run that has yet to unpack it.
tools_unpack() {
    local url="$1" sha="$2" name="$3" dir="$tools_cache/$3" unpacked
    shift 3
    [ ! -e "$dir" ] || return 0
    mkdir -p "$tools_cache" || return 1
    "$tools_dir/fetch.sh" "$url" "$sha" "$dir.tar.gz" || return 1
    unpacked="$(mktemp -d "$dir.XXXXXX")" || return 1
    tar -xzf "$dir.tar.gz" -C "$unpacked" "$@" || { rm -rf "$unpacked"; return 1; }
    ln -sn "$(basename "$unpacked")" "$dir" 2>/dev/null && return 0
    rm -rf "$unpacked"
    [ -e "$dir" ] # another run's tree, or a link that failed
}

use_go() {
    local sha
    case "$tools_platform" in
        linux_amd64) sha=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
        linux_arm64) sha=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
        darwin_arm64) sha=dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2 ;;
        darwin_amd64) sha=b6f8e931e4ab497fcde6da8ae4499a58f9d258e55c8a80824a516eae5950a750 ;;
    esac
    tools_unpack "https://go.dev/dl/go$GO_VERSION.${tools_platform/_/-}.tar.gz" "$sha" "go-$GO_VERSION" --strip-components=1 || return 1
    export PATH="$tools_cache/go-$GO_VERSION/bin:$PATH" GOTOOLCHAIN=local GOFLAGS=-mod=readonly
}

use_goreleaser() {
    local sha archive
    case "$tools_platform" in
        linux_amd64) archive=Linux_x86_64 sha=ebc3194ad1d1b1787614405285a0039665cd4c5bd3305215a1b201600f90630b ;;
        linux_arm64) archive=Linux_arm64 sha=ef33741b684c9f62d6a21e7a3c8b051f139ea7b1d301693b67cc819c46226d53 ;;
        darwin_arm64) archive=Darwin_arm64 sha=713192b46698ac10ed9275abf25c922a152ab8280c71ae58dc0ff46a33f60004 ;;
        darwin_amd64) archive=Darwin_x86_64 sha=164fce297e601ec00009e40d26858789b637335b5564bff2c99027b10d28bafe ;;
    esac
    tools_unpack "https://github.com/goreleaser/goreleaser/releases/download/v$GORELEASER_VERSION/goreleaser_$archive.tar.gz" "$sha" "goreleaser-$GORELEASER_VERSION" || return 1
    export PATH="$tools_cache/goreleaser-$GORELEASER_VERSION:$PATH"
}
