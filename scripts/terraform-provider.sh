#!/usr/bin/env bash
# Checks the Terraform provider, terraform-provider/ (docs/design/terraform-provider.md,
# section 8): gofmt, go vet, its unit tests, then its acceptance tests on
# Terraform and OpenTofu against a local coffre, the Node example on SQLite
# that packages/conformance/scripts/terraform-fixture.ts boots on ports 3482
# and 3483. Never a live instance.
#
# Go, Terraform and OpenTofu are pinned by version and SHA-256, as
# scripts/formal.sh pins TLC, and downloaded once into the cache below. Run
# `pnpm build` first: the fixture boots the example as conformance does.
#
#   scripts/terraform-provider.sh            everything
#   scripts/terraform-provider.sh --unit     gofmt, vet and the unit tests alone: no coffre, no Terraform
set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"

GO_VERSION=1.27.3
TERRAFORM_VERSION=1.11.4
TOFU_VERSION=1.11.14

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) platform=linux_amd64 ;;
    Linux/aarch64 | Linux/arm64) platform=linux_arm64 ;;
    Darwin/arm64) platform=darwin_arm64 ;;
    Darwin/x86_64) platform=darwin_amd64 ;;
    *) echo "no pinned tools for $(uname -s)/$(uname -m)" >&2; exit 2 ;;
esac

# pinned <tool>: the tool's SHA-256 for this platform, from its release's own sums.
pinned() {
    case "$1/$platform" in
        go/linux_amd64) echo 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 ;;
        go/linux_arm64) echo a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49 ;;
        go/darwin_arm64) echo dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2 ;;
        go/darwin_amd64) echo b6f8e931e4ab497fcde6da8ae4499a58f9d258e55c8a80824a516eae5950a750 ;;
        terraform/linux_amd64) echo 1ce994251c00281d6845f0f268637ba50c0005657eb3cf096b92f753b42ef4dc ;;
        terraform/linux_arm64) echo a43d1d0da9b9bab214a8305a39db0e40869572594ccf50c416a7756499143633 ;;
        terraform/darwin_arm64) echo 867e0808fa971217043e25b7a792b10720c79b1546f8a68479b74f138be73e18 ;;
        terraform/darwin_amd64) echo a56d5002b9f7647291faccc3dd1a70350e60fb61e4c45037629508b8fdc2575b ;;
        tofu/linux_amd64) echo 8279a6c6d4044899ae77190fc50c40c147615a76aca13ea605d68320c424c2a6 ;;
        tofu/linux_arm64) echo 3171726f7b1164af56fb67368742aa851162b8a9a60628ff73b8590e7f22dc73 ;;
        tofu/darwin_arm64) echo bc4025a749d074ccf168b8a24600fcdf95645ad13937c9bd40de90ce55fdc29a ;;
        tofu/darwin_amd64) echo 13e8995ddaa5ad321b84bcf48880faccca567ebe1230db579ab159fd15995b60 ;;
    esac
}

cache="${XDG_CACHE_HOME:-$HOME/.cache}/coffre/terraform-provider"
mkdir -p "$cache"

sha256() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# fetch <url> <sha256> <file>: the file, downloaded once and held to its hash.
fetch() {
    local url="$1" want="$2" file="$cache/$3"
    if [ ! -f "$file" ] || [ "$(sha256 "$file")" != "$want" ]; then
        curl -fsSL --retry 3 -o "$file.part" "$url"
        local got
        got="$(sha256 "$file.part")"
        if [ "$got" != "$want" ]; then
            rm -f "$file.part"
            echo "$url: SHA-256 $got, not the pinned $want" >&2
            exit 1
        fi
        mv "$file.part" "$file"
    fi
}

go_os="${platform%_*}" go_arch="${platform#*_}"
go_dir="$cache/go-$GO_VERSION"
if [ ! -x "$go_dir/bin/go" ]; then
    fetch "https://go.dev/dl/go$GO_VERSION.$go_os-$go_arch.tar.gz" "$(pinned go)" "go-$GO_VERSION.tar.gz"
    rm -rf "$go_dir" "$go_dir.part" && mkdir -p "$go_dir.part"
    tar -xzf "$cache/go-$GO_VERSION.tar.gz" -C "$go_dir.part" --strip-components=1
    mv "$go_dir.part" "$go_dir"
fi
export PATH="$go_dir/bin:$PATH" GOTOOLCHAIN=local GOFLAGS=-mod=readonly

cd terraform-provider
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
    echo "gofmt would change: $unformatted" >&2
    exit 1
fi
go vet ./...
go test -count=1 ./internal/coffre ./internal/provider ./internal/acceptance
[ "${1:-}" = --unit ] && exit 0

# unpack <zip> <binary> <dir>: the release's one binary, unpacked once.
unpack() {
    local zip="$cache/$1" binary="$2" dir="$cache/$3"
    if [ ! -x "$dir/$binary" ]; then
        rm -rf "$dir" && mkdir -p "$dir"
        (cd "$dir" && unzip -q "$zip" "$binary")
    fi
    echo "$dir/$binary"
}
fetch "https://releases.hashicorp.com/terraform/$TERRAFORM_VERSION/terraform_${TERRAFORM_VERSION}_$platform.zip" "$(pinned terraform)" "terraform-$TERRAFORM_VERSION.zip"
fetch "https://github.com/opentofu/opentofu/releases/download/v$TOFU_VERSION/tofu_${TOFU_VERSION}_$platform.zip" "$(pinned tofu)" "tofu-$TOFU_VERSION.zip"
terraform="$(unpack "terraform-$TERRAFORM_VERSION.zip" terraform "terraform-$TERRAFORM_VERSION")"
tofu="$(unpack "tofu-$TOFU_VERSION.zip" tofu "tofu-$TOFU_VERSION")"

TF_ACC=1 go test -count=1 -timeout 30m ./internal/acceptance -args -terraform="$terraform" -tofu="$tofu" -repo="$root"
