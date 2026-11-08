#!/usr/bin/env bash
# Checks the Terraform provider, terraform-provider/ (docs/design/terraform-provider.md,
# section 8): gofmt, go vet, its unit tests, then its release (GoReleaser's
# snapshot) installed and run by Terraform and OpenTofu, then its acceptance
# tests on both against a local coffre, the Node example on SQLite that
# packages/conformance/scripts/terraform-fixture.ts boots on ports 3482 and
# 3483. Never a live instance.
#
# Go and GoReleaser come from terraform-provider/scripts/tools.sh, which the
# provider's own release builds with; Terraform and OpenTofu are pinned here.
# Each by version and SHA-256, as scripts/formal.sh pins TLC, and downloaded
# once into the cache. Run `pnpm build` first: the fixture boots the example
# as conformance does.
#
#   scripts/terraform-provider.sh            everything
#   scripts/terraform-provider.sh --unit     gofmt, vet and the unit tests alone: no release, no coffre, no Terraform
set -euo pipefail

cd "$(dirname "$0")/.."
root="$PWD"

source terraform-provider/scripts/tools.sh
platform="$tools_platform"
use_go

TERRAFORM_VERSION=1.11.4
TOFU_VERSION=1.11.14

# pinned <tool>: the tool's SHA-256 for this platform, from its release's own sums.
pinned() {
    case "$1/$platform" in
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

cache="$tools_cache"

# fetch <url> <sha256> <file>: the file in the cache, downloaded once and held to its hash.
fetch() {
    "$root/scripts/fetch.sh" "$1" "$2" "$cache/$3"
}

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

# The release as Terraform and OpenTofu install it, with their own code:
# GoReleaser's snapshot (.goreleaser.yml, unsigned), this platform's zip in a
# packed filesystem mirror, `init` from that mirror alone, then a plan and the
# schema, which run the provider.
use_goreleaser
goreleaser release --snapshot --clean --skip=sign
zip="$(echo dist/terraform-provider-coffre_*_"$platform".zip)"
version="${zip#dist/terraform-provider-coffre_}"
version="${version%_"$platform".zip}"
installed="$(mktemp -d)"
trap 'rm -rf "$installed"' EXIT
mkdir -p "$installed/mirror/registry.terraform.io/erwinkn/coffre"
cp "$zip" "$installed/mirror/registry.terraform.io/erwinkn/coffre/"
echo "provider_installation { filesystem_mirror { path = \"$installed/mirror\" } }" > "$installed/cli.tfrc"
# from_mirror <arg>…: $cli in $work, installing from the mirror alone.
from_mirror() {
    env TF_CLI_CONFIG_FILE="$installed/cli.tfrc" HOME="$work" TF_IN_AUTOMATION=1 CHECKPOINT_DISABLE=1 \
        "$cli" -chdir="$work" "$@"
}
for cli in "$terraform" "$tofu"; do
    work="$installed/$(basename "$cli")"
    mkdir "$work"
    cat > "$work/main.tf" <<HCL
terraform {
  required_providers {
    coffre = { source = "registry.terraform.io/erwinkn/coffre", version = "$version" }
  }
}
provider "coffre" { url = "https://coffre.invalid" }
HCL
    from_mirror init -input=false -no-color > /dev/null
    from_mirror plan -input=false -no-color > /dev/null
    schema="$(from_mirror providers schema -json)"
    grep -q '"coffre_secret"' <<< "$schema"
    echo "$(basename "$cli") installed $zip and ran it"
done
rm -rf dist

TF_ACC=1 go test -count=1 -timeout 30m ./internal/acceptance -args -terraform="$terraform" -tofu="$tofu" -repo="$root"
