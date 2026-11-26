#!/usr/bin/env bash
# Download the Terraform and OpenTofu binaries the acceptance tests run, for
# linux/amd64, each checked against its pinned SHA-256, into <dir>; print
# them comma-separated, as COFFRE_ACC_BINARIES takes them. The oldest of
# each is the first release with write-only attributes; the newest is the
# newest when pinned.
#
#   COFFRE_ACC_BINARIES="$(terraform-provider/scripts/binaries.sh "$RUNNER_TEMP/tf")"
set -euo pipefail

dir="${1:?usage: binaries.sh <dir>}"
mkdir -p "$dir"

# name version url sha256
pins=(
  "terraform 1.11.4 https://releases.hashicorp.com/terraform/1.11.4/terraform_1.11.4_linux_amd64.zip 1ce994251c00281d6845f0f268637ba50c0005657eb3cf096b92f753b42ef4dc"
  "terraform 1.17.2 https://releases.hashicorp.com/terraform/1.17.2/terraform_1.17.2_linux_amd64.zip e6f16b2f0b137ee5729caa8c4e79a3bae4ee261acd198a1fcfa8584a6296605b"
  "tofu 1.11.14 https://github.com/opentofu/opentofu/releases/download/v1.11.14/tofu_1.11.14_linux_amd64.tar.gz 88ee1d2e1a69f266ac99b8b30374e07757a42219e745b046ea0426c08ea951ae"
  "tofu 1.13.10 https://github.com/opentofu/opentofu/releases/download/v1.13.10/tofu_1.13.10_linux_amd64.tar.gz f606b6117ee03177374806d56d580bde7b512aff69f86d2b9f3148dced4ca375"
)

paths=()
for pin in "${pins[@]}"; do
  read -r name version url sha <<< "$pin"
  target="$dir/$name-$version"
  if [[ ! -x "$target/$name" ]]; then
    archive="$dir/$(basename "$url")"
    curl -fsSL --retry 3 -o "$archive" "$url"
    echo "$sha  $archive" | sha256sum --check --quiet
    mkdir -p "$target"
    case "$archive" in
      *.zip) unzip -q -o "$archive" "$name" -d "$target" ;;
      *.tar.gz) tar -xzf "$archive" -C "$target" "$name" ;;
    esac
    rm "$archive"
  fi
  paths+=("$target/$name")
done
(IFS=,; echo "${paths[*]}")
