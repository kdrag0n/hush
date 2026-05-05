#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_asset() {
  local asset=$1
  [[ -f "${DIST_DIR}/${asset}" ]] || die "missing release asset ${DIST_DIR}/${asset}"
}

DIST_DIR=${DIST_DIR:-dist}
TAP_REPO=${TAP_REPO:-kdrag0n/homebrew-tap}
TAP_BRANCH=${TAP_BRANCH:-main}
FORMULA_PATH=${FORMULA_PATH:-Formula/hush.rb}
HUSH_REPOSITORY=${HUSH_REPOSITORY:-${GITHUB_REPOSITORY:-kdrag0n/hush}}
HUSH_VERSION=${HUSH_VERSION:-0.1.0}
HOMEBREW_REVISION=${HOMEBREW_REVISION:-${GITHUB_RUN_NUMBER:-}}

[[ -n "${HOMEBREW_REVISION}" ]] || die "HOMEBREW_REVISION or GITHUB_RUN_NUMBER must be set"
[[ "${HOMEBREW_REVISION}" =~ ^[0-9]+$ ]] || die "HOMEBREW_REVISION must be an integer"
[[ -n "${GH_TOKEN:-}" ]] || die "GH_TOKEN must be set"
command -v gh >/dev/null 2>&1 || die "gh CLI is required"

if [[ -n "${RELEASE_TAG:-}" ]]; then
  release_tag=${RELEASE_TAG}
else
  ref_name=${GITHUB_REF_NAME:-main}
  safe_ref=$(printf '%s' "${ref_name}" | tr -c 'A-Za-z0-9._-' '-')
  release_tag="prerelease-${safe_ref}"
fi

assets=(
  hush-macos-aarch64
  hush-server-macos-aarch64
  hush-macos-x86_64
  hush-server-macos-x86_64
  hush-linux-aarch64-musl
  hush-server-linux-aarch64-musl
  hush-linux-x86_64-musl
  hush-server-linux-x86_64-musl
)

for asset in "${assets[@]}"; do
  require_asset "${asset}"
done

url_base="https://github.com/${HUSH_REPOSITORY}/releases/download/${release_tag}"
sha_hush_macos_arm=$(sha256_file "${DIST_DIR}/hush-macos-aarch64")
sha_server_macos_arm=$(sha256_file "${DIST_DIR}/hush-server-macos-aarch64")
sha_hush_macos_x64=$(sha256_file "${DIST_DIR}/hush-macos-x86_64")
sha_server_macos_x64=$(sha256_file "${DIST_DIR}/hush-server-macos-x86_64")
sha_hush_linux_arm=$(sha256_file "${DIST_DIR}/hush-linux-aarch64-musl")
sha_server_linux_arm=$(sha256_file "${DIST_DIR}/hush-server-linux-aarch64-musl")
sha_hush_linux_x64=$(sha256_file "${DIST_DIR}/hush-linux-x86_64-musl")
sha_server_linux_x64=$(sha256_file "${DIST_DIR}/hush-server-linux-x86_64-musl")

workdir=$(mktemp -d)
trap 'rm -rf "${workdir}"' EXIT

export GH_CONFIG_DIR=${GH_CONFIG_DIR:-"${workdir}/gh"}
mkdir -p "${GH_CONFIG_DIR}"
gh config set git_protocol https --host github.com
gh auth setup-git --hostname github.com
gh repo clone "${TAP_REPO}" "${workdir}/tap" -- --branch "${TAP_BRANCH}"

formula="${workdir}/tap/${FORMULA_PATH}"
mkdir -p "$(dirname "${formula}")"

cat > "${formula}" <<EOF
class Hush < Formula
  desc "Modern fuss-free SSH over QUIC"
  homepage "https://github.com/${HUSH_REPOSITORY}"
  version "${HUSH_VERSION}"
  revision ${HOMEBREW_REVISION}
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "${url_base}/hush-macos-aarch64",
        using: :nounzip
    sha256 "${sha_hush_macos_arm}"

    resource "hush-server" do
      url "${url_base}/hush-server-macos-aarch64",
          using: :nounzip
      sha256 "${sha_server_macos_arm}"
    end
  elsif OS.mac? && Hardware::CPU.intel?
    url "${url_base}/hush-macos-x86_64",
        using: :nounzip
    sha256 "${sha_hush_macos_x64}"

    resource "hush-server" do
      url "${url_base}/hush-server-macos-x86_64",
          using: :nounzip
      sha256 "${sha_server_macos_x64}"
    end
  elsif OS.linux? && Hardware::CPU.arm?
    url "${url_base}/hush-linux-aarch64-musl",
        using: :nounzip
    sha256 "${sha_hush_linux_arm}"

    resource "hush-server" do
      url "${url_base}/hush-server-linux-aarch64-musl",
          using: :nounzip
      sha256 "${sha_server_linux_arm}"
    end
  elsif OS.linux? && Hardware::CPU.intel?
    url "${url_base}/hush-linux-x86_64-musl",
        using: :nounzip
    sha256 "${sha_hush_linux_x64}"

    resource "hush-server" do
      url "${url_base}/hush-server-linux-x86_64-musl",
          using: :nounzip
      sha256 "${sha_server_linux_x64}"
    end
  else
    odie "hush prebuilt binaries are not available for this platform"
  end

  def install
    bin.install cached_download => "hush"
    bin.install resource("hush-server").cached_download => "hush-server"
  end

  service do
    run [opt_bin/"hush-server"]
    keep_alive true
    require_root true
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/hush --version")
    assert_match version.to_s, shell_output("#{bin}/hush-server --version")
  end
end
EOF

ruby -c "${formula}"

git -C "${workdir}/tap" config user.name "github-actions[bot]"
git -C "${workdir}/tap" config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git -C "${workdir}/tap" add "${FORMULA_PATH}"

if git -C "${workdir}/tap" diff --cached --quiet; then
  printf 'Homebrew formula is already up to date.\n'
  exit 0
fi

git -C "${workdir}/tap" commit -m "Update hush prerelease formula"
git -C "${workdir}/tap" push origin "HEAD:${TAP_BRANCH}"
