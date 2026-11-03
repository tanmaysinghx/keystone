#!/usr/bin/env bash
# Keystone Vault installer.
#
#   curl -fsSL https://raw.githubusercontent.com/tanmaysinghx/keystone-vault/main/install.sh | bash
#   curl -fsSL .../install.sh | sudo bash -s -- --service        # + systemd service in /var/lib/keystone
#   curl -fsSL .../install.sh | bash -s -- --version v1.0.42     # a specific release
#
# Downloads the release binary for this platform, verifies its SHA-256 checksum and installs it.
# The binary contains the console; no runtime, database server or web server is needed.
set -euo pipefail

REPO="tanmaysinghx/keystone-vault"
VERSION="${KEYSTONE_VERSION:-latest}"
SERVICE=0
PREFIX=""
while [ $# -gt 0 ]; do
  case "$1" in
    --service) SERVICE=1 ;;
    --version) VERSION="$2"; shift ;;
    --prefix) PREFIX="$2"; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) die "Unsupported OS $(uname -s). Download a release manually or use Docker." ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  arm64|aarch64) arch=aarch64 ;;
  *) die "Unsupported CPU $(uname -m)." ;;
esac
asset="keystone-${os}-${arch}.tar.gz"
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/${REPO}/releases/latest/download"
else
  base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

if [ -z "$PREFIX" ]; then
  if [ "$(id -u)" = 0 ]; then PREFIX=/usr/local/bin; else PREFIX="$HOME/.local/bin"; fi
fi
[ "$SERVICE" = 1 ] && [ "$(id -u)" != 0 ] && die "--service needs root (sudo)."

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
say "Downloading Keystone Vault ($VERSION, $os-$arch)"
fetch() { if command -v curl >/dev/null; then curl -fsSL -o "$2" "$1"; else wget -qO "$2" "$1"; fi; }
fetch "$base/$asset" "$tmp/$asset" || die "Download failed: $base/$asset"
fetch "$base/$asset.sha256" "$tmp/$asset.sha256" || die "Checksum download failed"
expected="$(cut -d' ' -f1 < "$tmp/$asset.sha256")"
if command -v sha256sum >/dev/null; then actual="$(sha256sum "$tmp/$asset" | cut -d' ' -f1)"; else actual="$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)"; fi
[ "$expected" = "$actual" ] || die "Checksum mismatch: the download is corrupt or was tampered with."
say "Checksum verified"
tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$PREFIX"
install -m 0755 "$tmp/keystone" "$PREFIX/keystone"
say "Installed $("$PREFIX/keystone" version) to $PREFIX/keystone"

if [ "$SERVICE" = 1 ]; then
  id keystone >/dev/null 2>&1 || useradd --system --home-dir /var/lib/keystone --shell /usr/sbin/nologin keystone
  install -d -m 0700 -o keystone -g keystone /var/lib/keystone
  install -d -m 0750 -o root -g keystone /etc/keystone
  if [ ! -f /etc/keystone/keystone.properties ]; then
    as_keystone() { if command -v runuser >/dev/null; then runuser -u keystone -- "$@"; else sudo -u keystone "$@"; fi; }
    as_keystone "$PREFIX/keystone" init --home /var/lib/keystone --config /tmp/keystone.properties.$$ >/dev/null
    install -m 0640 -o root -g keystone /tmp/keystone.properties.$$ /etc/keystone/keystone.properties
    rm -f /tmp/keystone.properties.$$
  fi
  fetch "https://raw.githubusercontent.com/${REPO}/main/distribution/keystone.service" "$tmp/keystone.service" \
    || die "Could not download the systemd unit"
  sed "s#/usr/local/bin/keystone#$PREFIX/keystone#" "$tmp/keystone.service" > /etc/systemd/system/keystone.service
  systemctl daemon-reload
  systemctl enable --now keystone
  say "Service started: systemctl status keystone"
  echo
  echo "  Config:      /etc/keystone/keystone.properties   (edit, then: sudo systemctl restart keystone)"
  echo "  Data:        /var/lib/keystone"
  echo "  Master key:  /var/lib/keystone/secrets/master.key   BACK IT UP somewhere else now"
  echo "  Connect Portal SSO:"
  echo "    sudo systemctl stop keystone"
  echo "    sudo -u keystone $PREFIX/keystone connect-portal https://your-portal --home /var/lib/keystone --config /etc/keystone/keystone.properties"
  echo "    sudo systemctl start keystone"
else
  case ":$PATH:" in *":$PREFIX:"*) ;; *) echo "Add $PREFIX to your PATH." ;; esac
  echo
  echo "  Next:"
  echo "    keystone connect-portal https://your-portal     # once; a Portal admin approves it"
  echo "    keystone                                        # http://127.0.0.1:8090"
  echo "  Everything is in ~/.keystone (config: ~/.keystone/keystone.properties)."
fi
