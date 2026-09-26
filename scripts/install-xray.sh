#!/usr/bin/env bash
# Install the Xray release pinned for the servers (ansible/roles/xray_bin/defaults)
# into DIR (default ~/.local/bin), verifying its sha256. Used by CI and handy for
# local tests: config validation and the integration test's client need `xray`.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEFAULTS="$ROOT/ansible/roles/xray_bin/defaults/main.yml"
DIR=${1:-$HOME/.local/bin}

version=$(awk '/^xray_version:/ {print $2}' "$DEFAULTS")
sha256=$(awk '/^  "64":/ {print $2}' "$DEFAULTS")
[[ -n "$version" && -n "$sha256" ]] || { echo "cannot read pinned version from $DEFAULTS" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/$version/Xray-linux-64.zip"
echo "$sha256  $tmp/xray.zip" | sha256sum -c --quiet
unzip -q "$tmp/xray.zip" -d "$tmp/x"
mkdir -p "$DIR"
install -m 0755 "$tmp/x/xray" "$DIR/xray"
install -m 0644 "$tmp/x/geoip.dat" "$tmp/x/geosite.dat" "$DIR/"
"$DIR/xray" version | head -1
