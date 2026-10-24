#!/bin/sh
# OMGS first-run binary bootstrap (POSIX).
# Downloads the platform binary from a release base, verifies its SHA-256
# against the release SHA256SUMS file, and installs it without sudo into
# ${OMGS_HOME:-$HOME/.local/share/omgs}/bin. Prints the installed path.
set -eu

BASE="${OMGS_RELEASE_BASE:-https://github.com/OpenAdminOS/OMGSecurity/releases/latest/download}"
DEST_ROOT="${OMGS_HOME:-$HOME/.local/share/omgs}"
DEST="$DEST_ROOT/bin"

os="$(uname -s)"
arch="$(uname -m)"
case "$os/$arch" in
  Darwin/arm64) asset="omgs-aarch64-apple-darwin" ;;
  Darwin/x86_64) asset="omgs-x86_64-apple-darwin" ;;
  Linux/x86_64) asset="omgs-x86_64-unknown-linux-gnu" ;;
  Linux/aarch64|Linux/arm64) asset="omgs-aarch64-unknown-linux-gnu" ;;
  *) echo "omgs bootstrap: unsupported platform $os/$arch" >&2; exit 1 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "downloading $BASE/$asset"
curl -fsSL "$BASE/$asset" -o "$tmp/$asset"
curl -fsSL "$BASE/SHA256SUMS" -o "$tmp/SHA256SUMS"

expected="$(awk -v a="$asset" '$2 == a || $2 == "*" a {print $1}' "$tmp/SHA256SUMS")"
if [ -z "$expected" ]; then
  echo "omgs bootstrap: no checksum entry for $asset" >&2; exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
fi
if [ "$actual" != "$expected" ]; then
  echo "omgs bootstrap: checksum mismatch for $asset" >&2; exit 1
fi

mkdir -p "$DEST"
install -m 0755 "$tmp/$asset" "$DEST/omgs"
echo "$DEST/omgs"
"$DEST/omgs" --version
