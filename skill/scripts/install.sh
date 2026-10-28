#!/bin/sh
# Per-user bootstrap. No test verifier or signature bypass is accepted here.
set -eu
[ "$#" -eq 0 ] || { echo "No installer arguments are accepted" >&2; exit 2; }
export RUSTUP_AUTO_INSTALL=0
SKILL_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(cat "$SKILL_DIR/VERSION")
printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || exit 1
BASE=${OMGS_RELEASE_BASE:-https://github.com/OpenAdminOS/oh-my-god-security/releases/download/v$VERSION}
DEST_ROOT=${OMGS_HOME:-$HOME/.local/share/omgs}
case "$DEST_ROOT" in /*) ;; *) echo 'OMGS_HOME must be absolute' >&2; exit 1 ;; esac
# Owner sets this public signing identity before the first public release.
OMGS_TEAM_ID='OWNER_TEAM_ID'
MICROSOFT_TEAM_ID='UBF8T346G9'
os=$(uname -s)
arch=$(uname -m)
if [ "$os/$arch" = Darwin/x86_64 ] && [ "$(/usr/sbin/sysctl -in sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then arch=arm64; fi
[ "$arch" != arm64 ] || [ "$os" != Linux ] || arch=aarch64
case "$os/$arch" in
  Darwin/arm64) asset=omgs-aarch64-apple-darwin ;;
  Darwin/x86_64) asset=omgs-x86_64-apple-darwin ;;
  Linux/x86_64) asset=omgs-x86_64-unknown-linux-gnu ;;
  Linux/aarch64) asset=omgs-aarch64-unknown-linux-gnu ;;
  *) echo "unsupported platform $os/$arch" >&2; exit 1 ;;
esac
row=$(awk -v p="$os/$arch" '$1 == p {print}' "$SKILL_DIR/mxc-pins.txt")
mxc_asset=$(printf '%s' "$row" | awk '{print $3}')
mxc_hash=$(printf '%s' "$row" | awk '{print $4}')
mxc_file=$(printf '%s' "$row" | awk '{sub(".*/", "", $2); print $2}')
cat <<'CONSENT'
OMGS installation consent
Download the version pinned in skill/VERSION from the OMGS GitHub release:
https://github.com/OpenAdminOS/oh-my-god-security/releases/download/v<VERSION>
If OMGS_RELEASE_BASE is set, use that explicitly configured bundle instead.
Download the OMGS binary (at most 100 MiB), the unmodified Microsoft MXC 1.0.1
executor for this platform (at most 100 MiB), SHA256SUMS and the MXC MIT notice
(at most 1 MiB each). Intel Macs have no MXC executor and cannot run proofs.
Verify OMGS with SHA256SUMS and, on macOS or Windows, the pinned publisher
signature. Verify MXC with SHA256SUMS, the executor hash pinned in this skill,
and Microsoft's signature where the OS supports it. Linux has no native
publisher signature check. With authenticated gh, also check OMGS provenance;
failed or unavailable provenance is reported as unverified, not as tampering.
Install without elevation under OMGS_HOME, defaulting to ~/.local/share/omgs
(%USERPROFILE%\.local\share\omgs on Windows): bin/omgs and mxc/1.0.1/.
No target dependencies or toolchains will be downloaded. Show the installed
paths, versions and verification results afterwards.
Download and install these files? Type yes to consent:
CONSENT
printf 'Resolved: OMGS %s; source %s; destination %s; binary %s; executor %s\n' "$VERSION" "$BASE" "$DEST_ROOT" "$asset" "${mxc_asset:-unavailable}"
IFS= read -r answer || answer=''
[ "$answer" = yes ] || { echo 'Installation cancelled before downloads' >&2; exit 1; }
tmp=$(mktemp -d)
staged_omgs=''
staged_mxc=''
staged_license=''
cleanup() {
  for staged in "$staged_omgs" "$staged_mxc" "$staged_license"; do
    [ -z "$staged" ] || rm -f -- "$staged"
  done
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
fetch() {
  case "$BASE" in
    /*) cp "$BASE/$1" "$tmp/$1" ;;
    file://*) cp "${BASE#file://}/$1" "$tmp/$1" ;;
    https://*) curl --proto '=https' --proto-redir '=https' -fsSL --max-filesize "$2" "$BASE/$1" -o "$tmp/$1" ;;
    *) echo 'OMGS_RELEASE_BASE must be HTTPS or an absolute local bundle' >&2; exit 1 ;;
  esac
  [ "$(wc -c < "$tmp/$1")" -le "$2" ] || { echo "oversize download: $1" >&2; exit 1; }
}
digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}
checksum() {
  expected=$(awk -v a="$1" '$2 == a || $2 == "*" a {print $1}' "$tmp/SHA256SUMS")
  printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' || { echo "missing or invalid checksum: $1" >&2; exit 1; }
  [ "$(digest "${2:-$tmp/$1}")" = "$expected" ] || { echo "checksum mismatch: $1" >&2; exit 1; }
  echo "SHA256SUMS verified: $1"
}
verify_signature() {
  if [ "$os" = Darwin ]; then
    /usr/bin/codesign --verify --strict -R "=anchor apple generic and certificate leaf[subject.OU] = \"$2\"" "$1" || { echo "publisher signature rejected: $1" >&2; exit 1; }
    echo "Publisher signature verified: $2"
  else
    echo 'Publisher signature: unavailable on Linux'
  fi
}
fetch SHA256SUMS 1048576
fetch "$asset" 104857600
checksum "$asset"
verify_signature "$tmp/$asset" "$OMGS_TEAM_ID"
if [ -n "$mxc_asset" ]; then
  fetch "$mxc_asset" 104857600
  checksum "$mxc_asset"
  [ "$(digest "$tmp/$mxc_asset")" = "$mxc_hash" ] || { echo 'MXC pin mismatch' >&2; exit 1; }
  verify_signature "$tmp/$mxc_asset" "$MICROSOFT_TEAM_ID"
  fetch MXC-LICENSE.txt 1048576
  checksum MXC-LICENSE.txt
  echo "MXC 1.0.1 pin verified: $mxc_hash"
fi
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  if gh attestation verify "$tmp/$asset" --repo OpenAdminOS/oh-my-god-security; then
    echo 'OMGS provenance: verified'
  else
    echo 'OMGS provenance: unverified (verification failed; this alone is not evidence of tampering)' >&2
  fi
else
  echo 'OMGS provenance: unverified (authenticated gh unavailable)'
fi
chmod 0755 "$tmp/$asset"
if ! actual_version=$("$tmp/$asset" --version); then
  echo "version mismatch: skill expects omgs $VERSION; binary --version failed" >&2; exit 1
fi
[ "$actual_version" = "omgs $VERSION" ] || { echo "version mismatch: skill expects omgs $VERSION; binary reports $actual_version" >&2; exit 1; }
# Existing storage is inspected, never repaired. Check every replaceable parent.
# Outside HOME, a root-owned non-writable (or sticky) directory anchors the walk.
umask 077
storage_error() {
  echo "owner-private installation storage $1: $2; see README.md#storage-migration" >&2
  exit 1
}
check_storage() {
  [ ! -L "$1" ] && [ -d "$1" ] || storage_error "$1" 'storage must be a directory without links'
  if [ "$(uname -s)" = Darwin ]; then
    info=$(stat -f '%u %OLp' "$1")
  else
    info=$(stat -c '%u %a' "$1")
  fi
  owner=${info%% *}
  mode=${info#* }
  bits=$((0$mode))
  [ "$owner" = "$(id -u)" ] || [ "$2" = anchor -a "$owner" = 0 ] || storage_error "$1" 'storage must be owned by the current user'
  [ $((bits & 0022)) -eq 0 ] || [ $((bits & 01000)) -ne 0 ] || storage_error "$1" 'storage must not be group- or world-writable without the sticky bit'
}
check_ancestors() {
  current=$1
  while :; do
    if [ -e "$current" ] || [ -L "$current" ]; then
      case "$current/" in
        "$HOME/"*) check_storage "$current" ancestor ;;
        *) check_storage "$current" anchor ;;
      esac
      [ "$current" != "$HOME" ] || break
      # A custom root outside HOME can end at a non-replaceable system anchor.
      if [ "$owner" = 0 ] && [ "$(id -u)" != 0 ]; then
        check_storage "$current" anchor
        break
      fi
    fi
    [ "$current" != / ] || break
    current=$(dirname -- "$current")
  done
}
private_tree() (
  directory=$1
  if [ -e "$directory" ] || [ -L "$directory" ]; then
    check_storage "$directory" destination
  else
    parent=$(dirname -- "$directory")
    if [ ! -d "$parent" ]; then private_tree "$parent"; fi
    mkdir -m 0700 -- "$directory"
    # Remove inherited extended ACLs only on directories just created by us.
    if [ "$(uname -s)" = Darwin ]; then chmod -N "$directory"; fi
    chmod 0700 "$directory"
    check_storage "$directory" destination
  fi
)
check_ancestors "$DEST_ROOT/bin"
check_ancestors "$DEST_ROOT/mxc/1.0.1"

# Stage every file on its destination filesystem before publishing any file.
private_tree "$DEST_ROOT/bin"
staged_omgs=$(mktemp "$DEST_ROOT/bin/.omgs.XXXXXXXX")
install -m 0755 "$tmp/$asset" "$staged_omgs"
if [ -n "$mxc_asset" ]; then
  private_tree "$DEST_ROOT/mxc/1.0.1"
  staged_mxc=$(mktemp "$DEST_ROOT/mxc/1.0.1/.mxc.XXXXXXXX")
  install -m 0755 "$tmp/$mxc_asset" "$staged_mxc"
  staged_license=$(mktemp "$DEST_ROOT/mxc/1.0.1/.license.XXXXXXXX")
  install -m 0644 "$tmp/MXC-LICENSE.txt" "$staged_license"
fi
checksum "$asset" "$staged_omgs"
verify_signature "$staged_omgs" "$OMGS_TEAM_ID"
if [ -n "$mxc_asset" ]; then
  checksum "$mxc_asset" "$staged_mxc"
  verify_signature "$staged_mxc" "$MICROSOFT_TEAM_ID"
  checksum MXC-LICENSE.txt "$staged_license"
  mv -f -- "$staged_mxc" "$DEST_ROOT/mxc/1.0.1/$mxc_file"
  mv -f -- "$staged_license" "$DEST_ROOT/mxc/1.0.1/MXC-LICENSE.txt"
  echo "Installed MXC 1.0.1: $DEST_ROOT/mxc/1.0.1/$mxc_file"
fi
mv -f -- "$staged_omgs" "$DEST_ROOT/bin/omgs"
echo "Installed $actual_version: $DEST_ROOT/bin/omgs"
