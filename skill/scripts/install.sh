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
OMGS_TEAM_ID='D259ULY2B4'
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
umask 077
# Never execute from ambient TMPDIR. Resolve the home alias once, then admit
# its entire physical chain before creating or verifying executable content.
staging_error() { echo "Unsafe staging ancestor: $1" >&2; exit 1; }
admit_staging() {
  entry=$1
  while :; do
    [ -d "$entry" ] && [ ! -L "$entry" ] || staging_error "$entry"
    if [ "$(uname -s)" = Darwin ]; then
      owner=$(stat -f %u "$entry"); mode=$(stat -f %Op "$entry")
      # Reject mutation grants to any principal except this user or root.
      acl=$(LC_ALL=C ls -led "$entry") || staging_error "$entry"
      if printf '%s\n' "$acl" | awk -v u="$(id -un)" '
        / allow / && $2 != "user:" u && $2 != "user:root" {
          sub(/^.* allow /, "")
          if ($0 ~ /(^|,)(write[^,]*|delete[^,]*|add_file|add_subdirectory|append|chown)(,|$)/) bad=1
        } END {exit !bad}'; then staging_error "$entry"; fi
    else
      owner=$(stat -c %u "$entry"); mode=$(stat -c %a "$entry")
    fi
    [ "$owner" = "$(id -u)" ] || [ "$owner" = 0 ] || staging_error "$entry"
    [ $((0$mode & 0022)) -eq 0 ] || [ $((0$mode & 01000)) -ne 0 ] || staging_error "$entry"
    [ "$entry" != / ] || break
    entry=$(dirname "$entry")
  done
}
staging_parent=$(CDPATH='' cd -- "$HOME" && pwd -P)
admit_staging "$staging_parent"
tmp=$(mktemp -d "$staging_parent/.omgs-bootstrap.XXXXXXXX")
# Clear inherited ACLs only on this exclusively created disposable directory.
if [ "$(uname -s)" = Darwin ]; then chmod -N "$tmp"; fi
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
admit_staging "$tmp"
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
binary_hash=$expected
verify_signature "$tmp/$asset" "$OMGS_TEAM_ID"
if [ -n "$mxc_asset" ]; then
  fetch "$mxc_asset" 104857600
  checksum "$mxc_asset"
  executor_hash=$expected
  [ "$(digest "$tmp/$mxc_asset")" = "$mxc_hash" ] || { echo 'MXC pin mismatch' >&2; exit 1; }
  verify_signature "$tmp/$mxc_asset" "$MICROSOFT_TEAM_ID"
  fetch MXC-LICENSE.txt 1048576
  checksum MXC-LICENSE.txt
  license_hash=$expected
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
admit_staging "$tmp"
[ "$(digest "$tmp/$asset")" = "$binary_hash" ] || { echo 'checksum mismatch before execution' >&2; exit 1; }
chmod 0755 "$tmp/$asset"
if ! actual_version=$("$tmp/$asset" --version); then
  echo "version mismatch: skill expects omgs $VERSION; binary --version failed" >&2; exit 1
fi
[ "$actual_version" = "omgs $VERSION" ] || { echo "version mismatch: skill expects omgs $VERSION; binary reports $actual_version" >&2; exit 1; }
# The verified executable owns admission and exact-path publication.
if [ -n "$mxc_asset" ]; then
  "$tmp/$asset" install-self --to "$DEST_ROOT" --staging "$tmp" --binary "$asset" --binary-sha256 "$binary_hash" --mxc "$mxc_asset" --mxc-sha256 "$executor_hash" --license MXC-LICENSE.txt --license-sha256 "$license_hash"
else
  "$tmp/$asset" install-self --to "$DEST_ROOT" --staging "$tmp" --binary "$asset" --binary-sha256 "$binary_hash"
fi
