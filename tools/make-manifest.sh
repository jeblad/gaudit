#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Makes and signs gAudit's manifest for an install tree, at release time.
#
#   tools/make-manifest.sh <destdir> <prefix> <version> <days valid> <secret key>
#
# <destdir> is where `cmake --install build/release --prefix <prefix>` put
# the files, with DESTDIR=<destdir>. Every file of gAudit's own is listed
# with its SHA-256, size and installed path (without <destdir>): the GUI,
# everything in libexec/gaudit and share/gaudit, and gAudit's translations.
# The manifest goes to <destdir><prefix>/share/gaudit/manifest, signed next
# to it (manifest.minisig) with minisign and the secret key, kept offline.
# <version> must be higher than the last release's: the helper refuses an
# older one once it has seen a newer.
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 <destdir> <prefix> <version> <days valid> <secret key>" >&2
    exit 2
fi
destdir=$1
prefix=$2
version=$3
days=$4
key=$5

case "$version" in *[!0-9]*|'') echo "version: a whole number" >&2; exit 2 ;; esac
case "$days" in *[!0-9]*|'') echo "days: a whole number" >&2; exit 2 ;; esac
case "$prefix" in /*) ;; *) echo "prefix: an absolute path" >&2; exit 2 ;; esac
command -v minisign >/dev/null || { echo "minisign is not installed" >&2; exit 1; }

root=$destdir$prefix
out=$root/share/gaudit/manifest
signed=$(date -u +%s)
expires=$((signed + days * 86400))

list() {
    [ -e "$root/bin/gaudit" ] && echo "$root/bin/gaudit"
    for d in "$root/libexec/gaudit" "$root/share/gaudit"; do
        [ -d "$d" ] && find "$d" -type f ! -path "$out" ! -path "$out.minisig"
    done
    [ -d "$root/share/locale" ] && find "$root/share/locale" -type f -name 'gaudit*.mo'
    true
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
{
    echo "gaudit-manifest 1"
    echo "version $version"
    echo "signed $signed"
    echo "expires $expires"
    list | LC_ALL=C sort | while IFS= read -r file; do
        case "$file" in *[[:space:]]*) echo "a path with a space: $file" >&2; exit 1 ;; esac
        hash=$(sha256sum "$file" | cut -d' ' -f1)
        size=$(stat -c %s "$file")
        echo "file $hash $size ${file#"$destdir"}"
    done
} > "$tmp"
mkdir -p "$(dirname "$out")"
cp "$tmp" "$out"
minisign -S -s "$key" -m "$out" -x "$out.minisig" -t "gaudit manifest $version, signed $signed"
echo "$(($(wc -l < "$out") - 4)) files in $out"
