#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Every icon name used in the code has its SVG bundled in data/icons and
# listed in data/gaudit.gresource.xml, so no icon is ever missing.
# Usage: check-icons.sh <source dir>
set -u
src=$1
status=0
names=$(grep -rhoE '"[a-z0-9-]+-symbolic"' "$src/src" | tr -d '"' | sort -u)
for n in $names; do
    if [ ! -f "$src/data/icons/scalable/actions/$n.svg" ]; then
        echo "missing SVG: data/icons/scalable/actions/$n.svg" >&2
        status=1
    fi
    if ! grep -q "alias=\"$n.svg\"" "$src/data/gaudit.gresource.xml"; then
        echo "not in data/gaudit.gresource.xml: $n.svg" >&2
        status=1
    fi
done
exit $status
