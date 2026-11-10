#!/bin/sh
if [ "${1:-}" = list ]; then
    echo '(package (name "a") (arch "noarch") (version "1-1") (group 2) (offered ""))'
    echo '(end (count 2))'
    exit 0
fi
echo "(dnf (installed 1) (upgradable 2) (extras 0) (above 0))"
