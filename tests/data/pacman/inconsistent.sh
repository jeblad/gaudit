#!/bin/sh
if [ "${1:-}" = list ]; then
    echo '(package (name "a") (arch "any") (version "1-1") (group 0) (offered ""))'
    echo '(end (count 1))'
    exit 0
fi
echo "(pacman (installed 5) (upgradable 4) (foreign 4) (above 0))"
