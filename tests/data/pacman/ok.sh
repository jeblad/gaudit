#!/bin/sh
if [ "${1:-}" = list ]; then
    echo '(package (name "linux-firmware") (arch "any") (version "20260101.abc-1") (group 0) (offered "20251201.def-1"))'
    echo '(package (name "python2") (arch "x86_64") (version "2.7.18-12") (group 1) (offered ""))'
    echo '(package (name "yay") (arch "x86_64") (version "12.4.2-1") (group 2) (offered ""))'
    echo '(end (count 3))'
    exit 0
fi
echo "(pacman (installed 900) (upgradable 14) (foreign 6) (above 1))"
