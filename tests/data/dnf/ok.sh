#!/bin/sh
if [ "${1:-}" = list ]; then
    echo '(package (name "bzip2-libs") (arch "x86_64") (version "1.0.8-19.fc45") (group 0) (offered "1.0.8-18.fc45"))'
    echo '(package (name "python2.7") (arch "x86_64") (version "2.7.18-40.fc43") (group 1) (offered ""))'
    echo '(package (name "openh264") (arch "x86_64") (version "2.5.1-1.fc45") (group 2) (offered ""))'
    echo '(package (name "cuda-toolkit") (arch "x86_64") (version "1:13.0.2-1") (group 2) (offered ""))'
    echo '(end (count 4))'
    exit 0
fi
echo "(dnf (installed 1800) (upgradable 12) (extras 3) (above 1))"
