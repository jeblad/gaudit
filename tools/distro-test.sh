#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
#
# Build and test gAudit on another distribution in a throwaway container,
# then remove everything again. Not part of ctest; run it on demand.
#
#   tools/distro-test.sh fedora|arch|opensuse|debian [--keep-image]
#
# Uses rootless podman. The source tree is mounted read-only; the build
# happens inside the container and disappears with it (--rm). The image is
# removed afterwards unless --keep-image is given, so nothing stays on disk.
# The container needs network access to install build dependencies.
set -eu

usage() {
    echo "usage: $0 fedora|arch|opensuse|debian [--keep-image]" >&2
    exit 2
}

[ $# -ge 1 ] || usage
distro=$1
keep_image=no
[ "${2:-}" = "--keep-image" ] && keep_image=yes

# Package names per distribution. They follow each distribution's naming
# and should be checked on the first run, when they have not been before.
case "$distro" in
    fedora)
        image=registry.fedoraproject.org/fedora:latest
        install='dnf -y install gcc gcc-c++ cmake pkgconf-pkg-config gettext desktop-file-utils
                 gtk4-devel libadwaita-devel flatpak-devel json-glib-devel libdnf5-devel util-linux'
        # Packages without a source: disable the updates repositories after
        # everything is installed, so versions that came from there are
        # offered by no enabled repository. The exact number does not matter;
        # it must match what dnf reports.
        # Repositories live in /usr/share/dnf5/repos.d (owned by the package);
        # dnf5 takes local changes from /etc/dnf/repos.override.d.
        prepare='mkdir -p /etc/dnf/repos.override.d
                 && printf "[updates]\\nenabled=0\\n" > /etc/dnf/repos.override.d/99-gaudit-test.repo
                 && echo "== prepared: updates disabled; enabled repositories now:"
                 && dnf -q repo list | sed 1d'
        # dnf's own view, for comparison with the collector (test only; the
        # product never parses tool output).
        compare='echo "== dnf: upgradable / extras (as root, cache only)"
                 dnf -q --cacheonly check-upgrade | grep -c "\." || true
                 dnf -q --cacheonly list --extras | grep -c "\." || true'
        ;;
    arch)
        image=docker.io/library/archlinux:latest
        install='pacman -Syu --noconfirm base-devel cmake gettext desktop-file-utils
                 gtk4 libadwaita flatpak json-glib'
        ;;
    opensuse)
        image=registry.opensuse.org/opensuse/tumbleweed:latest
        install='zypper --non-interactive install gcc gcc-c++ cmake pkgconf gettext-tools
                 desktop-file-utils gtk4-devel libadwaita-devel flatpak-devel json-glib-devel util-linux'
        ;;
    debian)
        image=docker.io/library/debian:stable
        install='apt-get update && apt-get -y install build-essential cmake pkg-config gettext
                 desktop-file-utils libgtk-4-dev libadwaita-1-dev libflatpak-dev libjson-glib-dev'
        ;;
    *)
        usage
        ;;
esac

compare=${compare:-true}
prepare=${prepare:-true}

# The package lists above are wrapped for reading; a newline would end the
# command in the container's shell, so make each one a single line.
install=$(printf '%s' "$install" | tr '\n' ' ')
prepare=$(printf '%s' "$prepare" | tr '\n' ' ')

command -v podman >/dev/null || { echo "podman is not installed" >&2; exit 1; }

src=$(cd "$(dirname "$0")/.." && pwd)

echo "== $distro: $image"
status=0
podman run --rm --pull=newer \
    --volume "$src:/src:ro,Z" \
    "$image" \
    sh -euc "
        $install
        cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Debug -DGAUDIT_DEVELOPER_BUILD=ON
        cmake --build /build -j 4
        ctest --test-dir /build --output-on-failure -j 2
        $prepare
        echo '== gaudit-probe-dump (root)'
        /build/tools/gaudit-probe-dump || true
        # Status probes are meant to run without privileges.
        echo '== gaudit-probe-dump (nobody)'
        runuser -u nobody -- /build/tools/gaudit-probe-dump || true
        for c in /build/src/collectors/*/gaudit-*-probe; do
            [ -x \"\$c\" ] || continue
            echo \"== \$c (nobody)\"
            runuser -u nobody -- \"\$c\" || echo \"exit \$?\"
        done
        $compare
    " || status=$?

if [ "$keep_image" = no ]; then
    podman rmi "$image" >/dev/null 2>&1 || true
    echo "== removed image $image"
fi

[ "$status" -eq 0 ] && echo "== $distro: OK" || echo "== $distro: FAILED ($status)"
exit "$status"
