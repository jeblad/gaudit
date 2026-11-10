# SPDX-License-Identifier: GPL-3.0-only
# Distro backends behind a thin interface: Debian family, and a generic
# fallback for everything else.
add_library(gaudit_backend STATIC
  capability.c
  os-release.c
  package-systems.c
  collector.c
  flatpak-runner.c
  snap-runner.c
  debian/pkg-debian.c
  debian/apt-conf.c
  debian/dpkg.c
  generic/pkg-generic.c
)
target_compile_definitions(gaudit_backend PRIVATE _GNU_SOURCE)
target_include_directories(gaudit_backend PUBLIC include PRIVATE .)
target_link_libraries(gaudit_backend PRIVATE gaudit_config)
