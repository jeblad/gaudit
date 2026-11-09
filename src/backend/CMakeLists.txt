# SPDX-License-Identifier: GPL-3.0-only
# Distro backends behind a thin interface. Only Ubuntu is implemented.
add_library(gaudit_backend STATIC
  capability.c
  ubuntu/pkg-ubuntu.c
  ubuntu/apt-conf.c
  ubuntu/dpkg.c
)
target_compile_definitions(gaudit_backend PRIVATE _GNU_SOURCE)
target_include_directories(gaudit_backend PUBLIC include)
