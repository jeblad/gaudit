# SPDX-License-Identifier: GPL-3.0-only
# Flatpak collector: the only part of gAudit linked against libflatpak.
# Optional at build time; without it the Flatpak row is simply not shown.
pkg_check_modules(FLATPAK IMPORTED_TARGET flatpak)
if(FLATPAK_FOUND)
  add_executable(gaudit-flatpak-probe gaudit-flatpak-probe.c)
  target_compile_definitions(gaudit-flatpak-probe PRIVATE _GNU_SOURCE)
  target_link_libraries(gaudit-flatpak-probe PRIVATE PkgConfig::FLATPAK)
  install(TARGETS gaudit-flatpak-probe RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
  message(STATUS "Flatpak collector: enabled")
else()
  message(STATUS "Flatpak collector: disabled (libflatpak-dev not found)")
endif()
