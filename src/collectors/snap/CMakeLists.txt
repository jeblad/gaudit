# SPDX-License-Identifier: GPL-3.0-only
# Snap collector: talks to snapd's local REST API. The only part of gAudit
# linked against json-glib. Optional at build time.
pkg_check_modules(SNAP_DEPS IMPORTED_TARGET gio-unix-2.0 json-glib-1.0)
if(SNAP_DEPS_FOUND)
  add_executable(gaudit-snap-probe gaudit-snap-probe.c)
  target_link_libraries(gaudit-snap-probe PRIVATE PkgConfig::SNAP_DEPS)
  install(TARGETS gaudit-snap-probe RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
  message(STATUS "Snap collector: enabled")
else()
  message(STATUS "Snap collector: disabled (json-glib or gio-unix not found)")
endif()
