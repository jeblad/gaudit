# SPDX-License-Identifier: GPL-3.0-only
# dnf collector: the only part of gAudit linked against libdnf5 (C++ API).
# Optional at build time; normally only found on Fedora.
pkg_check_modules(LIBDNF5 IMPORTED_TARGET libdnf5)
if(LIBDNF5_FOUND)
  add_executable(gaudit-dnf-probe gaudit-dnf-probe.cpp)
  target_link_libraries(gaudit-dnf-probe PRIVATE PkgConfig::LIBDNF5)
  install(TARGETS gaudit-dnf-probe RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
  message(STATUS "dnf collector: enabled")
else()
  message(STATUS "dnf collector: disabled (libdnf5 not found)")
endif()
