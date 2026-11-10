# SPDX-License-Identifier: GPL-3.0-only
# pacman collector: the only part of gAudit linked against libalpm.
# Optional at build time; normally only found on Arch and derivatives.
pkg_check_modules(LIBALPM IMPORTED_TARGET libalpm)
if(LIBALPM_FOUND)
  add_executable(gaudit-pacman-probe
    gaudit-pacman-probe.c
    ${PROJECT_SOURCE_DIR}/src/backend/arch/pacman-files.c)
  target_compile_definitions(gaudit-pacman-probe PRIVATE _GNU_SOURCE)
  target_include_directories(gaudit-pacman-probe PRIVATE
    ${PROJECT_SOURCE_DIR}/src/backend/arch ${PROJECT_SOURCE_DIR}/src/backend/include)
  target_link_libraries(gaudit-pacman-probe PRIVATE PkgConfig::LIBALPM)
  install(TARGETS gaudit-pacman-probe RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
  message(STATUS "pacman collector: enabled")
else()
  message(STATUS "pacman collector: disabled (libalpm not found)")
endif()
