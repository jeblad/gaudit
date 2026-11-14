# SPDX-License-Identifier: GPL-3.0-only
# Rule engine: Guile in a sandbox, no privileges, data in over a pipe.
pkg_check_modules(GUILE REQUIRED IMPORTED_TARGET GLOBAL guile-3.0)
add_executable(gaudit-engine main.c confine.c)
target_compile_definitions(gaudit-engine PRIVATE _GNU_SOURCE)
target_link_libraries(gaudit-engine PRIVATE PkgConfig::GUILE gaudit_sandbox gaudit_config)
install(TARGETS gaudit-engine RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
