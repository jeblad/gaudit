# SPDX-License-Identifier: GPL-3.0-only
# Rule engine: Guile in a sandbox, no privileges, data in over a pipe.
# guile-3.0 is linked once the engine is implemented.
add_executable(gaudit-engine main.c)
target_link_libraries(gaudit-engine PRIVATE gaudit_config)
install(TARGETS gaudit-engine RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
