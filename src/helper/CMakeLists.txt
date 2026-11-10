# SPDX-License-Identifier: GPL-3.0-only
# Privileged helper, started via pkexec. Kept minimal: glibc + libsodium only
# (libsodium/libcap/libseccomp are added when the code needs them).
add_executable(gaudit-helper main.c)
target_compile_definitions(gaudit-helper PRIVATE _GNU_SOURCE)
# Not linked against gaudit_backend: that pulls in decompression and more.
target_link_libraries(gaudit-helper PRIVATE gaudit_config)
install(TARGETS gaudit-helper RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
