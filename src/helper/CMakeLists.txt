# SPDX-License-Identifier: GPL-3.0-only
# Privileged helper, started via pkexec. Kept minimal: glibc, libcap and
# libseccomp (libsodium comes with the manifest). Not linked against
# gaudit_backend, which pulls in decompression and more.
pkg_check_modules(HELPER_DEPS REQUIRED IMPORTED_TARGET libcap libseccomp)

# The sandbox on its own, so it can be tested.
add_library(gaudit_sandbox STATIC sandbox.c nft.c lease.c)
target_compile_definitions(gaudit_sandbox PRIVATE _GNU_SOURCE)
target_include_directories(gaudit_sandbox PUBLIC .)
target_link_libraries(gaudit_sandbox PUBLIC PkgConfig::HELPER_DEPS)

add_executable(gaudit-helper main.c)
target_compile_definitions(gaudit-helper PRIVATE _GNU_SOURCE)
target_link_libraries(gaudit-helper PRIVATE gaudit_sandbox gaudit_config)
install(TARGETS gaudit-helper RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
