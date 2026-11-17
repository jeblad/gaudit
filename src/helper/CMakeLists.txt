# SPDX-License-Identifier: GPL-3.0-only
# Privileged helper, started via pkexec. Kept minimal: glibc, libcap and
# libseccomp, and libsodium for the manifest's signature. Not linked against
# gaudit_backend, which pulls in decompression and more.
pkg_check_modules(HELPER_DEPS REQUIRED IMPORTED_TARGET libcap libseccomp libsodium)

# The sandbox on its own, so it can be tested.
# Plugins add their checks (src/plugins/*/helper/).
add_library(gaudit_sandbox STATIC sandbox.c lease.c sha256.c conf-write.c manifest.c selfcheck.c
            ${PROJECT_SOURCE_DIR}/src/gui/gaudit-environ.c)
target_compile_definitions(gaudit_sandbox PRIVATE _GNU_SOURCE)
target_include_directories(gaudit_sandbox PUBLIC . PRIVATE ${PROJECT_SOURCE_DIR}/src/gui)

# gAudit's public keys for the manifest, built into the helper: every
# minisign public key file in data/keys/manifest/ (two during a change of
# keys). None yet: the self-check then says the build has no key.
file(GLOB _manifest_keys ${PROJECT_SOURCE_DIR}/data/keys/manifest/*.pub)
set(GAUDIT_MANIFEST_KEYS "")
foreach(_key ${_manifest_keys})
  file(READ ${_key} _text)
  string(REPLACE "\\" "\\\\" _text "${_text}")
  string(REPLACE "\"" "\\\"" _text "${_text}")
  string(REPLACE "\n" "\\n" _text "${_text}")
  string(APPEND GAUDIT_MANIFEST_KEYS "    \"${_text}\",\n")
endforeach()
configure_file(manifest-keys.h.in ${CMAKE_CURRENT_BINARY_DIR}/manifest-keys.h @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/data/keys/manifest)
target_link_libraries(gaudit_sandbox PUBLIC PkgConfig::HELPER_DEPS)

add_executable(gaudit-helper main.c)
target_compile_definitions(gaudit-helper PRIVATE _GNU_SOURCE PROJECT_BINARY_DIR="${PROJECT_BINARY_DIR}")
target_link_libraries(gaudit-helper PRIVATE gaudit_sandbox gaudit_config)
target_include_directories(gaudit-helper PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
install(TARGETS gaudit-helper RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
