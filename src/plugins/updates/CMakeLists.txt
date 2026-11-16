# SPDX-License-Identifier: GPL-3.0-only
# Updates (core.updates), after the Private Files pattern:
#   common/        the collection's line format, parsed strictly
#   orchestrator/  the "updates" mode: facts, as the user
#   rules/         the report, in Guile (run by gaudit-engine)
#   helper/        package integrity (the Thorough report) and the
#                  automatic-updates drop-in, as root
target_sources(gaudit_probe PRIVATE common/updates-io.c)
target_include_directories(gaudit_probe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common
                                        PRIVATE ${PROJECT_SOURCE_DIR}/src/probe)
target_sources(gaudit-orchestrator PRIVATE orchestrator/updates.c common/apt-ops.c common/vendor.c)
target_include_directories(gaudit-orchestrator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/orchestrator)
target_sources(gaudit PRIVATE plugin.c gaudit-updates.c common/apt-ops.c common/vendor.c)
target_include_directories(gaudit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Its own text domain: the report and the fix pages.
gaudit_plugin_domain(gaudit-updates ${CMAKE_CURRENT_SOURCE_DIR}/po)
target_sources(gaudit_sandbox PRIVATE helper/md5.c helper/integrity.c helper/automatic.c helper/apt.c
                                     helper/sha1.c helper/vendor-pkg.c
                                     common/apt-ops.c common/vendor.c)
target_include_directories(gaudit_sandbox PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/helper
                                          ${CMAKE_CURRENT_SOURCE_DIR}/common)

set(GAUDIT_PLUGIN_ID core.updates)
configure_file(rules/report.scm ${GAUDIT_BUILD_RULES_DIR}/${GAUDIT_PLUGIN_ID}/report.scm COPYONLY)
install(FILES rules/report.scm DESTINATION ${GAUDIT_INSTALL_RULES_DIR}/${GAUDIT_PLUGIN_ID})

# Vendors' signing keys (common/vendor.c names them): armored here, so they
# can be read; binary in the build, as gpgv wants them.
find_program(GPG_PROGRAM gpg REQUIRED)
set(GAUDIT_VENDOR_KEYS zoom)
set(_vendor_key_outputs)
foreach(key ${GAUDIT_VENDOR_KEYS})
  set(_out ${GAUDIT_BUILD_VENDOR_KEYS_DIR}/${key}.gpg)
  add_custom_command(OUTPUT ${_out}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${GAUDIT_BUILD_VENDOR_KEYS_DIR}
    COMMAND ${GPG_PROGRAM} --batch --yes --no-options --dearmor --output ${_out}
            ${CMAKE_CURRENT_SOURCE_DIR}/keys/${key}.asc
    # Never writable by others: the helper refuses a key file that is.
    COMMAND chmod 0644 ${_out}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/keys/${key}.asc
    COMMENT "Vendor key ${key}"
    VERBATIM)
  list(APPEND _vendor_key_outputs ${_out})
endforeach()
add_custom_target(vendor-keys ALL DEPENDS ${_vendor_key_outputs})
install(FILES ${_vendor_key_outputs} DESTINATION ${GAUDIT_INSTALL_VENDOR_KEYS_DIR})
