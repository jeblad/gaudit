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
target_sources(gaudit-orchestrator PRIVATE orchestrator/updates.c)
target_include_directories(gaudit-orchestrator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/orchestrator)
target_sources(gaudit PRIVATE plugin.c gaudit-updates.c)
target_include_directories(gaudit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Its own text domain: the report and the fix pages.
gaudit_plugin_domain(gaudit-updates ${CMAKE_CURRENT_SOURCE_DIR}/po)
target_sources(gaudit_sandbox PRIVATE helper/md5.c helper/integrity.c helper/automatic.c)
target_include_directories(gaudit_sandbox PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/helper)

set(GAUDIT_PLUGIN_ID core.updates)
configure_file(rules/report.scm ${GAUDIT_BUILD_RULES_DIR}/${GAUDIT_PLUGIN_ID}/report.scm COPYONLY)
install(FILES rules/report.scm DESTINATION ${GAUDIT_INSTALL_RULES_DIR}/${GAUDIT_PLUGIN_ID})
