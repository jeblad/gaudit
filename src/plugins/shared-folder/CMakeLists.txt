# SPDX-License-Identifier: GPL-3.0-only
# Shared Folder (core.shared-folder): the folder for sharing on the local
# network, folders that look like it, and what shares folders. Everything
# runs as the user. The finding itself is the shared known-folders code in
# src/backend (public-share.c).
#   common/        the line format between orchestrator and GUI
#   orchestrator/  the "shared" mode
#   rules/         the report, in Guile (run by gaudit-engine)
target_sources(gaudit_probe PRIVATE common/shared-folder-io.c)
target_include_directories(gaudit_probe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common
                                        PRIVATE ${PROJECT_SOURCE_DIR}/src/probe)
target_sources(gaudit-orchestrator PRIVATE orchestrator/shared.c)
target_include_directories(gaudit-orchestrator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/orchestrator
                                                   ${PROJECT_SOURCE_DIR}/src/probe
                                                   ${PROJECT_SOURCE_DIR}/src/backend
                                                   ${PROJECT_SOURCE_DIR}/src/plugins/private-files/backend)
target_sources(gaudit PRIVATE plugin.c gaudit-shared-folder.c)
target_include_directories(gaudit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Its own text domain: the report and the fix page.
gaudit_plugin_domain(gaudit-shared-folder ${CMAKE_CURRENT_SOURCE_DIR}/po)

set(GAUDIT_PLUGIN_ID core.shared-folder)
configure_file(rules/report.scm ${GAUDIT_BUILD_RULES_DIR}/${GAUDIT_PLUGIN_ID}/report.scm COPYONLY)
install(FILES rules/report.scm DESTINATION ${GAUDIT_INSTALL_RULES_DIR}/${GAUDIT_PLUGIN_ID})
