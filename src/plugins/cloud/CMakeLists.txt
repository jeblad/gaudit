# SPDX-License-Identifier: GPL-3.0-only
# Cloud Services (core.cloud): file synchronisation clients and their
# folders, and what is known about each service. Everything runs as the
# user, and it only finds out. The finding itself is src/backend's
# cloud-folders.c.
#   common/        the line format between orchestrator and GUI
#   orchestrator/  the "cloud" mode
#   rules/         the report, in Guile (run by gaudit-engine), with the table
target_sources(gaudit_probe PRIVATE common/cloud-io.c)
target_include_directories(gaudit_probe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common
                                        PRIVATE ${PROJECT_SOURCE_DIR}/src/probe)
target_sources(gaudit-orchestrator PRIVATE orchestrator/cloud.c)
target_include_directories(gaudit-orchestrator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/orchestrator
                                                   ${PROJECT_SOURCE_DIR}/src/probe
                                                   ${PROJECT_SOURCE_DIR}/src/backend)
target_sources(gaudit PRIVATE plugin.c gaudit-cloud.c)
target_include_directories(gaudit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/src/backend)

# Its own text domain: the report.
gaudit_plugin_domain(gaudit-cloud ${CMAKE_CURRENT_SOURCE_DIR}/po)

set(GAUDIT_PLUGIN_ID core.cloud)
configure_file(rules/report.scm ${GAUDIT_BUILD_RULES_DIR}/${GAUDIT_PLUGIN_ID}/report.scm COPYONLY)
install(FILES rules/report.scm DESTINATION ${GAUDIT_INSTALL_RULES_DIR}/${GAUDIT_PLUGIN_ID})
