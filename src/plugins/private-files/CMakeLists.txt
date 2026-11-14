# SPDX-License-Identifier: GPL-3.0-only
# Private Files (core.private-files): the known locations for Home, and the
# deep scan of the home directory. Everything runs as the user.
#   backend/       the scans themselves
#   common/        the line format between orchestrator and GUI
#   orchestrator/  the "secrets" mode
target_sources(gaudit_backend PRIVATE backend/private-files.c backend/secret-scan.c)
target_include_directories(gaudit_backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/backend)
target_sources(gaudit_probe PRIVATE common/secrets-io.c)
target_include_directories(gaudit_probe PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common
                                        PRIVATE ${PROJECT_SOURCE_DIR}/src/probe)
target_sources(gaudit-orchestrator PRIVATE orchestrator/secrets.c)
target_include_directories(gaudit-orchestrator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/orchestrator)
target_sources(gaudit PRIVATE plugin.c gaudit-secrets-page.c)
target_include_directories(gaudit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
