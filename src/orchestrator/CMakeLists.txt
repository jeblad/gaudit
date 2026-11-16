# SPDX-License-Identifier: GPL-3.0-only
add_executable(gaudit-orchestrator main.c report.c)
target_compile_definitions(gaudit-orchestrator PRIVATE _GNU_SOURCE)
target_include_directories(gaudit-orchestrator PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_link_libraries(gaudit-orchestrator PRIVATE gaudit_probe gaudit_config gaudit_sandbox)
install(TARGETS gaudit-orchestrator RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/gaudit)
