# SPDX-License-Identifier: GPL-3.0-only
# Developer tools. Built in developer builds only and never installed.
add_executable(gaudit-probe-dump gaudit-probe-dump.c)
target_include_directories(gaudit-probe-dump PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/debian)
target_link_libraries(gaudit-probe-dump PRIVATE gaudit_probe)

add_executable(gaudit-secret-scan gaudit-secret-scan.c)
target_compile_definitions(gaudit-secret-scan PRIVATE _GNU_SOURCE)
target_include_directories(gaudit-secret-scan PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_link_libraries(gaudit-secret-scan PRIVATE gaudit_backend)
