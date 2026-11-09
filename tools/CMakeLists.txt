# SPDX-License-Identifier: GPL-3.0-only
# Developer tools. Built in developer builds only and never installed.
add_executable(gaudit-probe-dump gaudit-probe-dump.c)
target_include_directories(gaudit-probe-dump PRIVATE ${PROJECT_SOURCE_DIR}/src/backend/ubuntu)
target_link_libraries(gaudit-probe-dump PRIVATE gaudit_probe)
