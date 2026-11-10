# SPDX-License-Identifier: GPL-3.0-only
# Status probes for Home: cheap, read-only, no elevated privileges.
# Plain C without GTK, so it can move into the orchestrator later.
add_library(gaudit_probe STATIC probe.c probe-io.c run-io.c)
target_include_directories(gaudit_probe PUBLIC include PRIVATE ${PROJECT_SOURCE_DIR}/src/backend)
target_link_libraries(gaudit_probe PUBLIC gaudit_backend gaudit_model)
