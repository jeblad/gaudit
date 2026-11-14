# SPDX-License-Identifier: GPL-3.0-only
# Updates (core.updates): its full run checks package integrity in the
# helper. The update status rows on Home come from the distro backends.
target_sources(gaudit PRIVATE plugin.c)
target_sources(gaudit_sandbox PRIVATE helper/md5.c helper/integrity.c)
target_include_directories(gaudit_sandbox PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/helper)
