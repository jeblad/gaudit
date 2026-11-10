/* SPDX-License-Identifier: GPL-3.0-only */
/* What the Arch backend reads directly from files. Backend internal;
 * exposed in a private header for tests. root is a path prefix ("" for this
 * machine). */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "gaudit/backend.h"

/* 1 if /var/lib/pacman/local holds package entries and /usr/bin/pacman is
 * executable. */
int gaudit_arch_present(const char *root);

/* Newest mtime of <sync_dir>/<repo>.db: when the package databases were
 * last refreshed. UNAVAILABLE when there are none. */
gaudit_backend_status gaudit_pacman_sync_time(const char *sync_dir, int64_t *out_epoch);

/* Repository section names from pacman.conf (every [section] except
 * [options]), written to names as a NUL-separated list ending in an empty
 * string, and IgnorePkg entries from [options] the same way. Include
 * directives are not followed: only the section names are needed. */
gaudit_backend_status gaudit_pacman_conf(const char *path,
                                         char *repos, size_t repos_len,
                                         char *ignore, size_t ignore_len);
