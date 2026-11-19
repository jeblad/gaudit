/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "cloud" mode (see cloud.c), as the user:
 *
 *   cloud quick|full     the collection (the same at both levels for now)
 *
 * It only finds out; it never moves, writes or runs anything. */
#pragma once

#include <stdio.h>

int gaudit_cloud_mode(int argc, char *argv[]);

/* The collection for home, written to out; for tests, the mount list and
 * a prefix for /usr/bin may be given (NULL for the usual ones). 0 on success. */
int gaudit_cloud_collect(const char *home, const char *mounts, const char *root, FILE *out);
