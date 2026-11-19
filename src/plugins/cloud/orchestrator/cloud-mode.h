/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "cloud" mode (see cloud.c), as the user:
 *
 *   cloud quick|full              the collection (the same at both levels for now)
 *   cloud unit <service> <remote>  writes the systemd user unit that mounts it
 *
 * The collection only finds out. The unit is written only on the user's
 * informed choice: the page shows the very text first (common/cloud.h). */
#pragma once

#include <stdio.h>

int gaudit_cloud_mode(int argc, char *argv[]);

/* The collection for home, written to out; for tests, the mount list and
 * a prefix for /usr/bin may be given (NULL for the usual ones). 0 on success. */
int gaudit_cloud_collect(const char *home, const char *mounts, const char *root, FILE *out);

/* The unit for service and remote under home; result: written, unchanged,
 * foreign (another file of that name), refused, error. 0 when in place. */
int gaudit_cloud_write_unit(const char *home, const char *service, const char *remote,
                            char *result, size_t len);
