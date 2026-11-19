/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "cloud" mode (see cloud.c), as the user:
 *
 *   cloud quick|full              the collection (the same at both levels for now)
 *   cloud plain <remote>          on a click only: how many files and folders
 *                                 the remote has outside its encrypted folder,
 *                                 asked of the service with rclone (network)
 *   cloud unit <service> <disk> <paired> <remote> <gathering> <lang>
 *                                 writes the systemd user unit that mounts it:
 *                                 disk private|shared, paired 1 when both
 *                                 disks are there, gathering a known
 *                                 gathering folder's name, lang the language
 *                                 of the disks' words (cloud-folders.h)
 *
 * The collection only finds out. The unit is written only on the user's
 * informed choice: the page shows the very text first (common/cloud.h). */
#pragma once

#include <stdio.h>

int gaudit_cloud_mode(int argc, char *argv[]);

/* The collection for home, written to out; for tests, the mount list and
 * a prefix for /usr/bin may be given (NULL for the usual ones). 0 on success. */
int gaudit_cloud_collect(const char *home, const char *mounts, const char *root, FILE *out);

/* The unit for service, disk and remote under home; result: written,
 * unchanged, foreign (another file of that name), refused, error. 0 when
 * in place. */
int gaudit_cloud_write_unit(const char *home, const char *service, const char *disk,
                            const char *paired, const char *remote, const char *gathering, const char *lang,
                            char *result, size_t len);

/* Looks at remote's top level outside its encrypted folder, with the
 * rclone program at rclone (NULL: /usr/bin/rclone), and writes one
 * (cloud-plain ...) line. Only a remote the collection finds, with an
 * encryption over it. 0 when the line was written. */
int gaudit_cloud_plain(const char *home, const char *mounts, const char *remote,
                       const char *rclone, FILE *out);
