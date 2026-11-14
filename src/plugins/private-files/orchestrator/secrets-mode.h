/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "secrets" mode (see secrets.c). */
#pragma once

#include <pwd.h>
#include <stddef.h>
#include <stdio.h>

/* The collection for pw's home directory and uid, written to out (for
 * tests: any home): the known locations, and with deep also the scan of
 * the whole home and of each of folders (absolute; at most
 * GAUDIT_SECRETS_MAX_AREAS - 1 are searched). 0 on success. */
int gaudit_private_files_collect(const struct passwd *pw, int deep, const char *const *folders,
                                 size_t n_folders, FILE *out);

/* Writes the findings and the summary on stdout; level "quick" or "full".
 * 0 on success, 2 for another level. */
int gaudit_private_files_secrets(const char *level, const char *const *folders, size_t n_folders);
