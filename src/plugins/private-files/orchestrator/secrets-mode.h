/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "secrets" mode (see secrets.c). */
#pragma once

#include <pwd.h>
#include <stdio.h>

/* The collection for pw's home directory and uid, written to out (for
 * tests: any home): the known locations, and with deep also the scan of
 * the whole home. 0 on success. */
int gaudit_private_files_collect(const struct passwd *pw, int deep, FILE *out);

/* Writes the findings and the summary on stdout; level "quick" or "full".
 * 0 on success, 2 for another level. */
int gaudit_private_files_secrets(const char *level);
