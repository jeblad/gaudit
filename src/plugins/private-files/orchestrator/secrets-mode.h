/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "secrets" mode (see secrets.c). */
#pragma once

#include <pwd.h>
#include <stdio.h>

/* The full collection for pw's home directory and uid, written to out
 * (for tests: any home). 0 on success. */
int gaudit_private_files_collect(const struct passwd *pw, FILE *out);

/* Writes the findings and the summary on stdout. 0 on success. */
int gaudit_private_files_secrets(void);
