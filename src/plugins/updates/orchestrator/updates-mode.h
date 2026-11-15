/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "updates" mode: the Updates collection, as the user. */
#pragma once

#include <stdint.h>
#include <stdio.h>

#include "gaudit/backend.h"

/* Writes every fact the backend can give, then the closing line, to out.
 * expected: the backend the distribution implies (may be NULL). For tests
 * any backend will do. 0 on success. */
int gaudit_updates_collect(const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *expected,
                           int64_t now, FILE *out);

/* "quick" for now, the only level. 0 on success, 2 for another level. */
int gaudit_updates_mode(const char *level);
