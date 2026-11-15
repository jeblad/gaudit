/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "fix" mode for Private Files (see fix.c). */
#pragma once

/* 0: fixed, "(fixed (mode M))" written; 1: not fixed; 2: bad request. rel
 * is NULL for close-home (root is then the home folder). */
int gaudit_private_files_fix(const char *fix_id, const char *root, const char *rel);
