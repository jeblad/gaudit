/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "shared" mode (see shared.c), as the user:
 *
 *   shared quick|full            the collection (the same at both levels for now)
 *   shared check <from> <to>     what merging would do, changing nothing
 *   shared merge <from> <to>     the merge, only when nothing stands in the way
 *   shared remove <name>         a folder, only when empty
 *
 * <from>, <to> and <name> are plain names of folders straight in the home
 * folder. The tidying is refused while a service shares either folder. */
#pragma once

#include <stdio.h>

int gaudit_shared_mode(int argc, char *argv[]);

/* The collection for home and uid, written to out; for tests, the places
 * to read may be given (NULL for the usual ones). Both levels search the
 * folder for sharing and the folders that look like it for secrets; full
 * also every other folder a service shares. 0 on success. */
int gaudit_shared_collect(const char *home, unsigned uid, const char *const *locale_dirs,
                          const char *smb_conf, const char *proc, int full, FILE *out);
