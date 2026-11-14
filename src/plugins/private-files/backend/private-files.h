/* SPDX-License-Identifier: GPL-3.0-only */
/* Private files and folders in the home directory that others could read or
 * change. Only known locations (fast enough for Home); a deep search for
 * stray private keys elsewhere belongs in a plugin. Backend internal;
 * exposed for tests. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

/* Checks the known locations under home for owner uid. Two kinds of rule:
 * ~/.ssh and ~/.gnupg must have the modes ssh and gpg themselves insist
 * on; other secrets must not be readable by anyone else through the
 * folders on the way, where own_gid (the user's private group, or
 * (gid_t)-1 for none) counts as the owner. Returns the number of problems
 * and copies the first one, relative to home and starting with "~/", into
 * first. Missing locations are fine. -1 if home itself cannot be
 * examined. */
int gaudit_private_files_check(const char *home, uid_t uid, gid_t own_gid,
                               char *first, size_t first_len);

/* Which rule a problem broke. */
typedef enum {
    GAUDIT_PRIVATE_HOME_WRITABLE = 0,  /* the home directory is writable by others */
    GAUDIT_PRIVATE_TOOL_MODE,          /* ~/.ssh or ~/.gnupg: a mode the tool refuses */
    GAUDIT_PRIVATE_REACH,              /* a known secret others can reach */
} gaudit_private_rule;

/* rel is relative to home, without "~/" ("" for home itself). */
typedef void (*gaudit_private_fn)(const char *rel, gaudit_private_rule rule, void *ctx);

/* The same check, calling fn for every problem: the one collection that
 * Home's count and the plugin's full list both come from. Returns the
 * number of problems, or -1 as above. */
int gaudit_private_files_each(const char *home, uid_t uid, gid_t own_gid,
                              gaudit_private_fn fn, void *ctx);
