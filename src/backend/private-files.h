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
