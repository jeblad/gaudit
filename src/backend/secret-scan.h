/* SPDX-License-Identifier: GPL-3.0-only */
/* A search through a home directory for files that look like secrets
 * (private keys, password databases, stored credentials), wherever they
 * are. Slow compared with the known locations on Home; meant for the deep
 * scan and for finding out which locations Home should know about.
 *
 * Never follows symlinks, never leaves the home directory's filesystem,
 * never reads more than the start of small regular files, and never
 * reports any content: only path, mode and why it looks secret.
 * Backend internal; exposed for tests and tools. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

/* Who besides the owner can read the file, taking every folder on the way
 * from the home directory into account (a 0644 file in a 0700 folder is
 * out of reach). */
typedef enum {
    GAUDIT_REACH_OWNER = 0,  /* owner only */
    GAUDIT_REACH_GROUP = 1,  /* members of the groups on the way */
    GAUDIT_REACH_OTHERS = 2, /* every account on the machine */
} gaudit_reach;

typedef struct {
    const char *rel;     /* relative to home, no leading "~/" */
    const char *reason;  /* stable id, e.g. "pem-private-key", "keepass" */
    mode_t mode;
    int owned;           /* owned by the expected uid */
    gid_t gid;           /* the file's group, for judging GAUDIT_REACH_GROUP */
    gaudit_reach reach;
} gaudit_secret_hit;

typedef struct {
    unsigned dirs;
    unsigned files;
    unsigned read;       /* files whose start was read */
    unsigned skipped;    /* folders left out (noise, other filesystems, depth) */
    int truncated;       /* stopped at the entry limit */
} gaudit_secret_stats;

typedef void (*gaudit_secret_fn)(const gaudit_secret_hit *hit, void *ctx);

/* Walks home (absolute) for owner uid and calls fn for each hit. Returns 0,
 * or -1 if home cannot be opened. */
int gaudit_secret_scan(const char *home, uid_t uid, gaudit_secret_fn fn, void *ctx,
                       gaudit_secret_stats *stats);
