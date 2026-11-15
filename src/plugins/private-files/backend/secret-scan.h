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
    unsigned caches;     /* of them, caches (searched only on request) */
    int truncated;       /* stopped at the entry limit */
} gaudit_secret_stats;

typedef void (*gaudit_secret_fn)(const gaudit_secret_hit *hit, void *ctx);

/* Walks home (absolute) for owner uid and calls fn for each hit. Returns 0,
 * or -1 if home cannot be opened. */
int gaudit_secret_scan(const char *home, uid_t uid, gaudit_secret_fn fn, void *ctx,
                       gaudit_secret_stats *stats);

/* The same for a folder elsewhere (absolute, canonical): its whole tree,
 * within its filesystem; reach also takes the folders above it into
 * account, from "/" down (looked at with stat, never listed). rel is then
 * relative to root. */
/* The files whose start is read to recognise a key: up to this size (one
 * of GAUDIT_SECRET_READ_LIMITS; the smallest still holds every real key
 * file). Larger files are judged by name only. */
#define GAUDIT_SECRET_READ_LIMITS { 16384, 65536, 262144, 1048576 }
#define GAUDIT_SECRET_READ_LIMIT_DEFAULT 65536
#define GAUDIT_SECRET_READ_LIMIT_MAX 1048576
/* 0, or -1 for a size not in the list (nothing changes then). */
int gaudit_secret_scan_set_read_limit(size_t bytes);
size_t gaudit_secret_scan_read_limit(void);

/* One file checked again, as the scan would judge it (after a fix): rel
 * beneath root, opened without following any symbolic link; reach from
 * root down, and from "/" when outside_home. 1 still a secret (in *out;
 * out->rel is rel), 0 gone or no longer a secret, -1 cannot be checked. */
int gaudit_secret_check_one(const char *root, int outside_home, const char *rel, uid_t uid,
                            gaudit_secret_hit *out);

/* Whether caches are searched too (default: left out). */
void gaudit_secret_scan_set_caches(int search);

/* Called now and then during a scan with the entries looked at in the
 * folder being walked (every 256) and the folder it is in, relative to the
 * root ("" for the root), so a caller can show it is alive and where. */
typedef void (*gaudit_secret_progress_fn)(unsigned long entries, const char *rel, void *ctx);
void gaudit_secret_scan_set_progress(gaudit_secret_progress_fn fn, void *ctx);

int gaudit_secret_scan_area(const char *root, uid_t uid, gaudit_secret_fn fn, void *ctx,
                            gaudit_secret_stats *stats);
