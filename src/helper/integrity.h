/* SPDX-License-Identifier: GPL-3.0-only */
/* Package integrity: compares the installed files of every deb package
 * with dpkg's md5sums (/var/lib/dpkg/info/<package>.md5sums). Reads only.
 *
 * What it can tell: a file changed after installation by the user, a
 * program, or a clumsy root. What it cannot: a root that also rewrites the
 * md5sums, which are not signed after installation, and MD5 itself has
 * known collisions. A clean result is "no changes found", not proof.
 *
 * Configuration files are not in the md5sums (dpkg keeps their sums in
 * the status file), so the user's own edits in /etc are not findings.
 * Files moved aside with dpkg-divert are skipped: the diverting package
 * owns that path. A missing file that dpkg's path-exclude filters keep
 * out (e.g. documentation on minimal systems) is not a finding. */
#pragma once

#include <stddef.h>

typedef enum {
    GAUDIT_INTEGRITY_CHANGED = 0,  /* content differs, or no longer a regular file */
    GAUDIT_INTEGRITY_MISSING,      /* gone, and not excluded by path-exclude */
    GAUDIT_INTEGRITY_UNREADABLE,   /* could not be read (permissions, I/O) */
    GAUDIT_INTEGRITY_KINDS
} gaudit_integrity_kind;

typedef struct {
    unsigned packages;          /* md5sums lists read */
    unsigned long files;        /* files in them */
    unsigned long checked;      /* files read and compared */
    unsigned long changed;
    unsigned long missing;
    unsigned long unreadable;
    unsigned long excluded;     /* missing, but kept out by path-exclude */
    unsigned long diverted;     /* skipped: moved aside with dpkg-divert */
    unsigned long bad_lines;    /* lines in an md5sums list that are not "<md5>  <path>" */
    unsigned long long bytes;   /* bytes read */
} gaudit_integrity_result;

/* Called once per finding, never at the same time from two threads.
 * package is the list's name (e.g. "bash" or "libc6:amd64"); path is
 * absolute, as dpkg names it (without root). */
typedef void (*gaudit_integrity_fn)(gaudit_integrity_kind kind, const char *package,
                                    const char *path, void *ctx);

typedef struct {
    const char *root;           /* "" for the real system; a directory in tests */
    const char *info_dir;       /* /var/lib/dpkg/info */
    const char *diversions;     /* /var/lib/dpkg/diversions; may be missing */
    const char *cfg_file;       /* /etc/dpkg/dpkg.cfg; may be missing */
    const char *cfg_dir;        /* /etc/dpkg/dpkg.cfg.d; may be missing */
    unsigned threads;           /* 1 or more */
} gaudit_integrity_paths;

/* 0 when the scan ran (findings or not), -1 when it could not (info_dir
 * unreadable, out of memory). */
int gaudit_integrity_scan(const gaudit_integrity_paths *paths, gaudit_integrity_result *out,
                          gaudit_integrity_fn fn, void *ctx);
