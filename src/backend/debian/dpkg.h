/* SPDX-License-Identifier: GPL-3.0-only */
/* dpkg/apt package state, Ubuntu backend internal. Reads the files directly;
 * exposed in a private header so it can be tested on fixtures. */
#pragma once

#include "gaudit/backend.h"

/* 1 if status_file is a regular, readable file and dpkg_bin is executable. */
int gaudit_deb_present(const char *status_file, const char *dpkg_bin);

/* dpkg's version ordering (epoch:upstream-revision, '~' sorts first).
 * Returns <0, 0 or >0. */
int gaudit_deb_version_compare(const char *a, const char *b);

typedef struct {
    unsigned obsolete;    /* as apt's "local": installed version offered nowhere, no upgrade */
    unsigned upgradable;  /* an upgrade would install a newer version */
} gaudit_deb_counts;

/* Compares installed packages (status_file) with the package indexes
 * (*_Packages in lists_dir), choosing candidates the way apt does:
 *  - default priorities: 500, 1 for NotAutomatic suites, 100 with
 *    ButAutomaticUpgrades, 100 for the installed version;
 *  - apt preferences (prefs_file, prefs_dir; either may be NULL or missing):
 *    Pin: version / origin / release (a n v o l c b), glob patterns,
 *    specific records before "Package: *", first match wins;
 *  - highest priority wins, ties go to the higher version, negative
 *    priorities are never installed, downgrades are not counted;
 *  - phased updates below 100 % are held back.
 * Not followed: APT::Default-Release, regex package patterns.
 * Obsolete ignores versioned kernel packages, which are kept as fallbacks.
 *
 * GAUDIT_BACKEND_ERROR when the preferences use something not supported
 * (no guess). GAUDIT_BACKEND_UNAVAILABLE when there are no indexes, or when
 * any index is stored compressed (those are not read). */
gaudit_backend_status gaudit_deb_scan(const char *status_file, const char *lists_dir,
                                      const char *prefs_file, const char *prefs_dir,
                                      gaudit_deb_counts *out);

/* Called once per package counted as obsolete. */
typedef void (*gaudit_deb_package_fn)(const char *name, const char *arch,
                                      const char *version, void *ctx);

/* As gaudit_deb_scan, and reports each obsolete package (on_obsolete may be NULL). */
gaudit_backend_status gaudit_deb_scan_ex(const char *status_file, const char *lists_dir,
                                         const char *prefs_file, const char *prefs_dir,
                                         gaudit_deb_counts *out,
                                         gaudit_deb_package_fn on_obsolete, void *ctx);
