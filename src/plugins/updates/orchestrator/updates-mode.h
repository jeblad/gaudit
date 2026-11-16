/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's "updates" mode: the Updates collection, as the user. */
#pragma once

#include <stdint.h>
#include <stdio.h>

#include "gaudit/backend.h"
#include "vendor.h"

/* Writes every fact the backend can give, then the closing line, to out.
 * expected: the backend the distribution implies (may be NULL). For tests
 * any backend will do. 0 on success. */
int gaudit_updates_collect(const gaudit_pkg_backend *pkg, const gaudit_pkg_backend *expected,
                           int64_t now, FILE *out);

/* The known vendor package (vendor.h) an installed package without a
 * source is, by its name and maker, or NULL. The Updates collection and
 * the list of packages without a source both take these out. */
const gaudit_vendor_package *gaudit_updates_vendor_of(const gaudit_pkg_backend *pkg,
                                                      const char *name, const char *arch,
                                                      gaudit_sourceless_group group);

/* Local copies of a vendor's source (vendor.h) under var_dir ("/var"),
 * with what is installed from them; once per process (reset for tests). */
void gaudit_updates_local_scan(const gaudit_pkg_backend *pkg, const char *var_dir);
void gaudit_updates_local_reset(void);

/* 1 when an installed package with this name and version came from such a
 * copy: the Updates collection and the list of packages without a source
 * both take these out (after gaudit_updates_local_scan). */
int gaudit_updates_from_local(const char *name, const char *version);

/* The package another program keeps up to date (vendor.h) an installed
 * package without a source is, by its name and maker, or NULL. */
const gaudit_vendor_companion *gaudit_updates_companion_of(const gaudit_pkg_backend *pkg,
                                                           const char *name, const char *arch);

/* Where Flatpak apps are looked for: system ("/var/lib/flatpak") and a home
 * folder (NULL: the user's own). For tests. */
void gaudit_updates_flatpak_dirs(const char *system, const char *home);

/* "updates latest <id>": the newest version the vendor offers, as one
 * vendor-latest line (updates.h). 0 on success, 2 for an id not in the
 * table. The network is used here only. */
int gaudit_updates_latest(const char *id);

/* The vendor-latest line from response headers already fetched; for
 * tests. 0 on success. */
int gaudit_updates_latest_from(const gaudit_pkg_backend *pkg, const gaudit_vendor_package *v,
                               const char *headers, FILE *out);

/* "updates download <id> <version>": the vendor's package of that version
 * into ~/.cache/gaudit/vendor/<id>.deb (the folder emptied first), as one
 * vendor-download line (updates.h). 0 on success, 2 for bad arguments. */
int gaudit_updates_download(const char *id, const char *version);

/* "quick" for now, the only level. 0 on success, 2 for another level. */
int gaudit_updates_mode(const char *level);
