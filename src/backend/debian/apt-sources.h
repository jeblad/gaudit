/* SPDX-License-Identifier: GPL-3.0-only */
/* Where apt gets its security updates from, read from the list files apt
 * actually fetched (not from sources.list). Backend internal; exposed for
 * tests. */
#pragma once

#include <stddef.h>

#include "gaudit/backend.h"

/* Counts *-security suites in lists_dir by origin: official hosts
 * (Canonical's and Debian's own) and others (mirrors). The first other host
 * is copied to host_buf. UNAVAILABLE when there is no lists directory. */
gaudit_backend_status gaudit_apt_security_sources(const char *lists_dir,
                                                  unsigned *out_official, unsigned *out_mirror,
                                                  char *host_buf, size_t host_len);

/* Software sources that are set up but whose lists apt has never fetched
 * (no Release or InRelease file for them in lists_dir): nothing from them
 * gets updates. Read from sources_file (/etc/apt/sources.list) and every
 * *.list and *.sources file in sources_dir, both formats; disabled
 * entries (Enabled: no) and deb-src are left out, as are cdrom: sources.
 * The first hosts go to names, ", " between. GAUDIT_BACKEND_ERROR when a
 * deb entry cannot be read: no guess. */
gaudit_backend_status gaudit_apt_unread_sources(const char *sources_file, const char *sources_dir,
                                                const char *lists_dir, unsigned *out_count,
                                                char *names, size_t names_len);

/* Software sources switched off when the release was upgraded: a file in
 * sources_dir whose entries are all off (Enabled: no, or every deb line
 * commented out) with the copy the upgrade made beside it
 * (<name>.distUpgrade). Their names go to names, ", " between: a PPA as
 * "ppa:owner/name", other sources by host. */
gaudit_backend_status gaudit_apt_upgrade_disabled_sources(const char *sources_dir, unsigned *out_count,
                                                          char *names, size_t names_len);

/* One source switched off when the release was upgraded: its name as
 * above and the suite it was for (e.g. "questing"). */
typedef struct {
    char label[128];
    char suite[64];
} gaudit_apt_off_source;

/* The same sources one by one, at most max; *n how many were found. */
gaudit_backend_status gaudit_apt_upgrade_disabled_list(const char *sources_dir,
                                                       gaudit_apt_off_source *out, size_t max,
                                                       size_t *n);

/* The version of a release from its series name ("questing" -> "25.10",
 * "bookworm" -> "12"), by distro-info's table (csv: version,codename,
 * series,...); a suite's pocket ("questing-updates") is left off. 1 with
 * version set, 0 when the table or the series is not there. */
int gaudit_distro_info_version(const char *csv, const char *suite, char *version, size_t len);

/* 1 if host is an official source of security updates. */
int gaudit_apt_official_security_host(const char *host);
