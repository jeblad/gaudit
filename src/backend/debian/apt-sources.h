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

/* 1 if host is an official source of security updates. */
int gaudit_apt_official_security_host(const char *host);
