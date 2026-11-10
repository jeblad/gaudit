/* SPDX-License-Identifier: GPL-3.0-only */
/* Reading /etc/os-release and choosing a backend. Backend internal; exposed
 * in a private header for tests. */
#pragma once

#include <stddef.h>

#include "gaudit/backend.h"

typedef struct {
    char id[64];
    char id_like[256];
    char name[128];
    char version_id[64];
    char version[128];      /* e.g. "26.10 (Stonking Stoat)" */
    char pretty_name[256];
} gaudit_os_release;

/* Parses an os-release file (KEY=value, optionally quoted). Control
 * characters are dropped, values are truncated to the field sizes.
 * 0 on success, -1 if the file is missing, not a regular file or too large. */
int gaudit_os_release_read(const char *path, gaudit_os_release *out);

/* Debian backend if ID or ID_LIKE names debian or ubuntu, otherwise the
 * generic one (also for os == NULL). Recognising a distribution does not
 * mean every check works there: each backend function reports itself. */
const gaudit_pkg_backend *gaudit_pkg_backend_select(const gaudit_os_release *os);

/* "Ubuntu 26.10 Stonking Stoat": NAME VERSION_ID, plus the part of VERSION in
 * parentheses (the code name) without the parentheses. Else PRETTY_NAME,
 * else NAME, else "". */
void gaudit_os_release_describe(const gaudit_os_release *os, char *buf, size_t len);

/* Short name: NAME, else PRETTY_NAME, else "". */
void gaudit_os_release_name(const gaudit_os_release *os, char *buf, size_t len);
