/* SPDX-License-Identifier: GPL-3.0-only */
/* What the Fedora backend reads directly from files. Backend internal;
 * exposed in a private header so it can be tested on fixture trees.
 * root is a path prefix ("" for this machine). */
#pragma once

#include <stdint.h>

#include "gaudit/backend.h"

/* 1 if an rpm database, /usr/bin/rpm and /usr/bin/dnf5 are present. */
int gaudit_fedora_present(const char *root);

/* Newest mtime of <cache_dir>/<repo>/repodata/repomd.xml: when the package
 * metadata was last refreshed. UNAVAILABLE when there is no cache. */
gaudit_backend_status gaudit_dnf_cache_time(const char *cache_dir, int64_t *out_epoch);

/* Updates are installed automatically: dnf5-automatic.timer (or its alias
 * dnf-automatic.timer) is enabled and apply_updates is on. The override
 * files /etc/dnf/automatic.conf and /etc/dnf/dnf5-plugins/automatic.conf
 * are both honoured; if they disagree the answer is unknown (ERROR). Else
 * the packaged default applies. A timer that only downloads counts as off. */
gaudit_backend_status gaudit_dnf_automatic(const char *root, int *out_enabled);
