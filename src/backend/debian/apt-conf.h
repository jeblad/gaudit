/* SPDX-License-Identifier: GPL-3.0-only */
/* Minimal reader for apt configuration, Ubuntu backend internal.
 * Exposed in a private header so the parser can be tested on fixtures. */
#pragma once

#include "gaudit/backend.h"

/* Reads APT::Periodic::Unattended-Upgrade the way apt does: every file in
 * conf_dir in byte order (skipping names apt ignores), then conf_file; the
 * last value wins, absent means 0.
 *
 * Only the flat "Key "value";" form is understood. Any other form of the key
 * (e.g. nested blocks) gives GAUDIT_BACKEND_ERROR rather than a guess. */
gaudit_backend_status gaudit_apt_unattended_upgrade(const char *conf_file,
                                                    const char *conf_dir,
                                                    int *out_enabled);
