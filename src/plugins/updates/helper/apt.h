/* SPDX-License-Identifier: GPL-3.0-only */
/* Running the operations of common/apt-ops.h as root, on request from an
 * Updates fix page. Nothing else ever runs through here. */
#pragma once

#include <stddef.h>

#include "apt-ops.h"

/* A package that may be reinstalled: a plain name (apt-ops.h), and
 * installed, by dpkg's file list under info_dir (e.g. "/var/lib/dpkg/info").
 * 1 yes, 0 no. */
int gaudit_apt_package_ok(const char *name, const char *info_dir);

/* Runs the operation named op with exactly its argv (and packages, for
 * reinstall, each checked again here) and returns its exit status, or -1
 * when it could not be run. The tool's own output goes to /dev/null. */
int gaudit_apt_run(const char *op, char *const *packages, size_t n_packages);
