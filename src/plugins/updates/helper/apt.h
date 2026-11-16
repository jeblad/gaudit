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

/* A PPA that may be set up again: a plain name (apt-ops.h), named by a
 * file in sources_dir (e.g. "/etc/apt/sources.list.d") that has the
 * release upgrade's copy beside it (<file>.distUpgrade). So only a PPA
 * this computer had before, and the upgrade switched off, is ever added:
 * never one of the caller's choosing. 1 yes, 0 no. */
int gaudit_apt_ppa_ok(const char *ppa, const char *sources_dir);

/* VERSION_CODENAME from an os-release file ("stonking"), lower-case
 * letters only. 1 when found. */
int gaudit_os_codename(const char *os_release, char *out, size_t len);

/* Whether apt has read the PPA for this release: its InRelease or Release
 * file for codename is in lists_dir (e.g. "/var/lib/apt/lists"). 1 yes. */
int gaudit_apt_ppa_read(const char *ppa, const char *lists_dir, const char *codename);

/* One argument of op, checked for this system: an installed package for
 * reinstall, a PPA switched off at the upgrade for add-ppa. 1 yes, 0 no. */
int gaudit_apt_arg_ok(const gaudit_apt_op *op, const char *arg);

/* Runs the operation named op with exactly its argv and its arguments
 * (each checked again here) and returns its exit status, or -1 when it
 * could not be run. For add-ppa, 100 also when the tool ended well but
 * the PPA could not be read for the release running. The tool's own output goes to /dev/null. */
int gaudit_apt_run(const char *op, char *const *args, size_t n_args);

/* Installs the package file at path (absolute, in the helper's own folder)
 * with apt-get, so what it depends on comes along. The exit status, or -1. */
int gaudit_apt_install_file(const char *path);
