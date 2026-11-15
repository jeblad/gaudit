/* SPDX-License-Identifier: GPL-3.0-only */
/* The apt and systemctl operations an Updates fix page can run, in one
 * table both sides use: the helper runs argv, the GUI shows the same argv
 * as the command to copy, so what is shown is what runs. The run button
 * sends the operation's name only, never the text. Plain C, no
 * dependencies: it is compiled into the helper and into the GUI. */
#pragma once

#include <stddef.h>

#define GAUDIT_APT_MAX_PACKAGES 40

typedef struct {
    const char *name;          /* e.g. "apt-upgrade-update" */
    const char *const *argv;   /* absolute path first, NULL-terminated */
    int takes_packages;        /* package names follow argv (reinstall) */
} gaudit_apt_op;

/* The operation with this name, or NULL. */
const gaudit_apt_op *gaudit_apt_op_find(const char *name);

/* The command as the page shows it and the user copies it: "sudo", then
 * argv with the program's own name instead of its path, then the packages.
 * 0 on success, -1 if it does not fit. */
int gaudit_apt_op_shown(const gaudit_apt_op *op, const char *const *packages, size_t n_packages,
                        char *buf, size_t len);

/* A package name that may go into the command: [a-z0-9][a-z0-9+.-]+,
 * optionally ":arch". 1 yes, 0 no. */
int gaudit_apt_plain_package(const char *name);
