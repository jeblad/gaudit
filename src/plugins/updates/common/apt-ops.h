/* SPDX-License-Identifier: GPL-3.0-only */
/* The apt and systemctl operations an Updates fix page can run, in one
 * table both sides use: the helper runs argv, the GUI shows the same argv
 * as the command to copy, so what is shown is what runs. The run button
 * sends the operation's name only, never the text. Plain C, no
 * dependencies: it is compiled into the helper and into the GUI. */
#pragma once

#include <stddef.h>

#define GAUDIT_APT_MAX_PACKAGES 40

/* What may follow an operation's fixed argv. */
typedef enum {
    GAUDIT_APT_ARGS_NONE = 0,
    GAUDIT_APT_ARGS_PACKAGES,  /* one or more plain package names (reinstall) */
    GAUDIT_APT_ARGS_PPA,       /* exactly one "ppa:owner/name" (add-ppa) */
} gaudit_apt_args;

typedef struct {
    const char *name;          /* e.g. "apt-upgrade-update" */
    const char *const *argv;   /* absolute path first, NULL-terminated */
    gaudit_apt_args args;
} gaudit_apt_op;

/* The operation with this name, or NULL. */
const gaudit_apt_op *gaudit_apt_op_find(const char *name);

/* The command as the page shows it and the user copies it: "sudo", then
 * argv with the program's own name instead of its path, then the
 * arguments, each checked for the operation's kind (and their number).
 * 0 on success, -1 if one is refused or it does not fit. */
int gaudit_apt_op_shown(const gaudit_apt_op *op, const char *const *args, size_t n_args,
                        char *buf, size_t len);

/* Whether args (n_args of them) may follow op: the right number, and each
 * plain for its kind. Says nothing about whether they exist here. */
int gaudit_apt_op_args_ok(const gaudit_apt_op *op, const char *const *args, size_t n_args);

/* A package name that may go into the command: [a-z0-9][a-z0-9+.-]+,
 * optionally ":arch". 1 yes, 0 no. */
int gaudit_apt_plain_package(const char *name);

/* A Launchpad PPA that may go into the command: "ppa:" then owner and
 * name, each [a-z0-9][a-z0-9+.-]*, at most 64 characters, "/" between.
 * 1 yes, 0 no. */
int gaudit_apt_plain_ppa(const char *ppa);
