/* SPDX-License-Identifier: GPL-3.0-only */
/* Reducing a check process to what it needs. Called in a freshly forked
 * child of the privileged helper, before any check code runs. */
#pragma once

#include <stddef.h>
#include <sys/capability.h>

/* uid/gid of "nobody" on Debian, Fedora, Arch and SUSE. Fixed rather than
 * looked up: the helper does not use NSS. */
#define GAUDIT_NOBODY_UID 65534
#define GAUDIT_NOBODY_GID 65534

typedef struct {
    int to_nobody;            /* 1: become nobody, no capabilities at all */
    const cap_value_t *caps;  /* else: stay root with only these capabilities */
    size_t n_caps;
} gaudit_sandbox;

/* Close every file descriptor above 2 except keep_fd (-1: none), and point
 * stdin and stderr at /dev/null. 0 on success. */
int gaudit_sandbox_close_fds(int keep_fd);

/* Drop privileges as spec says (root only), set no_new_privs and install the
 * seccomp filter. Also clears the environment. 0 on success; on failure the
 * caller must exit without running the check. */
int gaudit_sandbox_enter(const gaudit_sandbox *spec);

/* Only the no_new_privs + seccomp part; works without root (used by tests). */
int gaudit_sandbox_restrict(void);
