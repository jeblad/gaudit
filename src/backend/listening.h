/* SPDX-License-Identifier: GPL-3.0-only */
/* Services that listen for connections from the network: TCP sockets in
 * LISTEN on an address other than loopback, read from /proc/net/tcp and
 * tcp6 (no privileges needed). Which program listens needs root and is
 * not known here; the owning account is. Backend internal; exposed for
 * tests. */
#pragma once

#include <sys/types.h>

typedef struct {
    unsigned services;  /* distinct ports */
    unsigned own;       /* ... of those, with a socket owned by uid */
} gaudit_listening;

/* Reads the given files (either may be missing). -1 if neither could be
 * read, or one is malformed. */
int gaudit_listening_read(const char *tcp, const char *tcp6, uid_t uid, gaudit_listening *out);
