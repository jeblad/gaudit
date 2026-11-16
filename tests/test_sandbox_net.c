/* SPDX-License-Identifier: GPL-3.0-only */
/* The orchestrator's filter: without the network, no network socket can
 * be made (a local one can); with it, a network socket can, and a raw
 * packet socket still cannot. Each in a child, since a filter stays. */
#define _GNU_SOURCE
#include "sandbox.h"

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* In a child: confine, then try a socket. 0 when it could be made. */
static int can_make(int network, int family, int type)
{
    pid_t pid = fork();
    if (pid == 0) {
        if (gaudit_sandbox_restrict_net(network) != 0)
            _exit(2);
        int s = socket(family, type | SOCK_CLOEXEC, 0);
        _exit(s >= 0 ? 0 : errno == EPERM ? 1 : 3);
    }
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

int main(void)
{
    int failures = 0;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); failures++; } } while (0)
    CHECK(can_make(0, AF_INET, SOCK_STREAM) == 1);
    CHECK(can_make(0, AF_INET6, SOCK_STREAM) == 1);
    CHECK(can_make(0, AF_UNIX, SOCK_STREAM) == 0);
    CHECK(can_make(1, AF_INET, SOCK_STREAM) == 0);
    CHECK(can_make(1, AF_PACKET, SOCK_RAW) == 1);
    if (failures == 0)
        puts("sandbox-net: all checks passed");
    return failures == 0 ? 0 : 1;
}
