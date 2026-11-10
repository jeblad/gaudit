/* SPDX-License-Identifier: GPL-3.0-only */
/* The helper's sandbox, as far as it can be tested without root: the
 * seccomp filter, closing file descriptors, and that dropping privileges
 * fails closed when it cannot be done. Each case runs in a child process,
 * because the filter cannot be removed again. The privilege drop itself is
 * exercised by "gaudit-helper selftest" (pkexec, distro-test.sh). */
#include "sandbox.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

/* Run fn in a child; its exit status (0..255), or -1 if it did not exit. */
static int in_child(int (*fn)(void))
{
    pid_t pid = fork();
    if (pid == 0)
        _exit(fn());
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

/* Each bit is one expectation that failed. */
static int restricted(void)
{
    if (gaudit_sandbox_restrict() != 0)
        return 1;
    int bad = 0;
    errno = 0;
    if (!(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1 && errno == EPERM))
        bad |= 2;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (!(s < 0 && errno == EPERM))
        bad |= 4;
    s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (!(s < 0 && errno == EPERM))
        bad |= 8;
    s = socket(AF_UNIX, SOCK_STREAM, 0);  /* local sockets stay allowed */
    if (s < 0)
        bad |= 16;
    else
        close(s);
    int fd = open("/proc/self/status", O_RDONLY);  /* reading still works */
    if (fd < 0)
        bad |= 32;
    else
        close(fd);
    return bad;
}

static int count_fds(void)
{
    DIR *dir = opendir("/proc/self/fd");
    int n = 0;
    struct dirent *de;
    while (dir != NULL && (de = readdir(dir)) != NULL)
        if (de->d_name[0] != '.')
            n++;
    if (dir != NULL)
        closedir(dir);
    return n - 1;
}

static int fds_closed(void)
{
    for (int i = 0; i < 5; i++)
        if (open("/dev/null", O_RDONLY) < 0)  /* deliberately leaked */
            return 100;
    int keep = open("/dev/null", O_RDONLY);
    if (gaudit_sandbox_close_fds(keep) != 0)
        return 101;
    /* stdin, stdout, stderr and keep; nothing else. */
    return count_fds() == 4 && fcntl(keep, F_GETFD) != -1 ? 0 : count_fds();
}

static int enter_unprivileged(void)
{
    /* Without root, dropping to nobody cannot be done: it must fail, never
     * carry on half done. */
    gaudit_sandbox spec = { .to_nobody = 1 };
    return gaudit_sandbox_enter(&spec) == 0 ? 1 : 0;
}

int main(void)
{
    CHECK(in_child(restricted) == 0);
    CHECK(in_child(fds_closed) == 0);
    if (geteuid() != 0)
        CHECK(in_child(enter_unprivileged) == 0);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
