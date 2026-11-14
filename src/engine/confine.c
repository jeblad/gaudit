/* SPDX-License-Identifier: GPL-3.0-only */
#include "confine.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Files, the filesystem, programs, processes and sockets. */
static const int denied[] = {
    SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(openat2), SCMP_SYS(creat),
    SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(mknod), SCMP_SYS(mknodat),
    SCMP_SYS(unlink), SCMP_SYS(unlinkat), SCMP_SYS(rmdir),
    SCMP_SYS(rename), SCMP_SYS(renameat), SCMP_SYS(renameat2),
    SCMP_SYS(link), SCMP_SYS(linkat), SCMP_SYS(symlink), SCMP_SYS(symlinkat),
    SCMP_SYS(truncate), SCMP_SYS(ftruncate),
    SCMP_SYS(chmod), SCMP_SYS(fchmod), SCMP_SYS(fchmodat),
    SCMP_SYS(chown), SCMP_SYS(fchown), SCMP_SYS(lchown), SCMP_SYS(fchownat),
    SCMP_SYS(utimensat), SCMP_SYS(setxattr), SCMP_SYS(lsetxattr), SCMP_SYS(fsetxattr),
    SCMP_SYS(removexattr), SCMP_SYS(lremovexattr), SCMP_SYS(fremovexattr),
    SCMP_SYS(execve), SCMP_SYS(execveat), SCMP_SYS(fork), SCMP_SYS(vfork),
    SCMP_SYS(socket), SCMP_SYS(socketpair), SCMP_SYS(connect), SCMP_SYS(bind),
    SCMP_SYS(listen), SCMP_SYS(accept), SCMP_SYS(accept4),
    SCMP_SYS(memfd_create), SCMP_SYS(pidfd_open), SCMP_SYS(pidfd_getfd),
};

int gaudit_engine_confine(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
        return -1;
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < sizeof denied / sizeof denied[0]; i++)
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), denied[i], 0);
    /* A new process is a clone without CLONE_THREAD; threads go on. */
    if (rc == 0)
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
                              SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_THREAD, 0));
    /* clone3 passes its flags in memory, out of the filter's reach. */
    if (rc == 0)
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
    if (rc == 0)
        rc = seccomp_load(ctx);
    seccomp_release(ctx);
    return rc == 0 ? 0 : -1;
}

static int report(const char *what, int allowed)
{
    printf("%s %s\n", allowed ? "ALLOWED" : "denied", what);
    return allowed;
}

int gaudit_engine_selftest(void)
{
    int bad = 0;
    int fd = open("/etc/hostname", O_RDONLY | O_CLOEXEC);
    bad += report("open a file", fd >= 0);
    if (fd >= 0)
        close(fd);
    bad += report("create a folder", mkdir("/tmp/gaudit-engine-selftest", 0700) == 0);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    bad += report("unix socket (D-Bus)", s >= 0);
    if (s >= 0)
        close(s);
    s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    bad += report("network socket", s >= 0);
    if (s >= 0)
        close(s);
    pid_t pid = fork();
    if (pid == 0)
        _exit(0);
    if (pid > 0)
        waitpid(pid, NULL, 0);
    bad += report("new process", pid >= 0);
    char *const argv[] = { (char *)"/bin/true", NULL };
    char *const envp[] = { NULL };
    execve("/bin/true", argv, envp);
    bad += report("start a program", 0);  /* still here: denied */
    return bad == 0 ? 0 : 1;
}
