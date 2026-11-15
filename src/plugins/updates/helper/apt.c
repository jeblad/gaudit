/* SPDX-License-Identifier: GPL-3.0-only */
#include "apt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int gaudit_apt_package_ok(const char *name, const char *info_dir)
{
    if (name == NULL || info_dir == NULL || !gaudit_apt_plain_package(name))
        return 0;
    /* dpkg keeps a file list per installed package: <name>.list, or
     * <name>:<arch>.list for a multi-arch one. */
    char path[256];
    struct stat st;
    snprintf(path, sizeof path, "%s/%s.list", info_dir, name);
    if (lstat(path, &st) == 0 && S_ISREG(st.st_mode))
        return 1;
    const char *colon = strchr(name, ':');
    if (colon != NULL) {
        snprintf(path, sizeof path, "%s/%.*s.list", info_dir, (int)(colon - name), name);
        return lstat(path, &st) == 0 && S_ISREG(st.st_mode);
    }
    return 0;
}

/* One step: argv[0] an absolute path, the environment fixed. */
static int step(char *const argv[])
{
    static char *const env[] = {
        (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        (char *)"DEBIAN_FRONTEND=noninteractive",
        (char *)"LC_ALL=C.UTF-8",
        (char *)"HOME=/root",
        NULL,
    };
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(null, STDOUT_FILENO) < 0
            || dup2(null, STDERR_FILENO) < 0)
            _exit(126);
        execve(argv[0], argv, env);
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

int gaudit_apt_run(const char *op, char *const *packages, size_t n_packages)
{
    const gaudit_apt_op *o = gaudit_apt_op_find(op);
    if (o == NULL || (n_packages > 0 && !o->takes_packages) || n_packages > GAUDIT_APT_MAX_PACKAGES
        || (o->takes_packages && n_packages == 0))
        return -1;
    char *argv[32 + GAUDIT_APT_MAX_PACKAGES];
    size_t n = 0;
    for (; o->argv[n] != NULL && n < 32; n++)
        argv[n] = (char *)o->argv[n];
    for (size_t i = 0; i < n_packages; i++) {
        if (!gaudit_apt_package_ok(packages[i], "/var/lib/dpkg/info"))
            return -1;
        argv[n++] = packages[i];
    }
    argv[n] = NULL;
    return step(argv);
}
