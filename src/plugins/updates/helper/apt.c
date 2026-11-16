/* SPDX-License-Identifier: GPL-3.0-only */
#include "apt.h"

#include <dirent.h>
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

/* path names a regular file (not a link). */
static int regular(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

/* Whether the file at path names the PPA's URI (at most 64 KiB read). */
static int names_ppa(const char *path, const char *owner, size_t owner_len, const char *name)
{
    char needle[2][200];
    snprintf(needle[0], sizeof needle[0], "://ppa.launchpadcontent.net/%.*s/%s/",
             (int)owner_len, owner, name);
    snprintf(needle[1], sizeof needle[1], "://ppa.launchpad.net/%.*s/%s/", (int)owner_len, owner, name);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return 0;
    static char buf[64 * 1024 + 1];
    size_t used = 0;
    ssize_t n;
    while (used < sizeof buf - 1 && (n = read(fd, buf + used, sizeof buf - 1 - used)) != 0) {
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            break;
        used += (size_t)n;
    }
    close(fd);
    buf[used] = '\0';
    return strstr(buf, needle[0]) != NULL || strstr(buf, needle[1]) != NULL;
}

int gaudit_apt_ppa_ok(const char *ppa, const char *sources_dir)
{
    if (sources_dir == NULL || !gaudit_apt_plain_ppa(ppa))
        return 0;
    const char *owner = ppa + 4, *slash = strchr(owner, '/');
    DIR *dir = opendir(sources_dir);
    if (dir == NULL)
        return 0;
    int found = 0;
    struct dirent *de;
    while (!found && (de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.' || !(ends_with(de->d_name, ".list") || ends_with(de->d_name, ".sources")))
            continue;
        /* The upgrade's own copy beside it: switched off by the upgrade,
         * not by hand, and not added since by anyone. */
        char path[4096], copy[4200];
        snprintf(path, sizeof path, "%s/%s", sources_dir, de->d_name);
        snprintf(copy, sizeof copy, "%s.distUpgrade", path);
        found = regular(path) && regular(copy)
                && names_ppa(path, owner, (size_t)(slash - owner), slash + 1);
    }
    closedir(dir);
    return found;
}

int gaudit_os_codename(const char *os_release, char *out, size_t len)
{
    if (os_release == NULL || out == NULL || len == 0)
        return 0;
    out[0] = '\0';
    FILE *f = fopen(os_release, "re");
    if (f == NULL)
        return 0;
    char line[512];
    while (fgets(line, sizeof line, f) != NULL) {
        if (strncmp(line, "VERSION_CODENAME=", 17) != 0)
            continue;
        char *v = line + 17;
        if (*v == '"' || *v == '\'')
            v++;
        size_t n = 0;
        while (v[n] >= 'a' && v[n] <= 'z')
            n++;
        if (n > 0 && n < len)
            snprintf(out, len, "%.*s", (int)n, v);
        break;
    }
    fclose(f);
    return out[0] != '\0';
}

int gaudit_apt_ppa_read(const char *ppa, const char *lists_dir, const char *codename)
{
    if (!gaudit_apt_plain_ppa(ppa) || lists_dir == NULL || codename == NULL || codename[0] == '\0')
        return 0;
    const char *owner = ppa + 4, *slash = strchr(owner, '/');
    static const char *const hosts[] = { "ppa.launchpadcontent.net", "ppa.launchpad.net" };
    static const char *const files[] = { "InRelease", "Release" };
    for (size_t h = 0; h < 2; h++)
        for (size_t f = 0; f < 2; f++) {
            char path[1024];
            snprintf(path, sizeof path, "%s/%s_%.*s_%s_ubuntu_dists_%s_%s", lists_dir, hosts[h],
                     (int)(slash - owner), owner, slash + 1, codename, files[f]);
            if (regular(path))
                return 1;
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

int gaudit_apt_arg_ok(const gaudit_apt_op *op, const char *arg)
{
    if (op == NULL)
        return 0;
    if (op->args == GAUDIT_APT_ARGS_PACKAGES)
        return gaudit_apt_package_ok(arg, "/var/lib/dpkg/info");
    if (op->args == GAUDIT_APT_ARGS_PPA)
        return gaudit_apt_ppa_ok(arg, "/etc/apt/sources.list.d");
    return 0;
}

int gaudit_apt_run(const char *op, char *const *args, size_t n_args)
{
    const gaudit_apt_op *o = gaudit_apt_op_find(op);
    if (o == NULL || !gaudit_apt_op_args_ok(o, (const char *const *)args, n_args))
        return -1;
    char *argv[32 + GAUDIT_APT_MAX_PACKAGES];
    size_t n = 0;
    for (; o->argv[n] != NULL && n < 32; n++)
        argv[n] = (char *)o->argv[n];
    for (size_t i = 0; i < n_args; i++) {
        if (!gaudit_apt_arg_ok(o, args[i]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    int status = step(argv);
    /* add-apt-repository ends with 0 even when apt could not read the PPA
     * (no Release file for this release: 404). Read means its Release file
     * for the release running is in apt's lists now; else 100, apt's own
     * code for an error. */
    char codename[64];
    if (status == 0 && o->args == GAUDIT_APT_ARGS_PPA
        && !(gaudit_os_codename("/etc/os-release", codename, sizeof codename)
             && gaudit_apt_ppa_read(args[0], "/var/lib/apt/lists", codename)))
        status = 100;
    return status;
}

int gaudit_apt_install_file(const char *path)
{
    /* A path apt reads as a file to install (it has a "/"), from the
     * helper's own folder; settings files kept, as for every apt step. */
    if (path == NULL || path[0] != '/')
        return -1;
    char *argv[] = {
        (char *)"/usr/bin/apt-get", (char *)"-y",
        (char *)"-o", (char *)"Dpkg::Options::=--force-confdef",
        (char *)"-o", (char *)"Dpkg::Options::=--force-confold",
        (char *)"install", (char *)path, NULL,
    };
    return step(argv);
}
