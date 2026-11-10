/* SPDX-License-Identifier: GPL-3.0-only */
#include "dnf-files.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILE_SIZE (64 * 1024)

static int join(char *buf, size_t len, const char *root, const char *path)
{
    int n = snprintf(buf, len, "%s%s", root != NULL ? root : "", path);
    return n >= 0 && (size_t)n < len;
}

static int regular_nonempty(const char *root, const char *path)
{
    char full[PATH_MAX];
    struct stat st;
    return join(full, sizeof full, root, path)
        && stat(full, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0;
}

static int executable(const char *root, const char *path)
{
    char full[PATH_MAX];
    return join(full, sizeof full, root, path) && access(full, X_OK) == 0;
}

int gaudit_fedora_present(const char *root)
{
    int rpmdb = regular_nonempty(root, "/usr/lib/sysimage/rpm/rpmdb.sqlite")
             || regular_nonempty(root, "/var/lib/rpm/rpmdb.sqlite");
    return rpmdb && executable(root, "/usr/bin/rpm") && executable(root, "/usr/bin/dnf5");
}

gaudit_backend_status gaudit_dnf_cache_time(const char *cache_dir, int64_t *out_epoch)
{
    if (cache_dir == NULL || out_epoch == NULL)
        return GAUDIT_BACKEND_ERROR;
    DIR *dir = opendir(cache_dir);
    if (dir == NULL)
        return errno == ENOENT ? GAUDIT_BACKEND_UNAVAILABLE : GAUDIT_BACKEND_ERROR;

    int64_t newest = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof path, "%s/%s/repodata/repomd.xml", cache_dir, de->d_name);
        struct stat st;
        if (n > 0 && (size_t)n < sizeof path && stat(path, &st) == 0 && S_ISREG(st.st_mode)
            && st.st_mtime > newest)
            newest = st.st_mtime;
    }
    closedir(dir);

    if (newest == 0)
        return GAUDIT_BACKEND_UNAVAILABLE;
    *out_epoch = newest;
    return GAUDIT_BACKEND_OK;
}

/* Value of key in [section] of an INI file: 1 true, 0 false, -1 absent,
 * -2 unreadable or unparsable. */
static int ini_bool(const char *path, const char *section, const char *key)
{
    FILE *f = fopen(path, "re");
    if (f == NULL)
        return errno == ENOENT ? -1 : -2;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > MAX_FILE_SIZE) {
        fclose(f);
        return -2;
    }

    int result = -1, in_section = 0;
    char line[512];
    while (fgets(line, sizeof line, f) != NULL) {
        char *s = line;
        while (isspace((unsigned char)*s))
            s++;
        if (*s == '#' || *s == ';' || *s == '\0')
            continue;
        if (*s == '[') {
            char *end = strchr(s, ']');
            in_section = end != NULL && (size_t)(end - s - 1) == strlen(section)
                      && strncmp(s + 1, section, strlen(section)) == 0;
            continue;
        }
        if (!in_section)
            continue;
        char *eq = strchr(s, '=');
        if (eq == NULL)
            continue;
        char *k_end = eq;
        while (k_end > s && isspace((unsigned char)k_end[-1]))
            k_end--;
        if ((size_t)(k_end - s) != strlen(key) || strncmp(s, key, strlen(key)) != 0)
            continue;
        char *v = eq + 1;
        while (isspace((unsigned char)*v))
            v++;
        size_t vlen = strcspn(v, " \t\r\n#;");
        if ((vlen == 3 && strncasecmp(v, "yes", 3) == 0) || (vlen == 4 && strncasecmp(v, "true", 4) == 0)
            || (vlen == 2 && strncasecmp(v, "on", 2) == 0) || (vlen == 1 && v[0] == '1'))
            result = 1;
        else if ((vlen == 2 && strncasecmp(v, "no", 2) == 0) || (vlen == 5 && strncasecmp(v, "false", 5) == 0)
                 || (vlen == 3 && strncasecmp(v, "off", 3) == 0) || (vlen == 1 && v[0] == '0'))
            result = 0;
        else
            result = -2;  /* a value we do not understand: no guess */
    }
    fclose(f);
    return result;
}

gaudit_backend_status gaudit_dnf_automatic(const char *root, int *out_enabled)
{
    if (out_enabled == NULL)
        return GAUDIT_BACKEND_ERROR;

    /* dnf-automatic.timer is an alias of dnf5-automatic.timer; either name
     * may be the one that was enabled. */
    static const char *const timers[] = {
        "/etc/systemd/system/timers.target.wants/dnf5-automatic.timer",
        "/etc/systemd/system/timers.target.wants/dnf-automatic.timer",
    };
    int timer_on = 0;
    for (size_t i = 0; i < sizeof timers / sizeof timers[0]; i++) {
        char path[PATH_MAX];
        struct stat st;
        if (!join(path, sizeof path, root, timers[i]))
            return GAUDIT_BACKEND_ERROR;
        if (lstat(path, &st) == 0)
            timer_on = 1;
    }
    if (!timer_on) {
        *out_enabled = 0;
        return GAUDIT_BACKEND_OK;
    }

    /* Both override files are reserved by the package; which one wins is
     * not known, so they must not disagree. Then the packaged default. */
    char etc_a[PATH_MAX], etc_b[PATH_MAX], packaged[PATH_MAX];
    if (!join(etc_a, sizeof etc_a, root, "/etc/dnf/automatic.conf")
        || !join(etc_b, sizeof etc_b, root, "/etc/dnf/dnf5-plugins/automatic.conf")
        || !join(packaged, sizeof packaged, root, "/usr/share/dnf5/dnf5-plugins/automatic.conf"))
        return GAUDIT_BACKEND_ERROR;
    int a = ini_bool(etc_a, "commands", "apply_updates");
    int b = ini_bool(etc_b, "commands", "apply_updates");
    if (a == -2 || b == -2 || (a >= 0 && b >= 0 && a != b))
        return GAUDIT_BACKEND_ERROR;
    int apply = a >= 0 ? a : b;
    if (apply == -1)
        apply = ini_bool(packaged, "commands", "apply_updates");
    if (apply == -2)
        return GAUDIT_BACKEND_ERROR;
    *out_enabled = apply == 1;  /* absent everywhere: dnf's default is no */
    return GAUDIT_BACKEND_OK;
}
