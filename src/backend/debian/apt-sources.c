/* SPDX-License-Identifier: GPL-3.0-only */
#include "apt-sources.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Run by Canonical or Debian themselves. Country mirrors such as
 * no.archive.ubuntu.com are third parties and may lag behind. */
static const char *const official_hosts[] = {
    "security.ubuntu.com",
    "archive.ubuntu.com",
    "ports.ubuntu.com",
    "esm.ubuntu.com",
    "security.debian.org",
    "deb.debian.org",
    NULL
};

int gaudit_apt_official_security_host(const char *host)
{
    if (host == NULL)
        return 0;
    for (const char *const *h = official_hosts; *h != NULL; h++)
        if (strcmp(host, *h) == 0)
            return 1;
    return 0;
}

/* "<host>_<path>_dists_<suite>_..." -> host and suite; 0 if not that shape. */
static int split_name(const char *name, char *host, size_t host_len,
                      char *suite, size_t suite_len)
{
    const char *host_end = strchr(name, '_');
    const char *dists = strstr(name, "_dists_");
    if (host_end == NULL || dists == NULL)
        return 0;
    const char *suite_start = dists + strlen("_dists_");
    const char *suite_end = strchr(suite_start, '_');
    if (suite_end == NULL)
        return 0;
    snprintf(host, host_len, "%.*s", (int)(host_end - name), name);
    snprintf(suite, suite_len, "%.*s", (int)(suite_end - suite_start), suite_start);
    return 1;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t len = strlen(s), slen = strlen(suffix);
    return len >= slen && strcmp(s + len - slen, suffix) == 0;
}

gaudit_backend_status gaudit_apt_security_sources(const char *lists_dir,
                                                  unsigned *out_official, unsigned *out_mirror,
                                                  char *host_buf, size_t host_len)
{
    if (lists_dir == NULL || out_official == NULL || out_mirror == NULL)
        return GAUDIT_BACKEND_ERROR;
    DIR *dir = opendir(lists_dir);
    if (dir == NULL)
        return errno == ENOENT ? GAUDIT_BACKEND_UNAVAILABLE : GAUDIT_BACKEND_ERROR;

    unsigned official = 0, mirror = 0;
    if (host_buf != NULL && host_len > 0)
        host_buf[0] = '\0';

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        /* One Release file per suite and origin. */
        if (!ends_with(de->d_name, "_InRelease") && !ends_with(de->d_name, "_Release"))
            continue;
        char host[256], suite[128];
        if (!split_name(de->d_name, host, sizeof host, suite, sizeof suite)
            || !ends_with(suite, "-security"))
            continue;
        if (gaudit_apt_official_security_host(host)) {
            official++;
        } else {
            if (mirror == 0 && host_buf != NULL && host_len > 0)
                snprintf(host_buf, host_len, "%s", host);
            mirror++;
        }
    }
    closedir(dir);

    *out_official = official;
    *out_mirror = mirror;
    return GAUDIT_BACKEND_OK;
}
