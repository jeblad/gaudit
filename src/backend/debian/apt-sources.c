/* SPDX-License-Identifier: GPL-3.0-only */
#include "apt-sources.h"

#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

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

/* --- Sources that are set up but never read ------------------------------ */

typedef struct {
    const char *lists_dir;
    DIR *lists;          /* reopened per lookup: small, and read once a source */
    unsigned count;
    char *names;
    size_t names_len;
    int failed;
} unread_ctx;

/* The start apt gives a source's list files: the URI without its method,
 * credentials and trailing slash, with '/' as '_'
 * ("http://prerelease.keybase.io/deb" -> "prerelease.keybase.io_deb").
 * 0 when the URI is of a kind not read here (cdrom:, mirror+...). */
static int list_prefix(const char *uri, char *out, size_t len)
{
    if (strncmp(uri, "cdrom:", 6) == 0 || strchr(uri, '+') != NULL)
        return 0;
    const char *p = strstr(uri, "://");
    if (p != NULL)
        p += 3;
    else if (strncmp(uri, "file:", 5) == 0)
        p = uri + 5;
    else
        return 0;
    const char *at = strchr(p, '@');
    const char *slash = strchr(p, '/');
    if (at != NULL && (slash == NULL || at < slash))
        p = at + 1;
    size_t n = 0;
    for (; *p != '\0' && n + 1 < len; p++)
        out[n++] = *p == '/' ? '_' : *p;
    while (n > 0 && out[n - 1] == '_')
        n--;
    out[n] = '\0';
    return n > 0;
}

static int fetched(unread_ctx *ctx, const char *prefix)
{
    DIR *dir = opendir(ctx->lists_dir);
    if (dir == NULL)
        return 0;
    size_t n = strlen(prefix);
    int found = 0;
    struct dirent *de;
    while (!found && (de = readdir(dir)) != NULL)
        found = strncmp(de->d_name, prefix, n) == 0 && de->d_name[n] == '_'
                && (ends_with(de->d_name, "_InRelease") || ends_with(de->d_name, "_Release"));
    closedir(dir);
    return found;
}

static void one_uri(unread_ctx *ctx, const char *uri)
{
    char prefix[512];
    if (!list_prefix(uri, prefix, sizeof prefix) || fetched(ctx, prefix))
        return;
    /* The host is what a person recognises. */
    char host[256];
    snprintf(host, sizeof host, "%.*s", (int)strcspn(prefix, "_"), prefix);
    if (strstr(ctx->names, host) == NULL) {
        size_t used = strlen(ctx->names);
        if (used + strlen(host) + 3 < ctx->names_len)
            snprintf(ctx->names + used, ctx->names_len - used, "%s%s", used > 0 ? ", " : "", host);
        ctx->count++;
    }
}

/* "deb [options] uri suite [component ...]". */
static void one_line(unread_ctx *ctx, char *line)
{
    char *p = line;
    while (isspace((unsigned char)*p))
        p++;
    if (*p == '#' || *p == '\0')
        return;
    if (strncmp(p, "deb-src", 7) == 0 && (p[7] == ' ' || p[7] == '\t'))
        return;
    if (strncmp(p, "deb", 3) != 0 || !(p[3] == ' ' || p[3] == '\t')) {
        ctx->failed = 1;  /* not a line apt would take either */
        return;
    }
    p += 3;
    while (isspace((unsigned char)*p))
        p++;
    if (*p == '[') {
        char *end = strchr(p, ']');
        if (end == NULL) {
            ctx->failed = 1;
            return;
        }
        p = end + 1;
        while (isspace((unsigned char)*p))
            p++;
    }
    size_t n = strcspn(p, " \t\n");
    if (n == 0) {
        ctx->failed = 1;
        return;
    }
    p[n] = '\0';
    one_uri(ctx, p);
}

static void read_list(unread_ctx *ctx, const char *path)
{
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        if (errno != ENOENT)
            ctx->failed = 1;
        return;
    }
    char line[4096];
    while (fgets(line, sizeof line, f) != NULL)
        one_line(ctx, line);
    fclose(f);
}

/* deb822: stanzas with Types, URIs, Enabled; continuation lines (keys
 * inside Signed-By) are not ours. */
static void read_sources(unread_ctx *ctx, const char *path)
{
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        ctx->failed = 1;
        return;
    }
    char line[4096], types[256] = "", uris[2048] = "", enabled[16] = "yes";
    int more = 1;
    while (more) {
        more = fgets(line, sizeof line, f) != NULL;
        char *p = line;
        if (more && line[0] != '\n' && line[0] != '\r') {
            if (line[0] == '#' || line[0] == ' ' || line[0] == '\t')
                continue;
            char *colon = strchr(line, ':');
            if (colon == NULL)
                continue;
            *colon = '\0';
            p = colon + 1;
            while (isspace((unsigned char)*p))
                p++;
            p[strcspn(p, "\r\n")] = '\0';
            if (strcasecmp(line, "Types") == 0)
                snprintf(types, sizeof types, "%s", p);
            else if (strcasecmp(line, "URIs") == 0)
                snprintf(uris, sizeof uris, "%s", p);
            else if (strcasecmp(line, "Enabled") == 0)
                snprintf(enabled, sizeof enabled, "%s", p);
            continue;
        }
        /* The end of a stanza. */
        int deb = 0;
        char copy[256];
        snprintf(copy, sizeof copy, "%s", types);
        char *save = NULL;
        for (char *t = strtok_r(copy, " \t", &save); t != NULL; t = strtok_r(NULL, " \t", &save))
            deb |= strcmp(t, "deb") == 0;
        if (deb && strcasecmp(enabled, "no") != 0) {
            if (uris[0] == '\0')
                ctx->failed = 1;
            save = NULL;
            for (char *u = strtok_r(uris, " \t", &save); u != NULL; u = strtok_r(NULL, " \t", &save))
                one_uri(ctx, u);
        }
        types[0] = uris[0] = '\0';
        snprintf(enabled, sizeof enabled, "yes");
    }
    fclose(f);
}

/* The names apt reads in sources.list.d: [A-Za-z0-9_.-], no dot first. */
static int source_name(const char *name)
{
    if (name[0] == '.')
        return 0;
    for (const char *c = name; *c != '\0'; c++)
        if (!(isalnum((unsigned char)*c) || *c == '_' || *c == '-' || *c == '.'))
            return 0;
    return 1;
}

gaudit_backend_status gaudit_apt_unread_sources(const char *sources_file, const char *sources_dir,
                                                const char *lists_dir, unsigned *out_count,
                                                char *names, size_t names_len)
{
    if (lists_dir == NULL || out_count == NULL || names == NULL || names_len == 0)
        return GAUDIT_BACKEND_ERROR;
    names[0] = '\0';
    unread_ctx ctx = { .lists_dir = lists_dir, .names = names, .names_len = names_len };
    if (sources_file != NULL)
        read_list(&ctx, sources_file);
    DIR *dir = sources_dir != NULL ? opendir(sources_dir) : NULL;
    if (dir == NULL && sources_dir != NULL && errno != ENOENT)
        ctx.failed = 1;
    struct dirent *de;
    while (dir != NULL && (de = readdir(dir)) != NULL) {
        if (!source_name(de->d_name))
            continue;
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", sources_dir, de->d_name);
        if (ends_with(de->d_name, ".list"))
            read_list(&ctx, path);
        else if (ends_with(de->d_name, ".sources"))
            read_sources(&ctx, path);
    }
    if (dir != NULL)
        closedir(dir);
    if (ctx.failed) {
        names[0] = '\0';
        return GAUDIT_BACKEND_ERROR;
    }
    *out_count = ctx.count;
    return GAUDIT_BACKEND_OK;
}

/* --- Sources switched off when the release was upgraded ------------------ */

/* What a person recognises: "ppa:owner/name" for a Launchpad PPA, else the
 * host. */
static void source_label(const char *uri, char *out, size_t len)
{
    const char *p = strstr(uri, "://");
    p = p != NULL ? p + 3 : uri;
    static const char *const ppa_hosts[] = { "ppa.launchpadcontent.net/", "ppa.launchpad.net/" };
    for (size_t i = 0; i < sizeof ppa_hosts / sizeof ppa_hosts[0]; i++) {
        size_t n = strlen(ppa_hosts[i]);
        if (strncmp(p, ppa_hosts[i], n) != 0)
            continue;
        const char *owner = p + n, *slash = strchr(owner, '/');
        if (slash == NULL)
            break;
        size_t name_len = strcspn(slash + 1, "/");
        if (name_len == 0)
            break;
        snprintf(out, len, "ppa:%.*s/%.*s", (int)(slash - owner), owner, (int)name_len, slash + 1);
        return;
    }
    snprintf(out, len, "%.*s", (int)strcspn(p, "/:"), p);
}

/* Counts the file's entries that are on and off, with label and suite set
 * from the first URI. -1 when it cannot be read. */
static int scan_file(const char *path, int deb822, char *label, size_t len, char *suite,
                     size_t suite_len, int *on_out, int *off_out)
{
    suite[0] = '\0';
    label[0] = '\0';
    *on_out = *off_out = 0;
    FILE *f = fopen(path, "re");
    if (f == NULL)
        return -1;
    char line[4096];
    int on = 0, off = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        char *p = line;
        while (isspace((unsigned char)*p))
            p++;
        if (deb822) {
            if (line[0] == ' ' || line[0] == '\t')
                continue;  /* inside Signed-By */
            if (strncasecmp(p, "URIs:", 5) == 0 && label[0] == '\0') {
                p += 5;
                while (isspace((unsigned char)*p))
                    p++;
                p[strcspn(p, " \t\r\n")] = '\0';
                source_label(p, label, len);
            } else if (strncasecmp(p, "Suites:", 7) == 0 && suite[0] == '\0') {
                p += 7;
                while (isspace((unsigned char)*p))
                    p++;
                snprintf(suite, suite_len, "%.*s", (int)strcspn(p, " \t\r\n"), p);
            } else if (strncasecmp(p, "Enabled:", 8) == 0) {
                p += 8;
                while (isspace((unsigned char)*p))
                    p++;
                if (strncasecmp(p, "no", 2) == 0)
                    off++;
                else
                    on++;
            }
            continue;
        }
        /* One-line: "# deb ..." is off, "deb ..." on. */
        int commented = *p == '#';
        if (commented) {
            p++;
            while (isspace((unsigned char)*p))
                p++;
        }
        if (strncmp(p, "deb", 3) != 0 || !(p[3] == ' ' || p[3] == '\t'))
            continue;
        if (commented)
            off++;
        else
            on++;
        if (label[0] == '\0') {
            p += 3;
            while (isspace((unsigned char)*p))
                p++;
            if (*p == '[') {
                char *end = strchr(p, ']');
                p = end != NULL ? end + 1 : p;
                while (isspace((unsigned char)*p))
                    p++;
            }
            size_t uri_len = strcspn(p, " \t\r\n");
            char *rest = p + uri_len;
            while (isspace((unsigned char)*rest))
                rest++;
            snprintf(suite, suite_len, "%.*s", (int)strcspn(rest, " \t\r\n#"), rest);
            p[uri_len] = '\0';
            source_label(p, label, len);
        }
    }
    fclose(f);
    /* deb822 without Enabled is on: a stanza with a URI and no Enabled. */
    if (deb822 && on == 0 && off == 0 && label[0] != '\0')
        on = 1;
    *on_out = on;
    *off_out = off;
    return 0;
}

/* 1 when the file's entries are all switched off, with label set from the
 * first URI; 0 when one is on or none is found. */
static int all_off(const char *path, int deb822, char *label, size_t len, char *suite,
                   size_t suite_len)
{
    int on, off;
    return scan_file(path, deb822, label, len, suite, suite_len, &on, &off) == 0
           && off > 0 && on == 0 && label[0] != '\0';
}

/* Whether a source with this label is on in some file of sources_dir:
 * then it was set up again since the upgrade (add-apt-repository makes a
 * new file named after the new release and leaves the old one), and is no
 * longer switched off. */
static int on_elsewhere(const char *sources_dir, const char *label)
{
    DIR *dir = opendir(sources_dir);
    if (dir == NULL)
        return 0;
    int found = 0;
    struct dirent *de;
    while (!found && (de = readdir(dir)) != NULL) {
        int deb822 = ends_with(de->d_name, ".sources");
        if (!source_name(de->d_name) || (!deb822 && !ends_with(de->d_name, ".list")))
            continue;
        char path[4096], other[128], suite[64];
        int on, off;
        snprintf(path, sizeof path, "%s/%s", sources_dir, de->d_name);
        found = scan_file(path, deb822, other, sizeof other, suite, sizeof suite, &on, &off) == 0
                && on > 0 && strcmp(other, label) == 0;
    }
    closedir(dir);
    return found;
}

gaudit_backend_status gaudit_apt_upgrade_disabled_list(const char *sources_dir,
                                                       gaudit_apt_off_source *out, size_t max,
                                                       size_t *n)
{
    if (sources_dir == NULL || n == NULL || (max > 0 && out == NULL))
        return GAUDIT_BACKEND_ERROR;
    *n = 0;
    DIR *dir = opendir(sources_dir);
    if (dir == NULL)
        return errno == ENOENT ? GAUDIT_BACKEND_OK : GAUDIT_BACKEND_ERROR;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL && *n < max) {
        int deb822 = ends_with(de->d_name, ".sources");
        if (!source_name(de->d_name) || (!deb822 && !ends_with(de->d_name, ".list")))
            continue;
        char path[4096], copy[4200], label[128], suite[64];
        struct stat st;
        snprintf(path, sizeof path, "%s/%s", sources_dir, de->d_name);
        snprintf(copy, sizeof copy, "%s.distUpgrade", path);
        if (stat(copy, &st) != 0 || !all_off(path, deb822, label, sizeof label, suite, sizeof suite)
            || on_elsewhere(sources_dir, label))
            continue;
        int seen = 0;
        for (size_t i = 0; i < *n; i++)
            seen |= strcmp(out[i].label, label) == 0 && strcmp(out[i].suite, suite) == 0;
        if (seen)
            continue;
        snprintf(out[*n].label, sizeof out[*n].label, "%s", label);
        snprintf(out[*n].suite, sizeof out[*n].suite, "%s", suite);
        (*n)++;
    }
    closedir(dir);
    return GAUDIT_BACKEND_OK;
}

gaudit_backend_status gaudit_apt_upgrade_disabled_sources(const char *sources_dir, unsigned *out_count,
                                                          char *names, size_t names_len)
{
    if (out_count == NULL || names == NULL || names_len == 0)
        return GAUDIT_BACKEND_ERROR;
    names[0] = '\0';
    *out_count = 0;
    gaudit_apt_off_source list[32];
    size_t n = 0;
    gaudit_backend_status st = gaudit_apt_upgrade_disabled_list(sources_dir, list, 32, &n);
    if (st != GAUDIT_BACKEND_OK)
        return st;
    for (size_t i = 0; i < n; i++) {
        if (strstr(names, list[i].label) != NULL)
            continue;
        size_t used = strlen(names);
        if (used + strlen(list[i].label) + 3 < names_len)
            snprintf(names + used, names_len - used, "%s%s", used > 0 ? ", " : "", list[i].label);
        (*out_count)++;
    }
    return GAUDIT_BACKEND_OK;
}

int gaudit_distro_info_version(const char *csv, const char *suite, char *version, size_t len)
{
    if (csv == NULL || suite == NULL || version == NULL || len == 0)
        return 0;
    char series[64];
    snprintf(series, sizeof series, "%.*s", (int)strcspn(suite, "-/"), suite);
    if (series[0] == '\0')
        return 0;
    FILE *f = fopen(csv, "re");
    if (f == NULL)
        return 0;
    char line[1024];
    int found = 0;
    while (!found && fgets(line, sizeof line, f) != NULL) {
        /* version,codename,series,... */
        char *v = line, *c1 = strchr(line, ',');
        char *c2 = c1 != NULL ? strchr(c1 + 1, ',') : NULL;
        if (c2 == NULL)
            continue;
        size_t sl = strcspn(c2 + 1, ",\r\n");
        if (sl == strlen(series) && strncmp(c2 + 1, series, sl) == 0) {
            /* "26.04 LTS" -> "26.04" */
            snprintf(version, len, "%.*s", (int)strcspn(v, " ,"), v);
            found = version[0] != '\0';
        }
    }
    fclose(f);
    return found;
}
