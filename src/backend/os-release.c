/* SPDX-License-Identifier: GPL-3.0-only */
#include "os-release.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILE_SIZE (64 * 1024)

/* Value after '=': optionally quoted; in double quotes, \" \\ \$ \` are
 * escapes. Unquoted values end at whitespace. */
static void copy_value(const char *p, char *out, size_t len)
{
    size_t o = 0;
    char quote = 0;
    if (*p == '"' || *p == '\'')
        quote = *p++;
    while (*p != '\0' && *p != '\n' && *p != '\r') {
        if (quote != 0 && *p == quote)
            break;
        if (quote == 0 && (*p == ' ' || *p == '\t'))
            break;
        if (quote == '"' && *p == '\\' && p[1] != '\0' && strchr("\"\\$`", p[1]) != NULL)
            p++;
        if ((unsigned char)*p >= 0x20 && *p != 0x7f && o + 1 < len)
            out[o++] = *p;
        p++;
    }
    out[o] = '\0';
}

int gaudit_os_release_read(const char *path, gaudit_os_release *out)
{
    if (path == NULL || out == NULL)
        return -1;
    memset(out, 0, sizeof *out);

    FILE *f = fopen(path, "re");
    if (f == NULL)
        return -1;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > MAX_FILE_SIZE) {
        fclose(f);
        return -1;
    }

    static const struct {
        const char *key;
        size_t offset;
        size_t size;
    } fields[] = {
        { "ID",          offsetof(gaudit_os_release, id),          sizeof out->id },
        { "ID_LIKE",     offsetof(gaudit_os_release, id_like),     sizeof out->id_like },
        { "NAME",        offsetof(gaudit_os_release, name),        sizeof out->name },
        { "VERSION_ID",  offsetof(gaudit_os_release, version_id),  sizeof out->version_id },
        { "VERSION",     offsetof(gaudit_os_release, version),     sizeof out->version },
        { "PRETTY_NAME", offsetof(gaudit_os_release, pretty_name), sizeof out->pretty_name },
    };

    char line[1024];
    while (fgets(line, sizeof line, f) != NULL) {
        char *eq = strchr(line, '=');
        if (line[0] == '#' || eq == NULL)
            continue;
        *eq = '\0';
        for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++)
            if (strcmp(line, fields[i].key) == 0)
                copy_value(eq + 1, (char *)out + fields[i].offset, fields[i].size);
    }
    fclose(f);
    return 0;
}

static int has_word(const char *list, const char *word)
{
    size_t n = strlen(word);
    for (const char *p = list; *p != '\0';) {
        while (*p == ' ')
            p++;
        size_t len = strcspn(p, " ");
        if (len == n && strncmp(p, word, n) == 0)
            return 1;
        p += len;
    }
    return 0;
}

const gaudit_pkg_backend *gaudit_pkg_backend_expected_for(const gaudit_os_release *os)
{
    if (os != NULL) {
        static const char *const debian_family[] = { "debian", "ubuntu", NULL };
        for (const char *const *w = debian_family; *w != NULL; w++)
            if (strcmp(os->id, *w) == 0 || has_word(os->id_like, *w))
                return gaudit_pkg_backend_debian();
        /* ID only: RHEL-family systems list "fedora" in ID_LIKE but have no
         * dnf5, and must not get a "package system missing" warning. */
        if (strcmp(os->id, "fedora") == 0)
            return gaudit_pkg_backend_fedora();
    }
    return NULL;
}

void gaudit_os_release_describe(const gaudit_os_release *os, char *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return;
    buf[0] = '\0';
    if (os == NULL)
        return;
    if (os->name[0] != '\0' && os->version_id[0] != '\0') {
        char codename[128] = "";
        const char *open = strchr(os->version, '(');
        const char *close = open != NULL ? strchr(open, ')') : NULL;
        if (close != NULL && close > open + 1)
            snprintf(codename, sizeof codename, " %.*s", (int)(close - open - 1), open + 1);
        snprintf(buf, len, "%s %s%s", os->name, os->version_id, codename);
    }
    else if (os->pretty_name[0] != '\0')
        snprintf(buf, len, "%s", os->pretty_name);
    else if (os->name[0] != '\0')
        snprintf(buf, len, "%s", os->name);
}

void gaudit_os_release_name(const gaudit_os_release *os, char *buf, size_t len)
{
    if (buf == NULL || len == 0)
        return;
    buf[0] = '\0';
    if (os == NULL)
        return;
    snprintf(buf, len, "%s", os->name[0] != '\0' ? os->name : os->pretty_name);
}

/* --- System ---------------------------------------------------------------- */

static int read_system_os_release(gaudit_os_release *os)
{
    return gaudit_os_release_read("/etc/os-release", os) == 0
        || gaudit_os_release_read("/usr/lib/os-release", os) == 0;
}

const gaudit_pkg_backend *gaudit_pkg_backend_default(void)
{
    static const gaudit_pkg_backend *chosen;
    if (chosen == NULL) {
        /* In order of preference; more backends go here. */
        const gaudit_pkg_backend *candidates[] = {
            gaudit_pkg_backend_debian(), gaudit_pkg_backend_fedora(), NULL
        };
        chosen = gaudit_pkg_backend_generic();
        for (const gaudit_pkg_backend **b = candidates; *b != NULL; b++)
            if ((*b)->detect != NULL && (*b)->detect()) {
                chosen = *b;
                break;
            }
    }
    return chosen;
}

const gaudit_pkg_backend *gaudit_pkg_backend_expected(void)
{
    gaudit_os_release os;
    return gaudit_pkg_backend_expected_for(read_system_os_release(&os) ? &os : NULL);
}

void gaudit_system_describe(char *host, size_t host_len, char *name, size_t name_len,
                            char *full, size_t full_len)
{
    if (host != NULL && host_len > 0) {
        char hostname[HOST_NAME_MAX + 1];
        host[0] = '\0';
        if (gethostname(hostname, sizeof hostname) == 0) {
            hostname[sizeof hostname - 1] = '\0';
            size_t o = 0;
            for (const char *p = hostname; *p != '\0' && o + 1 < host_len; p++)
                if ((unsigned char)*p >= 0x20 && *p != 0x7f)
                    host[o++] = *p;
            host[o] = '\0';
        }
    }
    gaudit_os_release os;
    int have = read_system_os_release(&os);
    if (name != NULL && name_len > 0)
        gaudit_os_release_name(have ? &os : NULL, name, name_len);
    if (full != NULL && full_len > 0)
        gaudit_os_release_describe(have ? &os : NULL, full, full_len);
}
