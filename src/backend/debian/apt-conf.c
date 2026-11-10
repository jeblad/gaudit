/* SPDX-License-Identifier: GPL-3.0-only */
#include "apt-conf.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define KEY           "APT::Periodic::Unattended-Upgrade"
#define BARE_KEY      "Unattended-Upgrade"
#define MAX_FILE_SIZE (64 * 1024)
#define MAX_FILES     256

/* Suffixes apt skips in apt.conf.d (Dir::Ignore-Files-Silently). */
static const char *const ignored_suffixes[] = {
    ".disabled", ".bak", ".save", ".orig", ".distUpgrade",
    ".dpkg-old", ".dpkg-new", ".dpkg-dist", ".dpkg-bak", ".dpkg-tmp",
    ".ucf-old", ".ucf-new", ".ucf-dist",
    NULL
};

static int name_allowed(const char *name)
{
    if (name[0] == '.')
        return 0;
    for (const char *p = name; *p != '\0'; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;

    size_t len = strlen(name);
    for (const char *const *s = ignored_suffixes; *s != NULL; s++) {
        size_t slen = strlen(*s);
        if (len >= slen && strcmp(name + len - slen, *s) == 0)
            return 0;
    }
    return 1;
}

static int filter_entry(const struct dirent *entry)
{
    return name_allowed(entry->d_name);
}

/* Byte order, independent of locale. */
static int compare_entries(const struct dirent **a, const struct dirent **b)
{
    return strcmp((*a)->d_name, (*b)->d_name);
}

/* A value assignment to a bare "Unattended-Upgrade" (nested block form). */
static int bare_assignment(const char *line)
{
    for (const char *q = strstr(line, BARE_KEY); q != NULL; q = strstr(q + 1, BARE_KEY)) {
        const char *after = q + strlen(BARE_KEY);
        while (isspace((unsigned char)*after))
            after++;
        if (*after == '"')
            return 1;
    }
    return 0;
}

/* 0: parsed (value/found updated if the key is present), -1: cannot tell. */
static int parse_file(const char *path, long *value, int *found)
{
    FILE *f = fopen(path, "re");
    if (f == NULL)
        return errno == ENOENT ? 0 : -1;

    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        fclose(f);
        return -1;
    }
    if (S_ISDIR(st.st_mode)) {
        fclose(f);
        return 0;
    }
    if (!S_ISREG(st.st_mode) || st.st_size > MAX_FILE_SIZE) {
        fclose(f);
        return -1;
    }

    int result = 0;
    char line[1024];
    while (fgets(line, sizeof line, f) != NULL) {
        char *s = line;
        while (isspace((unsigned char)*s))
            s++;
        if (*s == '#' || (s[0] == '/' && s[1] == '/'))
            continue;

        if (strstr(s, "Periodic") != NULL && strchr(s, '{') != NULL) {
            result = -1;  /* block syntax around Periodic */
            break;
        }

        size_t klen = strlen(KEY);
        if (strncmp(s, KEY, klen) == 0
            && (isspace((unsigned char)s[klen]) || s[klen] == '"')) {
            char *p = s + klen;
            while (isspace((unsigned char)*p))
                p++;
            if (*p != '"') {
                result = -1;
                break;
            }
            p++;
            char *end;
            errno = 0;
            long v = strtol(p, &end, 10);
            if (end == p || *end != '"' || errno != 0) {
                result = -1;
                break;
            }
            *value = v;
            *found = 1;
        } else if (bare_assignment(s)) {
            result = -1;
            break;
        }
    }
    fclose(f);
    return result;
}

gaudit_backend_status gaudit_apt_unattended_upgrade(const char *conf_file,
                                                    const char *conf_dir,
                                                    int *out_enabled)
{
    if (conf_file == NULL || conf_dir == NULL || out_enabled == NULL)
        return GAUDIT_BACKEND_ERROR;

    long value = 0;
    int found = 0;
    gaudit_backend_status status = GAUDIT_BACKEND_OK;

    struct dirent **entries = NULL;
    int n = scandir(conf_dir, &entries, filter_entry, compare_entries);
    if (n < 0) {
        if (errno != ENOENT)
            return GAUDIT_BACKEND_ERROR;
        n = 0;
    }
    if (n > MAX_FILES)
        status = GAUDIT_BACKEND_ERROR;

    for (int i = 0; i < n; i++) {
        if (status == GAUDIT_BACKEND_OK) {
            char path[PATH_MAX];
            int len = snprintf(path, sizeof path, "%s/%s", conf_dir, entries[i]->d_name);
            if (len < 0 || (size_t)len >= sizeof path
                || parse_file(path, &value, &found) != 0)
                status = GAUDIT_BACKEND_ERROR;
        }
        free(entries[i]);
    }
    free(entries);

    if (status == GAUDIT_BACKEND_OK && parse_file(conf_file, &value, &found) != 0)
        status = GAUDIT_BACKEND_ERROR;
    if (status != GAUDIT_BACKEND_OK)
        return status;

    *out_enabled = found && value != 0;
    return GAUDIT_BACKEND_OK;
}
