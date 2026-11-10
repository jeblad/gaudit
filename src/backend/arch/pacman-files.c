/* SPDX-License-Identifier: GPL-3.0-only */
#include "pacman-files.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILE_SIZE (256 * 1024)

static int join(char *buf, size_t len, const char *root, const char *path)
{
    int n = snprintf(buf, len, "%s%s", root != NULL ? root : "", path);
    return n >= 0 && (size_t)n < len;
}

int gaudit_arch_present(const char *root)
{
    char local[PATH_MAX], pacman[PATH_MAX];
    if (!join(local, sizeof local, root, "/var/lib/pacman/local")
        || !join(pacman, sizeof pacman, root, "/usr/bin/pacman")
        || access(pacman, X_OK) != 0)
        return 0;
    DIR *dir = opendir(local);
    if (dir == NULL)
        return 0;
    int found = 0;
    struct dirent *de;
    while (!found && (de = readdir(dir)) != NULL)
        found = de->d_name[0] != '.' && strcmp(de->d_name, "ALPM_DB_VERSION") != 0;
    closedir(dir);
    return found;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t len = strlen(s), slen = strlen(suffix);
    return len >= slen && strcmp(s + len - slen, suffix) == 0;
}

gaudit_backend_status gaudit_pacman_sync_time(const char *sync_dir, int64_t *out_epoch)
{
    if (sync_dir == NULL || out_epoch == NULL)
        return GAUDIT_BACKEND_ERROR;
    DIR *dir = opendir(sync_dir);
    if (dir == NULL)
        return errno == ENOENT ? GAUDIT_BACKEND_UNAVAILABLE : GAUDIT_BACKEND_ERROR;
    int64_t newest = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (!ends_with(de->d_name, ".db"))
            continue;
        char path[PATH_MAX];
        struct stat st;
        int n = snprintf(path, sizeof path, "%s/%s", sync_dir, de->d_name);
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

/* Append word to a NUL-separated list; -1 if it does not fit. */
static int list_add(char *list, size_t len, size_t *used, const char *word, size_t wlen)
{
    if (*used + wlen + 2 > len)
        return -1;
    memcpy(list + *used, word, wlen);
    *used += wlen;
    list[(*used)++] = '\0';
    list[*used] = '\0';
    return 0;
}

gaudit_backend_status gaudit_pacman_conf(const char *path,
                                         char *repos, size_t repos_len,
                                         char *ignore, size_t ignore_len)
{
    if (path == NULL || repos == NULL || repos_len < 2 || ignore == NULL || ignore_len < 2)
        return GAUDIT_BACKEND_ERROR;
    repos[0] = repos[1] = '\0';
    ignore[0] = ignore[1] = '\0';

    FILE *f = fopen(path, "re");
    if (f == NULL)
        return errno == ENOENT ? GAUDIT_BACKEND_UNAVAILABLE : GAUDIT_BACKEND_ERROR;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > MAX_FILE_SIZE) {
        fclose(f);
        return GAUDIT_BACKEND_ERROR;
    }

    size_t repos_used = 0, ignore_used = 0;
    int in_options = 0, rc = 0;
    char line[1024];
    while (rc == 0 && fgets(line, sizeof line, f) != NULL) {
        char *s = line;
        while (isspace((unsigned char)*s))
            s++;
        char *hash = strchr(s, '#');
        if (hash != NULL)
            *hash = '\0';
        size_t len = strlen(s);
        while (len > 0 && isspace((unsigned char)s[len - 1]))
            s[--len] = '\0';
        if (len == 0)
            continue;

        if (s[0] == '[') {
            if (s[len - 1] != ']' || len < 3) {
                rc = -1;
                break;
            }
            in_options = len == 9 && strncmp(s, "[options]", 9) == 0;
            if (!in_options)
                rc = list_add(repos, repos_len, &repos_used, s + 1, len - 2);
            continue;
        }

        if (in_options && strncmp(s, "IgnorePkg", 9) == 0) {
            char *eq = strchr(s, '=');
            if (eq == NULL)
                continue;
            for (char *w = strtok(eq + 1, " \t"); w != NULL && rc == 0; w = strtok(NULL, " \t"))
                rc = list_add(ignore, ignore_len, &ignore_used, w, strlen(w));
        }
    }
    fclose(f);
    return rc == 0 ? GAUDIT_BACKEND_OK : GAUDIT_BACKEND_ERROR;
}
