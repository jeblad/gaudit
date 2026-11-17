/* SPDX-License-Identifier: GPL-3.0-only */
#define _DEFAULT_SOURCE
#include "gaudit-environ.h"

#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

/* Variables that make the dynamic loader, GTK, GIO, GDK Pixbuf, GStreamer,
 * GSettings, GObject introspection or iconv load code or modules from a
 * place of the caller's choosing, or open GTK's inspector. GTK_IM_MODULE
 * stays: it picks among the input methods installed, and people need it to
 * type Chinese or Japanese. */
static const char *const names[] = {
    "GTK_MODULES", "GTK3_MODULES", "GTK_PATH", "GTK_EXE_PREFIX", "GTK_DATA_PREFIX",
    "GTK_DEBUG", "GTK_IM_MODULE_FILE", "GIO_EXTRA_MODULES", "GIO_MODULE_DIR",
    "GDK_PIXBUF_MODULE_FILE", "GDK_PIXBUF_MODULEDIR", "GSETTINGS_BACKEND", "GSETTINGS_SCHEMA_DIR",
    "GI_TYPELIB_PATH", "GCONV_PATH", "GST_PLUGIN_PATH", "GST_PLUGIN_PATH_1_0",
    "GST_PLUGIN_SYSTEM_PATH", "GST_PLUGIN_SYSTEM_PATH_1_0",
};

#define CARRIER "GAUDIT_REMOVED_ENV="
/* Each removed variable, "NAME=value", to the new start as
 * GAUDIT_REMOVED_<n>=NAME=value. */
#define ENTRY_PREFIX "GAUDIT_REMOVED_"
#define MAX_VALUE    4096

static char removed[512];
static char *entries[GAUDIT_ENVIRON_MAX];
static size_t n_entries;

/* GAUDIT_REMOVED_<digits>=...: a carried entry (not the names' CARRIER). */
static int is_carried(const char *entry)
{
    return strncmp(entry, ENTRY_PREFIX, sizeof ENTRY_PREFIX - 1) == 0
           && entry[sizeof ENTRY_PREFIX - 1] >= '0' && entry[sizeof ENTRY_PREFIX - 1] <= '9';
}

static void keep_entry(const char *entry)
{
    if (n_entries >= GAUDIT_ENVIRON_MAX)
        return;
    size_t len = strnlen(entry, MAX_VALUE);
    char *copy = malloc(len + 1);
    if (copy == NULL)
        return;
    memcpy(copy, entry, len);
    copy[len] = '\0';
    entries[n_entries++] = copy;
}

int gaudit_environ_unwanted(const char *entry)
{
    if (entry == NULL)
        return 0;
    size_t n = strcspn(entry, "=");
    if (n >= 3 && strncmp(entry, "LD_", 3) == 0)
        return 1;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (strlen(names[i]) == n && strncmp(entry, names[i], n) == 0)
            return 1;
    return 0;
}

void gaudit_environ_clean(char *argv[])
{
    /* What an earlier start removed, carried here by it; never passed on. */
    size_t n = 0, bad = 0;
    for (char **e = environ; *e != NULL; e++, n++)
        bad += gaudit_environ_unwanted(*e);
    if (bad == 0) {
        /* This is the new start (or one given them by hand, which can only
         * show a warning that is not true): take them in, never pass on. */
        const char *carried = getenv("GAUDIT_REMOVED_ENV");
        if (carried != NULL)
            snprintf(removed, sizeof removed, "%s", carried);
        for (int again = 1; again;) {
            again = 0;
            for (char **e = environ; *e != NULL; e++) {
                if (!is_carried(*e) && strncmp(*e, CARRIER, sizeof CARRIER - 1) != 0)
                    continue;
                char name[64];
                size_t nl = strcspn(*e, "=");
                snprintf(name, sizeof name, "%.*s", (int)nl, *e);
                if (is_carried(*e) && gaudit_environ_unwanted(*e + nl + 1))
                    keep_entry(*e + nl + 1);
                unsetenv(name);
                again = 1;
                break;
            }
        }
        return;
    }
    char **clean = calloc(n + 2 + GAUDIT_ENVIRON_MAX, sizeof *clean);
    char *list = calloc(1, sizeof CARRIER + 512);
    if (clean == NULL || list == NULL)
        goto unset;
    strcpy(list, CARRIER);
    size_t k = 0, carried = 0;
    for (char **e = environ; *e != NULL; e++) {
        if (is_carried(*e) || strncmp(*e, CARRIER, sizeof CARRIER - 1) == 0)
            continue;  /* given by the caller: never trusted, never passed on */
        if (!gaudit_environ_unwanted(*e)) {
            clean[k++] = *e;
            continue;
        }
        if (carried < GAUDIT_ENVIRON_MAX) {
            size_t vl = strnlen(*e, MAX_VALUE);
            char *c = malloc(sizeof ENTRY_PREFIX + 4 + vl + 1);
            if (c != NULL) {
                snprintf(c, sizeof ENTRY_PREFIX + 4 + vl + 1, "%s%zu=%.*s", ENTRY_PREFIX, carried,
                         (int)vl, *e);
                clean[k++] = c;
                carried++;
            }
        }
        size_t used = strlen(list), name = strcspn(*e, "=");
        if (used + name + 3 < sizeof CARRIER + 512)
            snprintf(list + used, sizeof CARRIER + 512 - used, "%s%.*s",
                     used > sizeof CARRIER - 1 ? ", " : "", (int)name, *e);
    }
    clean[k++] = list;
    clean[k] = NULL;
    execve("/proc/self/exe", argv, clean);
unset:
    /* Could not start again: take them out of this start at least. */
    for (int again = 1; again;) {
        again = 0;
        for (char **e = environ; *e != NULL; e++)
            if (gaudit_environ_unwanted(*e)) {
                keep_entry(*e);
                char name[256];
                snprintf(name, sizeof name, "%.*s", (int)strcspn(*e, "="), *e);
                size_t used = strlen(removed);
                snprintf(removed + used, sizeof removed - used, "%s%s", used > 0 ? ", " : "", name);
                unsetenv(name);
                again = 1;
                break;
            }
    }
    free(clean);
    free(list);
}

const char *gaudit_environ_removed(void)
{
    return removed[0] != '\0' ? removed : NULL;
}

size_t gaudit_environ_removed_count(void)
{
    return n_entries;
}

const char *gaudit_environ_removed_entry(size_t i)
{
    return i < n_entries ? entries[i] : NULL;
}

/* --- What a removed variable pointed to ------------------------------------ */

gaudit_env_kind gaudit_environ_kind(const char *name)
{
    static const char *const paths[] = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GTK_PATH", "GTK_EXE_PREFIX",
        "GTK_DATA_PREFIX", "GTK_IM_MODULE_FILE", "GIO_EXTRA_MODULES", "GIO_MODULE_DIR",
        "GDK_PIXBUF_MODULE_FILE", "GDK_PIXBUF_MODULEDIR", "GSETTINGS_SCHEMA_DIR",
        "GI_TYPELIB_PATH", "GCONV_PATH", "GST_PLUGIN_PATH", "GST_PLUGIN_PATH_1_0",
        "GST_PLUGIN_SYSTEM_PATH", "GST_PLUGIN_SYSTEM_PATH_1_0",
    };
    for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++)
        if (strcmp(name, paths[i]) == 0)
            return GAUDIT_ENV_PATHS;
    if (strcmp(name, "GTK_MODULES") == 0 || strcmp(name, "GTK3_MODULES") == 0)
        return GAUDIT_ENV_MODULES;
    return GAUDIT_ENV_OTHER;
}

static int group_has_members(gid_t gid)
{
    struct group *gr = getgrgid(gid);
    if (gr != NULL && gr->gr_mem != NULL && gr->gr_mem[0] != NULL)
        return 1;
    int found = 0;
    setpwent();
    for (struct passwd *pw; !found && (pw = getpwent()) != NULL;)
        found = pw->pw_gid == gid;
    endpwent();
    return found;
}

void gaudit_environ_group_members(gid_t group, char *buf, size_t len)
{
    size_t used = 0;
    buf[0] = '\0';
    struct group *gr = getgrgid(group);
    for (char **m = gr != NULL ? gr->gr_mem : NULL; m != NULL && *m != NULL && used + 1 < len; m++)
        used += (size_t)snprintf(buf + used, len - used, "%s%s", used > 0 ? ", " : "", *m);
    setpwent();
    for (struct passwd *pw; used + 1 < len && (pw = getpwent()) != NULL;)
        if (pw->pw_gid == group && strstr(buf, pw->pw_name) == NULL)
            used += (size_t)snprintf(buf + used, len - used, "%s%s", used > 0 ? ", " : "", pw->pw_name);
    endpwent();
}

/* One existing folder or file on the way: who besides root can change it.
 * A link itself is not judged: the folder it sits in decides whether it
 * can be replaced, and where it leads is judged on its own. */
static int judge_one(const char *path, gaudit_env_judgement *out)
{
    struct stat st;
    if (lstat(path, &st) != 0 || S_ISLNK(st.st_mode))
        return 0;
    gaudit_env_reach r = GAUDIT_ENV_ROOT_ONLY;
    if (st.st_uid != 0)
        r = GAUDIT_ENV_OWNER;
    else if (st.st_mode & S_IWOTH)
        r = GAUDIT_ENV_OTHERS;
    else if ((st.st_mode & S_IWGRP) && st.st_gid != 0 && group_has_members(st.st_gid))
        r = GAUDIT_ENV_GROUP;
    if (r == GAUDIT_ENV_ROOT_ONLY)
        return 0;
    out->reach = r;
    out->owner = st.st_uid;
    out->group = st.st_gid;
    snprintf(out->where, sizeof out->where, "%s", path);
    return 1;
}

/* Every folder from '/' down to path, and path itself, as far as they
 * exist: what does not exist yet can only be made by whoever can write
 * the last folder that does. Returns that last existing prefix in last. */
static int judge_chain(const char *path, gaudit_env_judgement *out, char *last, size_t last_len)
{
    char prefix[PATH_MAX];
    snprintf(last, last_len, "/");
    if (judge_one("/", out))
        return 1;
    for (size_t i = 1; path[i - 1] != '\0'; i++) {
        if (path[i] != '/' && path[i] != '\0')
            continue;
        if (i >= sizeof prefix)
            return 0;
        memcpy(prefix, path, i);
        prefix[i] = '\0';
        struct stat st;
        if (lstat(prefix, &st) != 0)
            return 0;
        snprintf(last, last_len, "%s", prefix);
        if (judge_one(prefix, out))
            return 1;
        if (path[i] == '\0')
            break;
    }
    return 0;
}

void gaudit_environ_judge_path(const char *path, gaudit_env_judgement *out)
{
    memset(out, 0, sizeof *out);
    if (path == NULL || path[0] != '/') {
        out->reach = path == NULL || path[0] == '\0' ? GAUDIT_ENV_EMPTY : GAUDIT_ENV_RELATIVE;
        snprintf(out->where, sizeof out->where, "%s", path != NULL ? path : "");
        return;
    }
    char last[PATH_MAX];
    if (judge_chain(path, out, last, sizeof last))
        return;
    /* And where its links really lead. */
    char real[PATH_MAX];
    if (realpath(last, real) != NULL && strcmp(real, last) != 0)
        judge_chain(real, out, last, sizeof last);
}
