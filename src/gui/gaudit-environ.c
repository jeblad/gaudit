/* SPDX-License-Identifier: GPL-3.0-only */
#define _POSIX_C_SOURCE 200809L
#include "gaudit-environ.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static char removed[512];

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
    const char *carried = getenv("GAUDIT_REMOVED_ENV");
    if (carried != NULL) {
        snprintf(removed, sizeof removed, "%s", carried);
        unsetenv("GAUDIT_REMOVED_ENV");
    }
    size_t n = 0, bad = 0;
    for (char **e = environ; *e != NULL; e++, n++)
        bad += gaudit_environ_unwanted(*e);
    if (bad == 0)
        return;
    char **clean = calloc(n + 2, sizeof *clean);
    char *list = calloc(1, sizeof CARRIER + 512);
    if (clean == NULL || list == NULL)
        goto unset;
    strcpy(list, CARRIER);
    size_t k = 0;
    for (char **e = environ; *e != NULL; e++) {
        if (!gaudit_environ_unwanted(*e)) {
            clean[k++] = *e;
            continue;
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
