/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "gaudit/backend.h"

#include <stddef.h>
#include <string.h>
#include <unistd.h>

#if GAUDIT_DEVELOPER_BUILD
static char pretend[256];

int gaudit_capability_pretend_missing(const char *ids)
{
    if (ids == NULL || strlen(ids) >= sizeof pretend)
        return -1;
    for (const char *c = ids; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-' || *c == ','))
            return -1;
    strcpy(pretend, ids);
    return 0;
}

const char *gaudit_capability_pretended(void)
{
    return pretend;
}

static int pretended_missing(const char *id)
{
    size_t n = id != NULL ? strlen(id) : 0;
    if (n == 0)
        return 0;
    for (const char *p = pretend; *p != '\0';) {
        const char *end = strchr(p, ',');
        size_t len = end != NULL ? (size_t)(end - p) : strlen(p);
        if (len == n && memcmp(p, id, n) == 0)
            return 1;
        p += len + (end != NULL);
    }
    return 0;
}
#endif

int gaudit_capability_present(const gaudit_capability *cap)
{
    if (cap == NULL || cap->paths == NULL || cap->paths[0] == NULL)
        return 0;
#if GAUDIT_DEVELOPER_BUILD
    if (pretended_missing(cap->id))
        return 0;
#endif
    for (const char *const *p = cap->paths; *p != NULL; p++)
        if (access(*p, X_OK) != 0)
            return 0;
    return 1;
}
