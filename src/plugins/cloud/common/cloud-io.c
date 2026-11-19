/* SPDX-License-Identifier: GPL-3.0-only */
#include "cloud.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE 2048

/* A client or service id: [a-z-], not empty. */
static int plain_id(const char *s)
{
    if (*s == '\0')
        return 0;
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || *c == '-'))
            return 0;
    return 1;
}

/* "", "~/..." or absolute. */
static int plain_where(const char *s)
{
    return s[0] == '\0' || s[0] == '/' || strncmp(s, "~/", 2) == 0;
}

int gaudit_cloud_format_folder(const gaudit_cloud_line *f, char *buf, size_t len)
{
    char path[sizeof f->path * 2 + 3], name[sizeof f->name * 2 + 3];
    if (!plain_id(f->client) || !plain_id(f->service) || f->how < 0 || f->how > 4
        || !plain_where(f->path) || gaudit_probe_quote(path, sizeof path, f->path) != 0
        || gaudit_probe_quote(name, sizeof name, f->name) != 0)
        return -1;
    int n = snprintf(buf, len,
                     "(cloud-folder (client \"%s\") (service \"%s\") (how %d) (path %s) (name %s)"
                     " (encrypted %d) (gathered %d))\n",
                     f->client, f->service, f->how, path, name, f->encrypted ? 1 : 0,
                     f->gathered ? 1 : 0);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_cloud_format_end(const gaudit_cloud_end *e, char *buf, size_t len)
{
    char g[sizeof e->gathering * 2 + 3];
    if (!plain_where(e->gathering) || gaudit_probe_quote(g, sizeof g, e->gathering) != 0)
        return -1;
    int n = snprintf(buf, len,
                     "(cloud-end (count %u) (more %d) (gathering %s) (gatherings %u)"
                     " (rclone-unreadable %d))\n",
                     e->count, e->more ? 1 : 0, g, e->gatherings, e->rclone_unreadable ? 1 : 0);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_cloud_parse_line(const char *line, gaudit_cloud_line *f, gaudit_cloud_end *e)
{
    if (line == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';
    long long how, enc, gath, count, more, gs, unread;
    gaudit_cloud_line ff = { 0 };
    const gaudit_sexpr_field folder[] = {
        { .key = "client", .text = ff.client, .text_len = sizeof ff.client },
        { .key = "service", .text = ff.service, .text_len = sizeof ff.service },
        { .key = "how", .value = &how, .max = 4 },
        { .key = "path", .text = ff.path, .text_len = sizeof ff.path },
        { .key = "name", .text = ff.name, .text_len = sizeof ff.name },
        { .key = "encrypted", .value = &enc, .max = 1 },
        { .key = "gathered", .value = &gath, .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "cloud-folder", folder, 7) == 0) {
        if (!plain_id(ff.client) || !plain_id(ff.service) || !plain_where(ff.path))
            return -1;
        ff.how = (int)how;
        ff.encrypted = (int)enc;
        ff.gathered = (int)gath;
        if (f != NULL)
            *f = ff;
        return 1;
    }
    gaudit_cloud_end ee = { 0 };
    const gaudit_sexpr_field end[] = {
        { .key = "count", .value = &count, .max = 1000 },
        { .key = "more", .value = &more, .max = 1 },
        { .key = "gathering", .text = ee.gathering, .text_len = sizeof ee.gathering },
        { .key = "gatherings", .value = &gs, .max = 100 },
        { .key = "rclone-unreadable", .value = &unread, .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "cloud-end", end, 5) == 0) {
        if (!plain_where(ee.gathering))
            return -1;
        ee.count = (unsigned)count;
        ee.more = (int)more;
        ee.gatherings = (unsigned)gs;
        ee.rclone_unreadable = (int)unread;
        if (e != NULL)
            *e = ee;
        return 2;
    }
    return -1;
}
