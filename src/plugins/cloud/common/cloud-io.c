/* SPDX-License-Identifier: GPL-3.0-only */
#include "cloud.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
    char path[sizeof f->path * 2 + 3], name[sizeof f->name * 2 + 3], via[sizeof f->via * 2 + 3];
    if (!plain_id(f->client) || !plain_id(f->service) || f->how < 0 || f->how > 4
        || !plain_where(f->path) || gaudit_probe_quote(path, sizeof path, f->path) != 0
        || gaudit_probe_quote(name, sizeof name, f->name) != 0
        || gaudit_probe_quote(via, sizeof via, f->via) != 0)
        return -1;
    int n = snprintf(buf, len,
                     "(cloud-folder (client \"%s\") (service \"%s\") (how %d) (path %s) (name %s)"
                     " (encrypted %d) (via %s) (gathered %d))\n",
                     f->client, f->service, f->how, path, name, f->encrypted ? 1 : 0, via,
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
        { .key = "via", .text = ff.via, .text_len = sizeof ff.via },
        { .key = "gathered", .value = &gath, .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "cloud-folder", folder, 8) == 0) {
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

int gaudit_cloud_format_unit(const gaudit_cloud_unit_line *u, char *buf, size_t len)
{
    char file[sizeof u->file * 2 + 3], path[sizeof u->path * 2 + 3];
    if (!plain_where(u->path) || gaudit_probe_quote(file, sizeof file, u->file) != 0
        || gaudit_probe_quote(path, sizeof path, u->path) != 0)
        return -1;
    int n = snprintf(buf, len, "(cloud-unit (file %s) (path %s) (enabled %d) (mounted %d))\n",
                     file, path, u->enabled ? 1 : 0, u->mounted ? 1 : 0);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_cloud_parse_unit(const char *line, gaudit_cloud_unit_line *u)
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
    long long en, mo;
    gaudit_cloud_unit_line uu = { 0 };
    const gaudit_sexpr_field unit[] = {
        { .key = "file", .text = uu.file, .text_len = sizeof uu.file },
        { .key = "path", .text = uu.path, .text_len = sizeof uu.path },
        { .key = "enabled", .value = &en, .max = 1 },
        { .key = "mounted", .value = &mo, .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "cloud-unit", unit, 4) != 0 || strncmp(uu.file, "rclone-", 7) != 0
        || strchr(uu.file, '/') != NULL || !plain_where(uu.path))
        return -1;
    uu.enabled = (int)en;
    uu.mounted = (int)mo;
    if (u != NULL)
        *u = uu;
    return 3;
}

/* --- The services the rclone page can set up -------------------------------- */

const gaudit_cloud_setup_service gaudit_cloud_setup_services[] = {
    /* rclone.org/jottacloud (2026-11-19): a single-use personal login token,
     * traded by rclone config; rclone authorize is not supported. */
    { "jottacloud", "Jottacloud", "jottacloud", "https://www.jottacloud.com/web/secure", "jotta" },
};
const unsigned gaudit_cloud_setup_services_count =
    sizeof gaudit_cloud_setup_services / sizeof gaudit_cloud_setup_services[0];

const gaudit_cloud_setup_service *gaudit_cloud_setup_find(const char *id)
{
    for (unsigned i = 0; id != NULL && i < gaudit_cloud_setup_services_count; i++)
        if (strcmp(gaudit_cloud_setup_services[i].id, id) == 0)
            return &gaudit_cloud_setup_services[i];
    return NULL;
}

int gaudit_cloud_plain_remote(const char *name)
{
    size_t n = name != NULL ? strlen(name) : 0;
    if (n == 0 || n > 64 || name[0] == '-' || name[0] == '.')
        return 0;
    for (const char *c = name; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9')
              || *c == '_' || *c == '-' || *c == '.'))
            return 0;
    return 1;
}

void gaudit_cloud_unit_name(const gaudit_cloud_setup_service *s, char *out, size_t len)
{
    snprintf(out, len, "rclone-%s.service", s->id);
}

int gaudit_cloud_unit_text(const gaudit_cloud_setup_service *s, const char *remote, char *out,
                           size_t len)
{
    if (s == NULL || !gaudit_cloud_plain_remote(remote))
        return -1;
    const char *fusermount = access("/usr/bin/fusermount3", X_OK) == 0 ? "/usr/bin/fusermount3"
                                                                        : "/usr/bin/fusermount";
    int n = snprintf(out, len,
                     "# Made by gAudit: mounts %s at each login. Remove it with\n"
                     "# systemctl --user disable --now rclone-%s.service, then delete this file.\n"
                     "[Unit]\n"
                     "Description=rclone mount of %s at ~/Cloud/%s\n"
                     "\n"
                     "[Service]\n"
                     "Type=notify\n"
                     "ExecStartPre=/usr/bin/mkdir -p %%h/Cloud/%s\n"
                     "ExecStartPre=/usr/bin/chmod 0700 %%h/Cloud/%s\n"
                     "ExecStart=/usr/bin/rclone mount %s: %%h/Cloud/%s --volname %s --umask 077 "
                     "--vfs-cache-mode full --dir-cache-time 1h\n"
                     "ExecStop=%s -u %%h/Cloud/%s\n"
                     "# Read-only whenever nothing is mounted, so nothing is saved there by mistake.\n"
                     "ExecStopPost=-/usr/bin/chmod 0500 %%h/Cloud/%s\n"
                     "Restart=on-failure\n"
                     "RestartSec=30\n"
                     "\n"
                     "[Install]\n"
                     "WantedBy=default.target\n",
                     s->name, s->id, s->name, s->name, s->name, s->name, remote, s->name, s->name,
                     fusermount, s->name, s->name);
    return n > 0 && (size_t)n < len ? 0 : -1;
}
