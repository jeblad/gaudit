/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/sourceless.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE 1024

int gaudit_sourceless_format_package(const gaudit_sourceless_package *p, char *buf, size_t len)
{
    char name[160], arch[48], version[128], offered[128];
    if (p == NULL || buf == NULL || p->group < 0 || p->group >= GAUDIT_SOURCELESS_GROUPS
        || gaudit_probe_quote(name, sizeof name, p->name) != 0
        || gaudit_probe_quote(arch, sizeof arch, p->arch) != 0
        || gaudit_probe_quote(version, sizeof version, p->version) != 0
        || gaudit_probe_quote(offered, sizeof offered, p->offered) != 0)
        return -1;
    int n = snprintf(buf, len, "(package (name %s) (arch %s) (version %s) (group %d) (offered %s))\n",
                     name, arch, version, (int)p->group, offered);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_sourceless_format_summary(const gaudit_sourceless_summary *s, char *buf, size_t len)
{
    if (s == NULL || buf == NULL)
        return -1;
    int n = snprintf(buf, len, "(packages (status %d) (count %u) (shown %u))\n",
                     (int)s->status, s->count, s->shown);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_sourceless_parse_line(const char *line, gaudit_sourceless_package *p,
                                 gaudit_sourceless_summary *s)
{
    if (line == NULL || p == NULL || s == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';

    gaudit_sourceless_package pkg;
    memset(&pkg, 0, sizeof pkg);
    long long group;
    const gaudit_sexpr_field fields[] = {
        { .key = "name",    .text = pkg.name,    .text_len = sizeof pkg.name },
        { .key = "arch",    .text = pkg.arch,    .text_len = sizeof pkg.arch },
        { .key = "version", .text = pkg.version, .text_len = sizeof pkg.version },
        { .key = "group",   .value = &group,     .max = GAUDIT_SOURCELESS_GROUPS - 1 },
        { .key = "offered", .text = pkg.offered, .text_len = sizeof pkg.offered },
    };
    if (gaudit_sexpr_parse(copy, "package", fields, sizeof fields / sizeof fields[0]) == 0) {
        if (pkg.name[0] == '\0' || pkg.version[0] == '\0')
            return -1;
        pkg.group = (gaudit_sourceless_group)group;
        *p = pkg;
        return 1;
    }
    long long status, count, shown;
    const gaudit_sexpr_field summary[] = {
        { .key = "status", .value = &status, .max = GAUDIT_SOURCELESS_UNKNOWN },
        { .key = "count",  .value = &count,  .max = 10000000 },
        { .key = "shown",  .value = &shown,  .max = GAUDIT_SOURCELESS_MAX_SHOWN },
    };
    if (gaudit_sexpr_parse(copy, "packages", summary, 3) == 0) {
        if (shown > count)
            return -1;
        s->status = (gaudit_sourceless_status)status;
        s->count = (unsigned)count;
        s->shown = (unsigned)shown;
        return 2;
    }
    return -1;
}
