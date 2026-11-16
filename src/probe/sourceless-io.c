/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/sourceless.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE 2048  /* a package with its details */

int gaudit_sourceless_format_package(const gaudit_sourceless_package *p, char *buf, size_t len)
{
    char name[160], arch[48], version[128], offered[128], replaced[128], needed[160], built[48],
        likely[160];
    if (p == NULL || buf == NULL || p->group < 0 || p->group >= GAUDIT_SOURCELESS_GROUPS
        || p->needed_by < -1 || p->manual < -1 || p->manual > 1 || p->installed < 0
        || p->program < -1 || p->program > 1
        || gaudit_probe_quote(name, sizeof name, p->name) != 0
        || gaudit_probe_quote(arch, sizeof arch, p->arch) != 0
        || gaudit_probe_quote(version, sizeof version, p->version) != 0
        || gaudit_probe_quote(offered, sizeof offered, p->offered) != 0
        || gaudit_probe_quote(replaced, sizeof replaced, p->replaced) != 0
        || gaudit_probe_quote(needed, sizeof needed, p->needed) != 0
        || gaudit_probe_quote(built, sizeof built, p->built_for) != 0
        || gaudit_probe_quote(likely, sizeof likely, p->likely_source) != 0)
        return -1;
    int n = snprintf(buf, len, "(package (name %s) (arch %s) (version %s) (group %d) (offered %s)"
                     " (replaced %s) (needed-by %d) (needed %s) (manual %d) (installed %lld)"
                     " (program %d) (built-for %s) (likely-source %s))\n",
                     name, arch, version, (int)p->group, offered, replaced, p->needed_by, needed,
                     p->manual, p->installed, p->program, built, likely);
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
    long long group, needed_by, manual, installed, program;
    const gaudit_sexpr_field fields[] = {
        { .key = "name",      .text = pkg.name,     .text_len = sizeof pkg.name },
        { .key = "arch",      .text = pkg.arch,     .text_len = sizeof pkg.arch },
        { .key = "version",   .text = pkg.version,  .text_len = sizeof pkg.version },
        { .key = "group",     .value = &group,      .max = GAUDIT_SOURCELESS_GROUPS - 1 },
        { .key = "offered",   .text = pkg.offered,  .text_len = sizeof pkg.offered },
        { .key = "replaced",  .text = pkg.replaced, .text_len = sizeof pkg.replaced },
        { .key = "needed-by", .value = &needed_by,  .min = -1, .max = 10000000 },
        { .key = "needed",    .text = pkg.needed,   .text_len = sizeof pkg.needed },
        { .key = "manual",    .value = &manual,     .min = -1, .max = 1 },
        { .key = "installed", .value = &installed,  .max = 32503680000LL },
        { .key = "program",   .value = &program,    .min = -1, .max = 1 },
        { .key = "built-for", .text = pkg.built_for, .text_len = sizeof pkg.built_for },
        { .key = "likely-source", .text = pkg.likely_source, .text_len = sizeof pkg.likely_source },
    };
    if (gaudit_sexpr_parse(copy, "package", fields, sizeof fields / sizeof fields[0]) == 0) {
        if (pkg.name[0] == '\0' || pkg.version[0] == '\0')
            return -1;
        pkg.group = (gaudit_sourceless_group)group;
        pkg.needed_by = (int)needed_by;
        pkg.manual = (int)manual;
        pkg.installed = installed;
        pkg.program = (int)program;
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
