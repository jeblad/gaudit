/* SPDX-License-Identifier: GPL-3.0-only */
#include "secrets.h"

#include "collector.h"
#include "probe-quote.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE 1024

int gaudit_secrets_format_finding(const gaudit_secret_finding *f, char *buf, size_t len)
{
    char path[sizeof f->path * 2 + 3], reason[sizeof f->reason * 2 + 3];
    if (f == NULL || buf == NULL || f->reach < 0 || f->reach >= GAUDIT_SECRET_REACHES
        || f->mode > 07777 || gaudit_probe_quote(path, sizeof path, f->path) != 0
        || gaudit_probe_quote(reason, sizeof reason, f->reason) != 0)
        return -1;
    int n = snprintf(buf, len, "(secret (path %s) (reason %s) (mode %u) (reach %d) (owned %d) (exact %d))\n",
                     path, reason, f->mode, (int)f->reach, f->owned ? 1 : 0, f->exact ? 1 : 0);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_secrets_format_summary(const gaudit_secrets_summary *s, char *buf, size_t len)
{
    if (s == NULL || buf == NULL)
        return -1;
    int n = snprintf(buf, len,
                     "(secrets (status %d) (count %u) (shown %u) (others %u) (groups %u) (truncated %d))\n",
                     (int)s->status, s->count, s->shown, s->others, s->groups, s->truncated ? 1 : 0);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_secrets_parse_line(const char *line, gaudit_secret_finding *f, gaudit_secrets_summary *s)
{
    if (line == NULL || f == NULL || s == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';

    gaudit_secret_finding hit;
    memset(&hit, 0, sizeof hit);
    long long mode, reach, owned, exact;
    const gaudit_sexpr_field fields[] = {
        { .key = "path",   .text = hit.path,   .text_len = sizeof hit.path },
        { .key = "reason", .text = hit.reason, .text_len = sizeof hit.reason },
        { .key = "mode",   .value = &mode,     .max = 07777 },
        { .key = "reach",  .value = &reach,    .max = GAUDIT_SECRET_REACHES - 1 },
        { .key = "owned",  .value = &owned,    .max = 1 },
        { .key = "exact",  .value = &exact,    .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "secret", fields, sizeof fields / sizeof fields[0]) == 0) {
        /* Relative to home, never leaving it. */
        if (hit.path[0] == '\0' || hit.path[0] == '/' || hit.reason[0] == '\0'
            || strcmp(hit.path, "..") == 0 || strncmp(hit.path, "../", 3) == 0
            || strstr(hit.path, "/../") != NULL)
            return -1;
        hit.mode = (unsigned)mode;
        hit.reach = (gaudit_secret_reach)reach;
        hit.owned = (int)owned;
        hit.exact = (int)exact;
        *f = hit;
        return 1;
    }
    long long status, count, shown, others, groups, truncated;
    const gaudit_sexpr_field summary[] = {
        { .key = "status",    .value = &status,    .max = GAUDIT_SECRETS_UNKNOWN },
        { .key = "count",     .value = &count,     .max = 10000000 },
        { .key = "shown",     .value = &shown,     .max = GAUDIT_SECRETS_MAX_SHOWN },
        { .key = "others",    .value = &others,    .max = 10000000 },
        { .key = "groups",    .value = &groups,    .max = 10000000 },
        { .key = "truncated", .value = &truncated, .max = 1 },
    };
    if (gaudit_sexpr_parse(copy, "secrets", summary, sizeof summary / sizeof summary[0]) == 0) {
        if (shown > count || others + groups > count)
            return -1;
        *s = (gaudit_secrets_summary){
            .status = (gaudit_secrets_status)status, .count = (unsigned)count,
            .shown = (unsigned)shown, .others = (unsigned)others, .groups = (unsigned)groups,
            .truncated = (int)truncated,
        };
        return 2;
    }
    return -1;
}

gaudit_verdict gaudit_secrets_verdict(const gaudit_secrets_summary *s)
{
    if (s == NULL || s->status != GAUDIT_SECRETS_OK)
        return GAUDIT_VERDICT_UNKNOWN;
    if (s->others + s->groups > 0)
        return GAUDIT_VERDICT_WARNING;
    if (s->truncated)
        return GAUDIT_VERDICT_UNKNOWN;
    return GAUDIT_VERDICT_OK;
}
