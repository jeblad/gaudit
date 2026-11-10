/* SPDX-License-Identifier: GPL-3.0-only */
/* Probe results over the pipe between orchestrator and GUI: one line per
 * result, parsed strictly on the receiving side. */
#include "gaudit/probe.h"

#include "collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_COUNT 100000000LL
#define MAX_EPOCH 32503680000LL  /* year 3000 */
#define MAX_LINE  1024

/* Text as a quoted string: \" and \\ escaped, other non-printable bytes
 * replaced, so the receiving parser always accepts it. */
static int quote(char *out, size_t len, const char *text)
{
    size_t o = 0;
    if (len < 3)
        return -1;
    out[o++] = '"';
    for (const char *p = text; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            if (o + 2 >= len)
                return -1;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else {
            if (o + 1 >= len)
                return -1;
            out[o++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
        }
    }
    if (o + 2 > len)
        return -1;
    out[o++] = '"';
    out[o] = '\0';
    return 0;
}

int gaudit_probe_format(const gaudit_probe_result *r, char *buf, size_t len)
{
    char missing[80], detail[80], text[160];
    if (r == NULL || buf == NULL
        || quote(missing, sizeof missing, r->missing_capability) != 0
        || quote(detail, sizeof detail, r->detail) != 0
        || quote(text, sizeof text, r->text) != 0)
        return -1;
    int n = snprintf(buf, len,
                     "(probe (kind %d) (verdict %d) (applicable %d) (unsupported %d)"
                     " (age %lld) (count %u) (extra %u) (info %u) (mask %u) (until %lld)"
                     " (down %d) (missing %s) (detail %s) (text %s))\n",
                     (int)r->kind, (int)r->verdict, r->applicable ? 1 : 0, r->unsupported ? 1 : 0,
                     (long long)r->age_seconds, r->count, r->extra_count, r->info_count, r->mask,
                     (long long)r->until_epoch, r->service_down ? 1 : 0, missing, detail, text);
    return n > 0 && (size_t)n < len ? 0 : -1;
}

static int parse_one(const char *line, gaudit_probe_result *out)
{
    long long kind, verdict, applicable, unsupported, age, count, extra, info, mask, until, down;
    gaudit_probe_result r;
    memset(&r, 0, sizeof r);
    const gaudit_sexpr_field fields[] = {
        { .key = "kind",        .value = &kind,        .max = GAUDIT_PROBE_COUNT - 1 },
        { .key = "verdict",     .value = &verdict,     .max = GAUDIT_VERDICT_CRITICAL },
        { .key = "applicable",  .value = &applicable,  .max = 1 },
        { .key = "unsupported", .value = &unsupported, .max = 1 },
        { .key = "age",         .value = &age,         .max = MAX_EPOCH, .min = -1 },
        { .key = "count",       .value = &count,       .max = MAX_COUNT },
        { .key = "extra",       .value = &extra,       .max = MAX_COUNT },
        { .key = "info",        .value = &info,        .max = MAX_COUNT },
        { .key = "mask",        .value = &mask,        .max = (1LL << GAUDIT_PKGSYS_COUNT) - 1 },
        { .key = "until",       .value = &until,       .max = MAX_EPOCH },
        { .key = "down",        .value = &down,        .max = 1 },
        { .key = "missing",     .text = r.missing_capability, .text_len = sizeof r.missing_capability },
        { .key = "detail",      .text = r.detail,             .text_len = sizeof r.detail },
        { .key = "text",        .text = r.text,               .text_len = sizeof r.text },
    };
    if (gaudit_sexpr_parse(line, "probe", fields, sizeof fields / sizeof fields[0]) != 0)
        return -1;
    r.kind = (gaudit_probe_kind)kind;
    r.id = gaudit_probe_id(r.kind);
    r.verdict = (gaudit_verdict)verdict;
    r.applicable = (int)applicable;
    r.unsupported = (int)unsupported;
    r.age_seconds = age;
    r.count = (unsigned)count;
    r.extra_count = (unsigned)extra;
    r.info_count = (unsigned)info;
    r.mask = (unsigned)mask;
    r.until_epoch = until;
    r.service_down = (int)down;
    *out = r;
    return 0;
}

int gaudit_probe_parse_all(const char *text, gaudit_probe_result out[GAUDIT_PROBE_COUNT])
{
    if (text == NULL || out == NULL)
        return -1;
    int seen[GAUDIT_PROBE_COUNT] = { 0 };
    int n = 0;
    const char *p = text;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t len = nl != NULL ? (size_t)(nl - p) : strlen(p);
        if (len >= MAX_LINE)
            return -1;
        char line[MAX_LINE];
        memcpy(line, p, len);
        line[len] = '\0';
        p += len + (nl != NULL ? 1 : 0);
        if (len == 0)
            continue;  /* blank line */

        gaudit_probe_result r;
        if (parse_one(line, &r) != 0 || seen[r.kind])
            return -1;  /* malformed, or a kind repeated */
        seen[r.kind] = 1;
        out[r.kind] = r;
        n++;
    }
    return n == GAUDIT_PROBE_COUNT ? 0 : -1;  /* every kind exactly once */
}
