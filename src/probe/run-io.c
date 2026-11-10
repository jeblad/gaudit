/* SPDX-License-Identifier: GPL-3.0-only */
#include "gaudit/run.h"

#include "collector.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE  1024
#define MAX_COUNT 100000000LL

gaudit_verdict gaudit_firewall_verdict(const gaudit_firewall_report *r)
{
    if (r == NULL)
        return GAUDIT_VERDICT_UNKNOWN;
    if (r->input_chains > 0 && (r->input_drop > 0 || r->input_rules > 0))
        return GAUDIT_VERDICT_OK;
    if (r->legacy > 0)
        return GAUDIT_VERDICT_UNKNOWN;
    return GAUDIT_VERDICT_WARNING;
}

int gaudit_run_format(const gaudit_run_event *ev, char *buf, size_t len)
{
    if (ev == NULL || buf == NULL)
        return -1;
    int n;
    const gaudit_firewall_report *f = &ev->firewall;
    switch (ev->type) {
    case GAUDIT_RUN_EVENT_ELEVATED:
        n = snprintf(buf, len, "(elevated (on %d))\n", ev->elevated ? 1 : 0);
        break;
    case GAUDIT_RUN_EVENT_FIREWALL:
        n = snprintf(buf, len,
                     "(firewall (verdict %d) (tables %u) (input-chains %u) (input-drop %u)"
                     " (input-rules %u) (rules %u) (legacy %u) (listening %u))\n",
                     (int)f->verdict, f->tables, f->input_chains, f->input_drop,
                     f->input_rules, f->rules, f->legacy, f->listening);
        break;
    case GAUDIT_RUN_EVENT_END:
        n = snprintf(buf, len, "(end (status %d))\n", (int)ev->status);
        break;
    default:
        return -1;
    }
    return n > 0 && (size_t)n < len ? 0 : -1;
}

int gaudit_run_parse_line(const char *line, gaudit_run_event *out)
{
    if (line == NULL || out == NULL)
        return -1;
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n')
        len--;
    if (len == 0 || len >= MAX_LINE || memchr(line, '\n', len) != NULL)
        return -1;
    char copy[MAX_LINE];
    memcpy(copy, line, len);
    copy[len] = '\0';

    gaudit_run_event ev;
    memset(&ev, 0, sizeof ev);
    long long a, b, c, d, e, f, g, h;

    const gaudit_sexpr_field elevated[] = { { .key = "on", .value = &a, .max = 1 } };
    if (gaudit_sexpr_parse(copy, "elevated", elevated, 1) == 0) {
        ev.type = GAUDIT_RUN_EVENT_ELEVATED;
        ev.elevated = (int)a;
        *out = ev;
        return 0;
    }
    const gaudit_sexpr_field end[] = { { .key = "status", .value = &a, .max = GAUDIT_RUN_FAILED } };
    if (gaudit_sexpr_parse(copy, "end", end, 1) == 0) {
        ev.type = GAUDIT_RUN_EVENT_END;
        ev.status = (gaudit_run_status)a;
        *out = ev;
        return 0;
    }
    const gaudit_sexpr_field fw[] = {
        { .key = "verdict",      .value = &a, .max = GAUDIT_VERDICT_CRITICAL },
        { .key = "tables",       .value = &b, .max = MAX_COUNT },
        { .key = "input-chains", .value = &c, .max = MAX_COUNT },
        { .key = "input-drop",   .value = &d, .max = MAX_COUNT },
        { .key = "input-rules",  .value = &e, .max = MAX_COUNT },
        { .key = "rules",        .value = &f, .max = MAX_COUNT },
        { .key = "legacy",       .value = &g, .max = MAX_COUNT },
        { .key = "listening",    .value = &h, .max = 65536 },
    };
    if (gaudit_sexpr_parse(copy, "firewall", fw, sizeof fw / sizeof fw[0]) == 0) {
        ev.type = GAUDIT_RUN_EVENT_FIREWALL;
        ev.firewall = (gaudit_firewall_report){
            .verdict = (gaudit_verdict)a, .tables = (unsigned)b, .input_chains = (unsigned)c,
            .input_drop = (unsigned)d, .input_rules = (unsigned)e, .rules = (unsigned)f,
            .legacy = (unsigned)g, .listening = (unsigned)h,
        };
        *out = ev;
        return 0;
    }
    return -1;
}
