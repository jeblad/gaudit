/* SPDX-License-Identifier: GPL-3.0-only */
/* Probe results over the orchestrator pipe: write and read back, and reject
 * anything else. The GUI treats this input as untrusted. */
#include "gaudit/probe.h"
#include "gaudit/run.h"
#include "gaudit/sourceless.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                \
                    __FILE__, __LINE__, #expr);                         \
            failures++;                                                 \
        }                                                               \
    } while (0)

static char text[16384];

/* All results as the orchestrator would write them. */
static void write_all(const gaudit_probe_result r[GAUDIT_PROBE_COUNT])
{
    size_t used = 0;
    text[0] = '\0';
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        char line[1024];
        CHECK(gaudit_probe_format(&r[k], line, sizeof line) == 0);
        size_t n = strlen(line);
        if (used + n + 1 < sizeof text) {
            memcpy(text + used, line, n + 1);
            used += n;
        }
    }
}

int main(void)
{
    gaudit_probe_result in[GAUDIT_PROBE_COUNT], out[GAUDIT_PROBE_COUNT];

    /* Unknown results from a NULL backend, then every field set. */
    gaudit_probe_collect(NULL, 0, in);
    gaudit_probe_result *r = &in[GAUDIT_PROBE_SNAP];
    r->verdict = GAUDIT_VERDICT_WARNING;
    r->age_seconds = -1;  /* unknown time */
    r->count = 7;
    r->extra_count = 8;
    r->info_count = 9;
    r->until_epoch = 1800000000;
    r->service_down = 1;
    in[GAUDIT_PROBE_OTHER_PACKAGE_SYSTEMS].mask = (1u << GAUDIT_PKGSYS_RPM) | (1u << GAUDIT_PKGSYS_NIX);
    in[GAUDIT_PROBE_PACKAGE_SYSTEM].applicable = 0;
    in[GAUDIT_PROBE_AUTO_UPDATES].unsupported = 1;
    snprintf(in[GAUDIT_PROBE_FLATPAK].missing_capability, sizeof in[0].missing_capability, "libflatpak");
    snprintf(in[GAUDIT_PROBE_PACKAGE_SYSTEM].detail, sizeof in[0].detail, "dpkg/apt");
    snprintf(in[GAUDIT_PROBE_SECURITY_SOURCE].text, sizeof in[0].text, "odd \"host\" \\ name");

    write_all(in);
    CHECK(gaudit_probe_parse_all(text, out) == 0);
    for (int k = 0; k < GAUDIT_PROBE_COUNT; k++) {
        CHECK(out[k].kind == in[k].kind && out[k].verdict == in[k].verdict);
        CHECK(out[k].applicable == in[k].applicable && out[k].unsupported == in[k].unsupported);
        CHECK(out[k].age_seconds == in[k].age_seconds && out[k].count == in[k].count);
        CHECK(out[k].extra_count == in[k].extra_count && out[k].info_count == in[k].info_count);
        CHECK(out[k].mask == in[k].mask && out[k].until_epoch == in[k].until_epoch);
        CHECK(out[k].service_down == in[k].service_down);
        CHECK(strcmp(out[k].missing_capability, in[k].missing_capability) == 0);
        CHECK(strcmp(out[k].detail, in[k].detail) == 0 && strcmp(out[k].text, in[k].text) == 0);
        CHECK(out[k].id != NULL && strcmp(out[k].id, gaudit_probe_id((gaudit_probe_kind)k)) == 0);
    }

    /* Control characters are replaced when written, so the line stays valid. */
    snprintf(in[GAUDIT_PROBE_SECURITY_SOURCE].text, sizeof in[0].text, "bad\x01name");
    write_all(in);
    CHECK(gaudit_probe_parse_all(text, out) == 0);
    CHECK(strcmp(out[GAUDIT_PROBE_SECURITY_SOURCE].text, "bad?name") == 0);

    /* Rejected: a kind missing, a kind twice, an extra line, out-of-range
     * values, overlong text, broken quoting. */
    write_all(in);
    char *last = strrchr(text, '(');                /* drop the last line */
    while (last > text && last[-1] != '\n')
        last--;
    char saved = *last;
    *last = '\0';
    CHECK(gaudit_probe_parse_all(text, out) != 0);
    *last = saved;

    char doubled[sizeof text * 2];
    snprintf(doubled, sizeof doubled, "%s%s", text, text);
    CHECK(gaudit_probe_parse_all(doubled, out) != 0);

    char extra[sizeof text + 64];
    snprintf(extra, sizeof extra, "%s(probe (kind 99))\n", text);
    CHECK(gaudit_probe_parse_all(extra, out) != 0);

#define BASE "(probe (kind 3) (verdict %s) (applicable 1) (unsupported 0) (age %s)" \
             " (count 0) (extra 0) (info 0) (mask 0) (until 0) (down 0)" \
             " (missing %s) (detail \"\") (text \"\"))"
    char line[2048];
    gaudit_probe_result one[GAUDIT_PROBE_COUNT];
    snprintf(line, sizeof line, BASE, "4", "0", "\"\"");     /* verdict out of range */
    CHECK(gaudit_probe_parse_all(line, one) != 0);
    snprintf(line, sizeof line, BASE, "0", "-2", "\"\"");    /* only -1 allowed below 0 */
    CHECK(gaudit_probe_parse_all(line, one) != 0);
    snprintf(line, sizeof line, BASE, "0", "0",
             "\"0123456789012345678901234567890123456789\"");  /* longer than the field */
    CHECK(gaudit_probe_parse_all(line, one) != 0);
    snprintf(line, sizeof line, BASE, "0", "0", "\"unterminated");
    CHECK(gaudit_probe_parse_all(line, one) != 0);
    snprintf(line, sizeof line, BASE, "0", "0", "\"bad \\n escape\"");
    CHECK(gaudit_probe_parse_all(line, one) != 0);
    CHECK(gaudit_probe_parse_all("", one) != 0);
    CHECK(gaudit_probe_parse_all(NULL, one) != 0);

    /* One line at a time, as the GUI reads them. */
    gaudit_probe_result lr;
    snprintf(line, sizeof line, BASE "\n", "2", "0", "\"\"");
    CHECK(gaudit_probe_parse_line(line, &lr) == 0);
    CHECK(lr.kind == 3 && lr.verdict == GAUDIT_VERDICT_WARNING && lr.id != NULL);
    line[strlen(line) - 1] = '\0';                        /* without the newline too */
    CHECK(gaudit_probe_parse_line(line, &lr) == 0);
    char two[4096];
    snprintf(two, sizeof two, "%s\n%s", line, line);     /* never two lines at once */
    CHECK(gaudit_probe_parse_line(two, &lr) != 0);
    CHECK(gaudit_probe_parse_line("", &lr) != 0);
    CHECK(gaudit_probe_parse_line("\n", &lr) != 0);
    CHECK(gaudit_probe_parse_line(NULL, &lr) != 0);

    /* The tasks cover every kind exactly once, so every row gets one answer. */
    unsigned all = 0;
    int overlap = 0;
    for (int t = 0; t < GAUDIT_PROBE_TASK_COUNT; t++) {
        unsigned kinds = gaudit_probe_task_kinds(t);
        CHECK(kinds != 0);
        overlap |= (all & kinds) != 0;
        all |= kinds;
    }
    CHECK(!overlap);
    CHECK(all == (1u << GAUDIT_PROBE_COUNT) - 1);
    CHECK(gaudit_probe_task_kinds(GAUDIT_PROBE_TASK_COUNT) == 0);
    CHECK(gaudit_probe_task_kinds(-1) == 0);

    /* Runs on request: every event round-trips, and only the protocol parses. */
    gaudit_run_event evs[] = {
        { .type = GAUDIT_RUN_EVENT_ELEVATED, .elevated = 1 },
        { .type = GAUDIT_RUN_EVENT_FIREWALL, .firewall = { .verdict = GAUDIT_VERDICT_OK,
          .tables = 3, .input_chains = 2, .input_drop = 1, .input_rules = 7, .rules = 40, .legacy = 0,
          .listening = 2 } },
        { .type = GAUDIT_RUN_EVENT_ELEVATED, .elevated = 0 },
        { .type = GAUDIT_RUN_EVENT_END, .status = GAUDIT_RUN_CANCELLED },
    };
    for (size_t i = 0; i < sizeof evs / sizeof evs[0]; i++) {
        char rl[512];
        gaudit_run_event back;
        CHECK(gaudit_run_format(&evs[i], rl, sizeof rl) == 0);
        CHECK(gaudit_run_parse_line(rl, &back) == 0);
        CHECK(back.type == evs[i].type && back.elevated == evs[i].elevated
              && back.status == evs[i].status
              && memcmp(&back.firewall, &evs[i].firewall, sizeof back.firewall) == 0);
    }
    gaudit_run_event ev;
    CHECK(gaudit_run_parse_line("(end (status 4))", &ev) != 0);           /* no such status */
    CHECK(gaudit_run_parse_line("(elevated (on 2))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(elevated (on 1) (on 1))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(firewall (verdict 0))", &ev) != 0);     /* fields missing */
    CHECK(gaudit_run_parse_line("(helper-start (version 1) (caller 0))", &ev) != 0);  /* helper's, not ours */
    CHECK(gaudit_run_parse_line("", &ev) != 0);

    /* The interim firewall verdict. */
    gaudit_firewall_report fw = { 0 };
    CHECK(gaudit_firewall_verdict(&fw) == GAUDIT_VERDICT_WARNING);       /* nothing at all */
    fw.input_chains = 1;
    CHECK(gaudit_firewall_verdict(&fw) == GAUDIT_VERDICT_WARNING);       /* accepts everything */
    fw.input_drop = 1;
    CHECK(gaudit_firewall_verdict(&fw) == GAUDIT_VERDICT_OK);            /* ufw: policy drop */
    fw.input_drop = 0;
    fw.input_rules = 12;
    CHECK(gaudit_firewall_verdict(&fw) == GAUDIT_VERDICT_OK);            /* firewalld: rules */
    fw = (gaudit_firewall_report){ .legacy = 2 };
    CHECK(gaudit_firewall_verdict(&fw) == GAUDIT_VERDICT_UNKNOWN);       /* rules out of sight */
    CHECK(gaudit_firewall_verdict(NULL) == GAUDIT_VERDICT_UNKNOWN);

    /* Packages without a source: round trip, and only the protocol parses. */
    gaudit_sourceless_package sp = { .name = "bzip2", .arch = "amd64", .version = "1.0.8-6ubuntu0.1",
                                     .offered = "1.0.8-6build2", .group = GAUDIT_SOURCELESS_ABOVE_SOURCE };
    gaudit_sourceless_package sp_back;
    gaudit_sourceless_summary ss = { .status = GAUDIT_SOURCELESS_OK, .count = 73, .shown = 73 }, ss_back;
    char sl[1024];
    CHECK(gaudit_sourceless_format_package(&sp, sl, sizeof sl) == 0);
    CHECK(gaudit_sourceless_parse_line(sl, &sp_back, &ss_back) == 1);
    CHECK(memcmp(&sp, &sp_back, sizeof sp) == 0);
    CHECK(gaudit_sourceless_format_summary(&ss, sl, sizeof sl) == 0);
    CHECK(gaudit_sourceless_parse_line(sl, &sp_back, &ss_back) == 2);
    CHECK(ss_back.count == 73 && ss_back.shown == 73 && ss_back.status == GAUDIT_SOURCELESS_OK);
    /* A quote in a name is escaped, and survives. */
    snprintf(sp.name, sizeof sp.name, "odd\"name");
    CHECK(gaudit_sourceless_format_package(&sp, sl, sizeof sl) == 0);
    CHECK(gaudit_sourceless_parse_line(sl, &sp_back, &ss_back) == 1 && strcmp(sp_back.name, "odd\"name") == 0);
    CHECK(gaudit_sourceless_parse_line("(packages (status 0) (count 2) (shown 3))", &sp_back, &ss_back) == -1);
    CHECK(gaudit_sourceless_parse_line("(packages (status 3) (count 2) (shown 2))", &sp_back, &ss_back) == -1);
    CHECK(gaudit_sourceless_parse_line("(package (name \"x\") (arch \"\") (version \"1\") (group 3) (offered \"\"))",
                                       &sp_back, &ss_back) == -1);   /* no such group */
    CHECK(gaudit_sourceless_parse_line("(package (name \"\") (arch \"\") (version \"1\") (group 0) (offered \"\"))",
                                       &sp_back, &ss_back) == -1);   /* no name */
    sp.group = (gaudit_sourceless_group)7;
    CHECK(gaudit_sourceless_format_package(&sp, sl, sizeof sl) == -1);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
