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
    in[GAUDIT_PROBE_LISTENING].mask = (1u << GAUDIT_PKGSYS_RPM) | (1u << GAUDIT_PKGSYS_NIX);
    in[GAUDIT_PROBE_ANTIVIRUS].applicable = 0;
    in[GAUDIT_PROBE_FIREWALL].unsupported = 1;
    snprintf(in[GAUDIT_PROBE_FLATPAK].missing_capability, sizeof in[0].missing_capability, "libflatpak");
    snprintf(in[GAUDIT_PROBE_LISTENING].detail, sizeof in[0].detail, "dpkg/apt");
    snprintf(in[GAUDIT_PROBE_SNAP].text, sizeof in[0].text, "odd \"host\" \\ name");

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
    snprintf(in[GAUDIT_PROBE_SNAP].text, sizeof in[0].text, "bad\x01name");
    write_all(in);
    CHECK(gaudit_probe_parse_all(text, out) == 0);
    CHECK(strcmp(out[GAUDIT_PROBE_SNAP].text, "bad?name") == 0);

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
        { .type = GAUDIT_RUN_EVENT_INTEGRITY_FILE, .file = { .kind = GAUDIT_INTEGRITY_FILE_CHANGED,
          .package = "libc6:amd64", .path = "/usr/lib/x86_64-linux-gnu/libc.so.6" } },
        { .type = GAUDIT_RUN_EVENT_INTEGRITY_FILE, .file = { .kind = GAUDIT_INTEGRITY_FILE_MISSING,
          .package = "odd", .path = "/usr/share/odd/a \"quoted\" \\ name" } },
        { .type = GAUDIT_RUN_EVENT_INTEGRITY, .integrity = { .verdict = GAUDIT_VERDICT_WARNING,
          .packages = 3105, .files = 446591, .checked = 446000, .changed = 1, .missing = 1,
          .unreadable = 589, .excluded = 0, .diverted = 1, .bad_lines = 0, .megabytes = 31734,
          .shown = 2, .seconds = 44 } },
        { .type = GAUDIT_RUN_EVENT_CONF, .conf = { .template_id = "core.updates.automatic",
          .action = "on", .result = "written" } },
        { .type = GAUDIT_RUN_EVENT_EXEC, .exec = { .op = "apt-upgrade-update", .status = 100 } },
        { .type = GAUDIT_RUN_EVENT_ELEVATED, .elevated = 0 },
        { .type = GAUDIT_RUN_EVENT_END, .status = GAUDIT_RUN_CANCELLED },
    };
    gaudit_run_event ev;
    for (size_t i = 0; i < sizeof evs / sizeof evs[0]; i++) {
        char rl[512];
        gaudit_run_event back;
        CHECK(gaudit_run_format(&evs[i], rl, sizeof rl) == 0);
        CHECK(gaudit_run_parse_line(rl, &back) == 0);
        CHECK(back.type == evs[i].type && back.elevated == evs[i].elevated
              && back.status == evs[i].status
              && memcmp(&back.firewall, &evs[i].firewall, sizeof back.firewall) == 0
              && memcmp(&back.integrity, &evs[i].integrity, sizeof back.integrity) == 0
              && back.file.kind == evs[i].file.kind
              && strcmp(back.file.package, evs[i].file.package) == 0
              && strcmp(back.file.path, evs[i].file.path) == 0
              && strcmp(back.conf.template_id, evs[i].conf.template_id) == 0
              && strcmp(back.conf.action, evs[i].conf.action) == 0
              && strcmp(back.conf.result, evs[i].conf.result) == 0
              && strcmp(back.exec.op, evs[i].exec.op) == 0 && back.exec.status == evs[i].exec.status);
    CHECK(gaudit_run_parse_line("(exec (op \"apt-update\") (status 256))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(exec (op \"a;b\") (status 0))", &ev) != 0);
    }
    /* A configuration write: only known actions and results, plain template ids. */
    CHECK(gaudit_run_parse_line("(conf (template \"t\") (action \"on\") (result \"deleted\"))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(conf (template \"t\") (action \"open\") (result \"written\"))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(conf (template \"../t\") (action \"on\") (result \"written\"))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(conf (template \"a b\") (action \"on\") (result \"written\"))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(conf (template \"t\") (action \"remove\") (result \"removed\"))", &ev) == 0
          && ev.type == GAUDIT_RUN_EVENT_CONF);
    CHECK(gaudit_run_parse_line("(end (status 4))", &ev) != 0);           /* no such status */
    CHECK(gaudit_run_parse_line("(elevated (on 2))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(elevated (on 1) (on 1))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(firewall (verdict 0))", &ev) != 0);     /* fields missing */
    CHECK(gaudit_run_parse_line("(helper-start (version 1) (caller 0))", &ev) != 0);  /* helper's, not ours */
    CHECK(gaudit_run_parse_line("", &ev) != 0);
    CHECK(gaudit_run_parse_line("(integrity-file (kind 3) (package \"a\") (path \"/x\"))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(integrity-file (kind 0) (package \"a\") (path \"x\"))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(integrity-file (kind 0) (package \"\") (path \"/x\"))", &ev) != 0);
    /* A verdict that does not follow from the counts, and counts that do
     * not add up, are both protocol violations. */
    CHECK(gaudit_run_parse_line("(integrity (verdict 0) (packages 1) (files 2) (checked 2) (changed 1)"
                                " (missing 0) (unreadable 0) (excluded 0) (diverted 0) (bad-lines 0)"
                                " (megabytes 0) (shown 0) (seconds 0))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(integrity (verdict 2) (packages 1) (files 2) (checked 2) (changed 1)"
                                " (missing 1) (unreadable 0) (excluded 0) (diverted 0) (bad-lines 0)"
                                " (megabytes 0) (shown 0) (seconds 0))", &ev) != 0);
    CHECK(gaudit_run_parse_line("(integrity (verdict 2) (packages 1) (files 2) (checked 2) (changed 1)"
                                " (missing 0) (unreadable 0) (excluded 0) (diverted 0) (bad-lines 0)"
                                " (megabytes 0) (shown 2) (seconds 0))", &ev) != 0);

    /* gAudit checking itself: round trip, then what is refused. */
    {
        gaudit_run_event sf = { .type = GAUDIT_RUN_EVENT_SELF_FILE,
                                .self_file = { .path = "/usr/libexec/gaudit/gaudit-helper",
                                               .problem = "changed" } };
        gaudit_run_event sp2 = { .type = GAUDIT_RUN_EVENT_SELF_PROCESS,
                                 .self_process = { .which = "gui", .problem = "env",
                                                   .detail = "LD_PRELOAD" } };
        gaudit_run_event so = { .type = GAUDIT_RUN_EVENT_SELF,
                                .self = { .manifest = "ok", .version = 999999999999999999ULL,
                                          .files = 40, .changed = 1, .extra = 2, .files_shown = 1,
                                          .processes = 2, .process_problems = 1,
                                          .processes_shown = 1 } };
        const gaudit_run_event *self_evs[] = { &sf, &sp2, &so };
        for (size_t i = 0; i < 3; i++) {
            char rl[512];
            gaudit_run_event back;
            CHECK(gaudit_run_format(self_evs[i], rl, sizeof rl) == 0);
            CHECK(gaudit_run_parse_line(rl, &back) == 0 && back.type == self_evs[i]->type
                  && memcmp(&back.self_file, &self_evs[i]->self_file, sizeof back.self_file) == 0
                  && memcmp(&back.self_process, &self_evs[i]->self_process, sizeof back.self_process) == 0
                  && memcmp(&back.self, &self_evs[i]->self, sizeof back.self) == 0);
        }
        CHECK(gaudit_self_verdict(&so.self) == GAUDIT_VERDICT_WARNING);
        gaudit_self_report sr = { .manifest = "ok", .files = 3, .processes = 2 };
        CHECK(gaudit_self_verdict(&sr) == GAUDIT_VERDICT_OK);
        sr.process_problems = 1;
        CHECK(gaudit_self_verdict(&sr) == GAUDIT_VERDICT_WARNING);
        sr = (gaudit_self_report){ .manifest = "missing", .processes = 2 };
        CHECK(gaudit_self_verdict(&sr) == GAUDIT_VERDICT_UNKNOWN);  /* nothing to check files with */
        snprintf(sr.manifest, sizeof sr.manifest, "no-key");
        CHECK(gaudit_self_verdict(&sr) == GAUDIT_VERDICT_UNKNOWN);
        snprintf(sr.manifest, sizeof sr.manifest, "too-old");
        CHECK(gaudit_self_verdict(&sr) == GAUDIT_VERDICT_WARNING);   /* an older gAudit put back */
        snprintf(sr.manifest, sizeof sr.manifest, "bad-signature");
        CHECK(gaudit_self_verdict(&sr) == GAUDIT_VERDICT_WARNING);
        /* Refused: unknown names, a quote, findings beyond what it says,
         * files counted without a good manifest. */
        CHECK(gaudit_run_parse_line("(self-file (path \"/x\") (problem \"gone\"))", &ev) != 0);
        CHECK(gaudit_run_parse_line("(self-file (path \"x\") (problem \"extra\"))", &ev) != 0);
        CHECK(gaudit_run_parse_line("(self-file (path \"/a\\\"b\") (problem \"extra\"))", &ev) != 0);
        CHECK(gaudit_run_parse_line("(self-process (which \"helper\") (problem \"env\") (detail \"\"))", &ev) != 0);
        CHECK(gaudit_run_parse_line("(self-process (which \"gui\") (problem \"odd\") (detail \"\"))", &ev) != 0);
        CHECK(gaudit_run_parse_line("(self-process (which \"gui\") (problem \"gone\") (detail \"\"))", &ev) == 0
              && ev.type == GAUDIT_RUN_EVENT_SELF_PROCESS);
        const char *head = "(self (manifest \"%s\") (version 1) (files %d) (changed %d) (missing 0)"
                           " (extra 0) (files-shown %d) (processes 2) (process-problems 0)"
                           " (processes-shown 0))";
        char sline[400];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        snprintf(sline, sizeof sline, head, "ok", 3, 1, 1);
        CHECK(gaudit_run_parse_line(sline, &ev) == 0 && ev.type == GAUDIT_RUN_EVENT_SELF);
        snprintf(sline, sizeof sline, head, "fine", 3, 1, 1);
        CHECK(gaudit_run_parse_line(sline, &ev) != 0);   /* no such state */
        snprintf(sline, sizeof sline, head, "ok", 3, 1, 2);
        CHECK(gaudit_run_parse_line(sline, &ev) != 0);   /* shows more than it found */
        snprintf(sline, sizeof sline, head, "ok", 1, 2, 0);
        CHECK(gaudit_run_parse_line(sline, &ev) != 0);   /* more changed than listed */
        snprintf(sline, sizeof sline, head, "missing", 3, 0, 0);
        CHECK(gaudit_run_parse_line(sline, &ev) != 0);   /* files without a manifest */
#pragma GCC diagnostic pop
        CHECK(gaudit_run_parse_line("(self (manifest \"ok\") (version 1) (files 1) (changed 0) (missing 0)"
                                    " (extra 0) (files-shown 0) (processes 3) (process-problems 0)"
                                    " (processes-shown 0))", &ev) != 0);  /* only two ask */
    }

    /* The integrity verdict. */
    gaudit_integrity_report ir = { .files = 10, .checked = 10 };
    CHECK(gaudit_integrity_verdict(&ir) == GAUDIT_VERDICT_OK);
    ir.unreadable = 1;
    CHECK(gaudit_integrity_verdict(&ir) == GAUDIT_VERDICT_UNKNOWN);  /* could not see everything */
    ir.changed = 1;
    CHECK(gaudit_integrity_verdict(&ir) == GAUDIT_VERDICT_WARNING);  /* worse than unknown */
    ir = (gaudit_integrity_report){ .files = 10, .checked = 9, .missing = 1 };
    CHECK(gaudit_integrity_verdict(&ir) == GAUDIT_VERDICT_WARNING);
    ir = (gaudit_integrity_report){ 0 };
    CHECK(gaudit_integrity_verdict(&ir) == GAUDIT_VERDICT_UNKNOWN);  /* nothing checked */

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
                                     .offered = "1.0.8-6build2", .group = GAUDIT_SOURCELESS_ABOVE_SOURCE,
                                     .replaced = "flatpak org.example.App", .needed_by = 3,
                                     .needed = "a, b, c", .manual = 0, .installed = 1700000000,
                                     .program = 1, .built_for = "Ubuntu 25.10",
                                     .likely_source = "ppa:cappelikan/ppa" };
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
    CHECK(gaudit_sourceless_parse_line("(package (name \"x\") (arch \"\") (version \"1\") (group 4) (offered \"\")"
                                       " (replaced \"\") (needed-by -1) (needed \"\") (manual -1) (installed 0)"
                                       " (program -1) (built-for \"\") (likely-source \"\"))",
                                       &sp_back, &ss_back) == -1);   /* no such group */
    CHECK(gaudit_sourceless_parse_line("(package (name \"x\") (arch \"\") (version \"1\") (group 0) (offered \"\"))",
                                       &sp_back, &ss_back) == -1);   /* the details missing */
    CHECK(gaudit_sourceless_parse_line("(package (name \"\") (arch \"\") (version \"1\") (group 0) (offered \"\"))",
                                       &sp_back, &ss_back) == -1);   /* no name */
    sp.group = (gaudit_sourceless_group)7;
    CHECK(gaudit_sourceless_format_package(&sp, sl, sizeof sl) == -1);

    if (failures)
        fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
