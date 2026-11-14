/* SPDX-License-Identifier: GPL-3.0-only */
/* A plugin's report, as the GUI parses it: what the engine writes for
 * Private Files is accepted, anything off the format is refused, and
 * texts are filled in from their {key} placeholders, never as formats. */
#include "gaudit-report.h"

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

/* The view's icons are not under test. */
GtkWidget *gaudit_verdict_icon_new(gaudit_verdict verdict);
GtkWidget *gaudit_verdict_icon_new(gaudit_verdict verdict)
{
    (void)verdict;
    return NULL;
}

static GauditReport *parse_file(const char *path)
{
    gchar *text = NULL;
    if (!g_file_get_contents(path, &text, NULL, NULL))
        return NULL;
    gchar **lines = g_strsplit(g_strchomp(text), "\n", -1);
    GauditReport *r = gaudit_report_parse((const char *const *)lines, g_strv_length(lines));
    g_strfreev(lines);
    g_free(text);
    return r;
}

static GauditReport *parse_one(const char *head, const char *line)
{
    const char *lines[] = { head, line };
    return gaudit_report_parse(lines, line != NULL ? 2 : 1);
}

#define HEAD "(report (verdict ok) (title (msg \"T\")) (description (text \"D\")))"

int main(int argc, char *argv[])
{
    if (argc != 2)
        return 2;
    char path[1024];

    snprintf(path, sizeof path, "%s/private-files-1.out", argv[1]);
    GauditReport *r = parse_file(path);
    CHECK(r != NULL);
    if (r != NULL) {
        CHECK(gaudit_report_verdict(r) == GAUDIT_VERDICT_WARNING);
        char *t = gaudit_report_title(r, "gaudit-test-none");
        CHECK(strcmp(t, "2 secrets can be read by others") == 0);
        g_free(t);
        gaudit_report_free(r);
    }
    snprintf(path, sizeof path, "%s/private-files-2.out", argv[1]);
    r = parse_file(path);
    CHECK(r != NULL && gaudit_report_verdict(r) == GAUDIT_VERDICT_UNKNOWN);
    gaudit_report_free(r);

    /* Placeholders: known ones filled, unknown ones left, formats inert. */
    r = parse_one("(report (verdict ok) (title (msg \"{a} and {b} %s %n\" (a 1))) (description (text \"\")))", NULL);
    CHECK(r != NULL);
    if (r != NULL) {
        char *t = gaudit_report_title(r, "gaudit-test-none");
        CHECK(strcmp(t, "1 and {b} %s %n") == 0);
        g_free(t);
        gaudit_report_free(r);
    }
    /* A nested message as a value. */
    r = parse_one("(report (verdict ok) (title (msg \"x {k}\" (k (msgn \"one\" \"many {n}\" 3 (n 3))))) (description (text \"\")))", NULL);
    CHECK(r != NULL);
    if (r != NULL) {
        char *t = gaudit_report_title(r, "gaudit-test-none");
        CHECK(strcmp(t, "x many 3") == 0);
        g_free(t);
        gaudit_report_free(r);
    }

    static const char *const bad_heads[] = {
        "(report (verdict fine) (title (msg \"T\")) (description (msg \"D\")))",
        "(report (verdict ok) (title (msg \"T\")))",
        "(report (verdict ok) (title (msg \"T\")) (description (msg \"D\")) (extra 1))",
        "(report (verdict ok) (title (msg \"T\")) (title (msg \"T\")) (description (msg \"D\")))",
        "(report (verdict ok) (title \"T\") (description (msg \"D\")))",
        "(report (verdict ok) (title (msg \"T\\n\")) (description (msg \"D\")))",
        "(report (verdict ok) (title (msg \"T\")) (description (msg \"D\"))) trailing",
        "(section (title (msg \"T\")) (description (msg \"D\")))",
        "(report (verdict OK) (title (msg \"T\")) (description (msg \"D\")))",
    };
    for (size_t i = 0; i < sizeof bad_heads / sizeof bad_heads[0]; i++) {
        r = parse_one(bad_heads[i], NULL);
        if (r != NULL) {
            fprintf(stderr, "accepted: %s\n", bad_heads[i]);
            failures++;
            gaudit_report_free(r);
        }
    }
    static const char *const bad_lines[] = {
        "(row (verdict ok) (title (text \"x\")))",
        "(row (verdict ok) (title (text \"x\")) (subtitle (text \"y\")) (fix make-private))",
        "(row (verdict ok) (title (text \"x\")) (subtitle (text \"y\")) (fix make-private (item -1)))",
        "(row (verdict ok) (title (text \"x\")) (subtitle (text \"y\")) (fix \"rm -rf ~\" (item 0)))",
        "(note \"plain\")",
        "(note (msg \"x\" (k)))",
        "(note (msg \"x\" (\"k\" 1)))",
        "(script (msg \"x\"))",
        "(note (msg \"x\" (k (msg \"y\" (k (msg \"z\" (k (msg \"w\" (k (msg \"v\"))))))))))",
    };
    for (size_t i = 0; i < sizeof bad_lines / sizeof bad_lines[0]; i++) {
        r = parse_one(HEAD, bad_lines[i]);
        if (r != NULL) {
            fprintf(stderr, "accepted: %s\n", bad_lines[i]);
            failures++;
            gaudit_report_free(r);
        }
    }
    r = parse_one(HEAD, "(row (verdict warning) (title (text \"~/x\")) (subtitle (msg \"y\")) (fix make-private (item 3)))");
    CHECK(r != NULL);
    gaudit_report_free(r);

    if (failures == 0)
        puts("report: all checks passed");
    return failures == 0 ? 0 : 1;
}
