/* SPDX-License-Identifier: GPL-3.0-only */
/* A plugin's report, as its rule script returns it through gaudit-engine:
 * parsed strictly, then shown generically. The texts are the plugin's own
 * msgids, translated in the plugin's text domain; nothing in a report is
 * markup, and nothing in it ever becomes part of a command (a fix names a
 * collection item, and the plugin builds the fix from the cached data).
 *
 *   (report (verdict V) (title MSG) (description MSG))   first, once
 *   (section (title MSG) (description MSG))
 *   (row (verdict V) (title MSG) (subtitle MSG) [(fix ID (item N))])
 *   (note MSG)
 *   (home (verdict V) (title MSG) (subtitle MSG))   Home's rows, not on page 2
 *
 *   V    ok | warning | critical | unknown; a row may also be advice (a
 *        recommendation: counts as fine, never on Home)
 *   MSG  (msg "text" (key VALUE) ...) | (msgn "one" "many" N (key VALUE) ...) | (text "plain")
 *   VALUE  "string" | integer | MSG
 *
 * Texts carry {key} placeholders, never printf formats.
 *
 * The home elements are Home's condensate of what fails: one row per
 * problem, each a summary ("37 security updates are waiting"), and one
 * row saying all is well when nothing fails. Page 2 shows everything. */
#pragma once

#include <adwaita.h>

#include "gaudit/model.h"

G_BEGIN_DECLS

typedef struct _GauditReport GauditReport;

/* All lines of a report; NULL if any of them breaks the format. */
GauditReport *gaudit_report_parse(const char *const *lines, gsize n_lines);
void gaudit_report_free(GauditReport *report);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(GauditReport, gaudit_report_free)

gaudit_verdict gaudit_report_verdict(const GauditReport *report);

/* The report's title, translated in domain and filled in. g_free it. */
char *gaudit_report_title(const GauditReport *report, const char *domain);

/* One of Home's rows. */
typedef struct {
    gaudit_verdict verdict;
    char *title;
    char *subtitle;
} GauditHomeRow;

/* Home's rows, translated in domain and filled in; when the rule gives
 * none, one from the report's verdict and title. Never NULL. */
GPtrArray *gaudit_report_home_rows(const GauditReport *report, const char *domain);

/* The page for a fix a row names, or NULL when the plugin has none for it.
 * fix_id is the rule's symbol, item the position of the collection line
 * the fix is about. */
typedef AdwNavigationPage *(*GauditReportFixFn)(const char *fix_id, guint item, gpointer user_data);

/* Fills page 2 (status) with the report: the verdict as the shield, the
 * title and description, then a group per section with its rows, each
 * row with its verdict as a symbol; a row naming a fix leads on to it. */
void gaudit_report_show(AdwStatusPage *status, const GauditReport *report, const char *domain,
                        GauditReportFixFn fix_fn, gpointer fix_data, GDestroyNotify fix_data_free);

G_END_DECLS
