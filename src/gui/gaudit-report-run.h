/* SPDX-License-Identifier: GPL-3.0-only */
/* Collections, kept for the session, and the reports made from them.
 *
 * The cache holds a plugin's latest collection (its checked lines) in this
 * process's memory only, never in a file the account could change. A
 * report is made from it by the plugin's rule script, through
 * "gaudit-orchestrator report <plugin-id>" and gaudit-engine; making it
 * again from the same collection gives the same report, so Home and the
 * plugin's page 2 never disagree. */
#pragma once

#include <glib.h>

#include "gaudit-report.h"
#include "gaudit-task.h"

G_BEGIN_DECLS

/* Keeps lines (a reference is taken) as task's latest collection, made by
 * command (its last word is the collection's level, e.g. "quick"); full:
 * made with the plugin's parameters (Run on Parameters), not for Home. */
void gaudit_cache_store(const GauditTaskInfo *task, const char *command, GPtrArray *lines,
                        gboolean full, const char *const *args);

/* The parameters a full cached collection was made with (borrowed; NULL
 * for none, or a simplified one), so it can be made again the same way. */
const char *const *gaudit_cache_args(const GauditTaskInfo *task);

/* Whether task's cached collection is a full one: its report is then the
 * report, otherwise the simplified one Home made. */
gboolean gaudit_cache_full(const GauditTaskInfo *task);

/* task's latest collection (borrowed; NULL for none) and when it was
 * made ("14:32"). */
GPtrArray *gaudit_cache_lines(const GauditTaskInfo *task, const char **when);

/* The command task's cached collection was made by (borrowed; NULL for none). */
const char *gaudit_cache_command(const GauditTaskInfo *task);

/* Told when a task's cached collection changes in place (a finding checked
 * again after a fix), so what shows a report from it can make it again. */
typedef void (*GauditCacheChangedFn)(const GauditTaskInfo *task, gpointer user_data);
guint gaudit_cache_watch(GauditCacheChangedFn fn, gpointer user_data);
void gaudit_cache_unwatch(guint id);
void gaudit_cache_changed(const GauditTaskInfo *task);

/* The report, or NULL when none could be made. Called exactly once. */
typedef void (*GauditReportDoneFn)(GauditReport *report, gpointer user_data);

/* Makes task's report from lines (a reference is taken while it runs),
 * collected by command. */
void gaudit_report_run(const GauditTaskInfo *task, const char *command, GPtrArray *lines,
                       GauditReportDoneFn done, gpointer user_data);

G_END_DECLS
