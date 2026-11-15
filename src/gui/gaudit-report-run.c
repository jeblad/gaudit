/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <string.h>

#include "gaudit-orchestrator.h"
#include "gaudit-report-run.h"
#include "gaudit/backend.h"

/* The engine's own limit is 2 s; starting Guile takes a little more. */
#define REPORT_TIMEOUT_S 15
#define MAX_REPORT_LINES 512

/* --- The cache ---------------------------------------------------------- */

typedef struct {
    GPtrArray *lines;
    char *command;
    gboolean full;
    char when[16];
} Entry;

static GHashTable *cache;  /* task id -> Entry */

static void entry_free(gpointer p)
{
    Entry *e = p;
    g_ptr_array_unref(e->lines);
    g_free(e->command);
    g_free(e);
}

void gaudit_cache_store(const GauditTaskInfo *task, const char *command, GPtrArray *lines,
                        gboolean full)
{
    g_return_if_fail(task != NULL && command != NULL && lines != NULL);
    if (cache == NULL)
        cache = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, entry_free);
    Entry *e = g_new0(Entry, 1);
    e->lines = g_ptr_array_ref(lines);
    e->command = g_strdup(command);
    e->full = full;
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree char *when = g_date_time_format(now, "%H:%M");
    g_strlcpy(e->when, when != NULL ? when : "", sizeof e->when);
    g_hash_table_replace(cache, (gpointer)task->id, e);
}

GPtrArray *gaudit_cache_lines(const GauditTaskInfo *task, const char **when)
{
    Entry *e = cache != NULL ? g_hash_table_lookup(cache, task->id) : NULL;
    if (when != NULL)
        *when = e != NULL ? e->when : NULL;
    return e != NULL ? e->lines : NULL;
}

gboolean gaudit_cache_full(const GauditTaskInfo *task)
{
    Entry *e = cache != NULL ? g_hash_table_lookup(cache, task->id) : NULL;
    return e != NULL && e->full;
}

const char *gaudit_cache_command(const GauditTaskInfo *task)
{
    Entry *e = cache != NULL ? g_hash_table_lookup(cache, task->id) : NULL;
    return e != NULL ? e->command : NULL;
}

typedef struct {
    guint id;
    GauditCacheChangedFn fn;
    gpointer data;
} Watch;

static GArray *watches;  /* Watch */
static guint next_watch = 1;

guint gaudit_cache_watch(GauditCacheChangedFn fn, gpointer user_data)
{
    if (watches == NULL)
        watches = g_array_new(FALSE, FALSE, sizeof(Watch));
    Watch w = { next_watch++, fn, user_data };
    g_array_append_val(watches, w);
    return w.id;
}

void gaudit_cache_unwatch(guint id)
{
    for (guint i = 0; watches != NULL && i < watches->len; i++)
        if (g_array_index(watches, Watch, i).id == id) {
            g_array_remove_index(watches, i);
            return;
        }
}

void gaudit_cache_changed(const GauditTaskInfo *task)
{
    /* A copy: a watcher may unwatch while it is told. */
    g_autoptr(GArray) now = watches != NULL ? g_array_copy(watches) : NULL;
    for (guint i = 0; now != NULL && i < now->len; i++)
        g_array_index(now, Watch, i).fn(task, g_array_index(now, Watch, i).data);
}

/* --- Making a report ---------------------------------------------------- */

typedef struct {
    GauditReportDoneFn done;
    gpointer user_data;
    GPtrArray *lines;  /* the report's */
    GauditOrchestrator *orch;
} Job;

/* text as a protocol string: \" and \\ escaped, control bytes dropped. */
static void append_quoted(GString *out, const char *text)
{
    g_string_append_c(out, '"');
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        if (*p == '"' || *p == '\\')
            g_string_append_c(out, '\\');
        if (*p >= 0x20 && *p != 0x7f)
            g_string_append_c(out, (char)*p);
    }
    g_string_append_c(out, '"');
}

/* What the rule script gets: the system's identification, the
 * collection's level (the command's last word, e.g. "quick") and the
 * collection, as data. */
static char *build_input(const char *command, GPtrArray *lines)
{
    const char *space = strrchr(command, ' ');
    const char *level = space != NULL ? space + 1 : command;
    char host[256], distro[256], full[256];
    gaudit_system_describe(host, sizeof host, distro, sizeof distro, full, sizeof full);
    const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
    GString *in = g_string_new("(input (system (host ");
    append_quoted(in, host);
    g_string_append(in, ") (distro ");
    append_quoted(in, full[0] != '\0' ? full : distro);
    g_string_append(in, ") (backend ");
    append_quoted(in, pkg != NULL ? pkg->name : "");
    g_string_append(in, "))\n (level ");
    append_quoted(in, level);
    g_string_append(in, ")\n (collection\n");
    for (guint i = 0; i < lines->len; i++) {
        g_string_append(in, "  ");
        g_string_append(in, g_ptr_array_index(lines, i));
        g_string_append_c(in, '\n');
    }
    g_string_append(in, "))\n");
    return g_string_free(in, FALSE);
}

static gboolean on_line(const char *line, gpointer user_data)
{
    Job *job = user_data;
    if (job->lines->len >= MAX_REPORT_LINES)
        return FALSE;
    g_ptr_array_add(job->lines, g_strdup(line));
    return TRUE;
}

static void on_done(gboolean broken, gpointer user_data)
{
    Job *job = user_data;
    GauditReport *report = NULL;
    if (!broken && job->lines->len > 0)
        report = gaudit_report_parse((const char *const *)job->lines->pdata, job->lines->len);
    if (!broken && job->lines->len > 0 && report == NULL)
        g_warning("gaudit: a plugin's report broke the format; not shown");
    job->done(report, job->user_data);
    g_ptr_array_unref(job->lines);
    g_free(job);
}

void gaudit_report_run(const GauditTaskInfo *task, const char *command, GPtrArray *lines,
                       GauditReportDoneFn done, gpointer user_data)
{
    g_return_if_fail(task != NULL && command != NULL && lines != NULL && done != NULL);
    Job *job = g_new0(Job, 1);
    job->done = done;
    job->user_data = user_data;
    job->lines = g_ptr_array_new_with_free_func(g_free);
    const char *args[] = { "report", task->id, NULL };
    g_autofree char *input = build_input(command, lines);
    GauditOrchestrator *orch = gaudit_orchestrator_start(args, REPORT_TIMEOUT_S, TRUE,
                                                          on_line, on_done, job);
    if (orch == NULL)
        return;  /* on_done has run */
    if (!gaudit_orchestrator_send(orch, input))
        gaudit_orchestrator_stop(orch);
    else
        gaudit_orchestrator_close_input(orch);
}
