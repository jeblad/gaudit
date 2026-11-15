/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "collector.h"
#include "gaudit-orchestrator.h"
#include "gaudit-session.h"
#include "gaudit-task.h"

#include <string.h>

/* The orchestrator gives a run at most 20 minutes (the integrity check;
 * others less); this is the GUI's own limit on top. */
#define RUN_WATCHDOG_S (21 * 60)

/* Someone else waiting for the same run (gaudit_session_attach). */
typedef struct {
    GauditRunProgressFn on_progress;
    GauditRunDoneFn on_done;
    gpointer user_data;
} Observer;

typedef struct {
    char *command;
    GStrv args;             /* the run's parameters, for runs as the user */
    GauditRunProgressFn on_progress;
    GauditRunDoneFn on_done;
    gpointer user_data;
    GArray *observers;      /* Observer */
    GauditOrchestrator *user_orch;  /* a user run's own orchestrator */
    gboolean cancelled;     /* the user stopped it */
    gboolean wants_result;  /* FALSE for "elevate", which only starts the helper */
    gboolean user;          /* runs as the user, not through the session */
    gboolean (*collection_line)(const char *line, gboolean *last);  /* user runs */
    guint64 progress;       /* entries looked at, from its progress lines */
    gint64 started;         /* monotonic, µs */
    char where[256];        /* the folder being searched, from them */
    gboolean have_result;
    GauditRunResult result;
} Run;

static struct {
    GauditOrchestrator *orch;  /* NULL while no session runs */
    gboolean elevated;
    Run *run;                  /* the run under way, if any */
    guint watchdog_id;
    void (*listener)(gboolean on, gpointer user_data);
    gpointer listener_data;
    void (*result_listener)(const char *command, const GauditRunResult *result,
                            gpointer user_data);
    gpointer result_listener_data;
} S;

static void set_elevated(gboolean on)
{
    if (S.elevated == on)
        return;
    S.elevated = on;
    if (S.listener != NULL)
        S.listener(on, S.listener_data);
}

static void end_run(gaudit_run_status status)
{
    Run *run = S.run;
    if (run == NULL)
        return;
    S.run = NULL;
    if (S.watchdog_id != 0) {
        g_source_remove(S.watchdog_id);
        S.watchdog_id = 0;
    }
    const GauditRunResult *result =
        status == GAUDIT_RUN_OK && run->have_result ? &run->result : NULL;
    if (result != NULL && S.result_listener != NULL)
        S.result_listener(run->command, result, S.result_listener_data);
    if (run->cancelled && status != GAUDIT_RUN_OK)
        status = GAUDIT_RUN_CANCELLED;
    run->on_done(status, result, run->user_data);
    for (guint i = 0; i < run->observers->len; i++) {
        Observer *o = &g_array_index(run->observers, Observer, i);
        o->on_done(status, result, o->user_data);
    }
    g_array_unref(run->observers);
    if (run->result.lines != NULL)
        g_ptr_array_unref(run->result.lines);
    g_free(run->command);
    g_strfreev(run->args);
    g_free(run);
}

static gboolean on_line(const char *line, gpointer user_data)
{
    (void)user_data;
    /* Only a run through the session hears from it. */
    Run *R = S.run != NULL && !S.run->user ? S.run : NULL;
    gaudit_run_event ev;
    if (gaudit_run_parse_line(line, &ev) != 0)
        return FALSE;
    switch (ev.type) {
    case GAUDIT_RUN_EVENT_ELEVATED:
        if (ev.elevated == S.elevated)
            return FALSE;  /* only on, then off */
        set_elevated(ev.elevated);
        if (ev.elevated && R != NULL && R->on_progress != NULL)
            R->on_progress(R->user_data);
        for (guint i = 0; ev.elevated && R != NULL && i < R->observers->len; i++) {
            Observer *o = &g_array_index(R->observers, Observer, i);
            if (o->on_progress != NULL)
                o->on_progress(o->user_data);
        }
        return TRUE;
    case GAUDIT_RUN_EVENT_FIREWALL:
        if (R == NULL || !R->wants_result || R->have_result || R->result.n_files > 0)
            return FALSE;  /* unasked, twice, or after another kind's findings */
        R->have_result = TRUE;
        R->result.kind = GAUDIT_RESULT_FIREWALL;
        R->result.firewall = ev.firewall;
        return TRUE;
    case GAUDIT_RUN_EVENT_INTEGRITY_FILE:
        if (R == NULL || !R->wants_result || R->have_result
            || R->result.n_files >= GAUDIT_INTEGRITY_SHOWN)
            return FALSE;  /* unasked, after the result, or too many */
        R->result.files[R->result.n_files++] = ev.file;
        return TRUE;
    case GAUDIT_RUN_EVENT_INTEGRITY:
        if (R == NULL || !R->wants_result || R->have_result
            || ev.integrity.shown != R->result.n_files)
            return FALSE;  /* unasked, twice, or not the findings it says it listed */
        R->have_result = TRUE;
        R->result.kind = GAUDIT_RESULT_INTEGRITY;
        R->result.integrity = ev.integrity;
        return TRUE;
    case GAUDIT_RUN_EVENT_END:
        if (R == NULL)
            return FALSE;
        if (ev.status == GAUDIT_RUN_OK && R->wants_result != R->have_result)
            return FALSE;  /* OK without the result asked for */
        if (ev.status == GAUDIT_RUN_OK && !R->wants_result && !S.elevated)
            return FALSE;  /* "elevate" ok, but the helper never started */
        end_run(ev.status);
        return TRUE;
    default:
        return FALSE;
    }
}

/* --- Runs as the user ------------------------------------------------------ */

/* Home's runs are kept short; the full run (with the plugin's parameters,
 * e.g. large or network folders) has no limit here: page 2 asks now and
 * then whether to go on, and it can always be stopped. Progress lines make
 * a long run's output larger, so its limit is too. */
#define HOME_RUN_TIMEOUT_S (5 * 60)
#define USER_RUN_MAX_OUTPUT (1024 * 1024)

/* A line of a collection, checked by the plugin it belongs to; nothing
 * may come after the last. */
#define MAX_COLLECTION_LINES 1024

static gboolean on_user_line(const char *line, gpointer user_data)
{
    Run *run = user_data;
    gboolean last = FALSE;
    /* "(progress (count N) (where "..."))": shown while it runs, not
     * collected. */
    if (g_str_has_prefix(line, "(progress ")) {
        long long count;
        char where[sizeof run->where];
        const gaudit_sexpr_field fields[] = {
            { .key = "count", .value = &count, .max = 100000000000LL },
            { .key = "where", .text = where, .text_len = sizeof where },
        };
        if (S.run != run || run->have_result || gaudit_sexpr_parse(line, "progress", fields, 2) != 0)
            return FALSE;
        run->progress = (guint64)count;
        g_strlcpy(run->where, where, sizeof run->where);
        return TRUE;
    }
    if (S.run != run || run->have_result || run->result.lines->len >= MAX_COLLECTION_LINES
        || !run->collection_line(line, &last))
        return FALSE;
    g_ptr_array_add(run->result.lines, g_strdup(line));
    if (last) {
        run->result.kind = GAUDIT_RESULT_COLLECTION;
        run->have_result = TRUE;
    }
    return TRUE;
}

static void on_user_done(gboolean broken, gpointer user_data)
{
    Run *run = user_data;
    if (S.run != run)
        return;
    if (broken)
        g_warning("gaudit: a run as the user broke the protocol");
    end_run(!broken && run->have_result ? GAUDIT_RUN_OK : GAUDIT_RUN_FAILED);
}

static void on_done(gboolean broken, gpointer user_data)
{
    (void)user_data;
    if (broken)
        g_warning("gaudit: the session broke the protocol; ending it");
    S.orch = NULL;
    set_elevated(FALSE);  /* whatever happened, the helper is gone */
    if (S.run != NULL && !S.run->user)
        end_run(GAUDIT_RUN_FAILED);
}

static gboolean on_watchdog(gpointer user_data)
{
    (void)user_data;
    S.watchdog_id = 0;
    g_warning("gaudit: a run did not end in time; ending the session");
    if (S.orch != NULL)
        gaudit_orchestrator_stop(S.orch);  /* on_done ends the run */
    return G_SOURCE_REMOVE;
}

gboolean gaudit_session_run(const char *command, GauditRunProgressFn on_progress,
                            GauditRunDoneFn on_done_fn, gpointer user_data)
{
    return gaudit_session_run_args(command, NULL, on_progress, on_done_fn, user_data);
}

gboolean gaudit_session_run_args(const char *command, const char *const *extra,
                                 GauditRunProgressFn on_progress, GauditRunDoneFn on_done_fn,
                                 gpointer user_data)
{
    g_return_val_if_fail(command != NULL && on_done_fn != NULL, FALSE);
    if (S.run != NULL)
        return FALSE;

    Run *run = g_new0(Run, 1);
    run->command = g_strdup(command);
    run->args = extra != NULL ? g_strdupv((char **)extra) : g_new0(char *, 1);
    run->result.full = extra != NULL;
    run->on_progress = on_progress;
    run->on_done = on_done_fn;
    run->user_data = user_data;
    run->wants_result = g_strcmp0(command, "elevate") != 0;
    run->started = g_get_monotonic_time();
    run->observers = g_array_new(FALSE, FALSE, sizeof(Observer));
    S.run = run;

    if (g_str_has_prefix(command, "user ")) {
        /* As the user: an orchestrator of its own, with its own timeout. */
        const char *mode = command + strlen("user ");
        const GauditTaskInfo *task = gaudit_task_for_command(command, NULL);
        run->collection_line = task != NULL ? task->collection_line : NULL;
        run->user = TRUE;
        if (run->collection_line == NULL) {
            end_run(GAUDIT_RUN_FAILED);  /* no plugin to check its lines */
            return TRUE;
        }
        run->result.lines = g_ptr_array_new_with_free_func(g_free);
        /* The mode and its argument, from the plugin's fixed table, then
         * the run's parameters, each one argument as it is. */
        g_auto(GStrv) fixed = g_strsplit(mode, " ", 3);
        if (g_strv_length(fixed) > 2) {
            end_run(GAUDIT_RUN_FAILED);
            return TRUE;
        }
        g_autoptr(GStrvBuilder) b = g_strv_builder_new();
        g_strv_builder_addv(b, (const char **)fixed);
        g_strv_builder_addv(b, (const char **)run->args);
        g_auto(GStrv) args = g_strv_builder_end(b);
        if (on_progress != NULL)
            on_progress(user_data);  /* no password to wait for */
        GauditOrchestrator *orch = gaudit_orchestrator_start_limit(
            (const char *const *)args, run->result.full ? 0 : HOME_RUN_TIMEOUT_S, FALSE,
            USER_RUN_MAX_OUTPUT, on_user_line, on_user_done, run);
        if (S.run == run)  /* it may already have ended, if it could not start */
            run->user_orch = orch;
        return TRUE;
    }
    S.watchdog_id = g_timeout_add_seconds(RUN_WATCHDOG_S, on_watchdog, NULL);

    if (S.orch == NULL) {
        static const char *const args[] = { "session", NULL };
        S.orch = gaudit_orchestrator_start(args, 0, TRUE, on_line, on_done, NULL);
        if (S.orch == NULL)
            return TRUE;  /* on_done has ended the run as failed */
    }
    g_autofree char *line = g_strdup_printf("%s\n", command);
    if (!gaudit_orchestrator_send(S.orch, line)) {
        gaudit_orchestrator_stop(S.orch);  /* on_done ends the run */
        return TRUE;
    }
    if (S.elevated && on_progress != NULL)
        on_progress(user_data);  /* the lease is still running: no password */
    return TRUE;
}

const char *gaudit_session_running(void)
{
    return S.run != NULL ? S.run->command : NULL;
}

gboolean gaudit_session_running_long(void)
{
    return S.run != NULL && S.run->wants_result
           && g_get_monotonic_time() - S.run->started > 10 * G_USEC_PER_SEC;
}

guint64 gaudit_session_progress(const char **where)
{
    if (where != NULL)
        *where = S.run != NULL && S.run->where[0] != '\0' ? S.run->where : NULL;
    return S.run != NULL ? S.run->progress : 0;
}

gboolean gaudit_session_running_is(const char *command, const char *const *args)
{
    if (S.run == NULL || g_strcmp0(S.run->command, command) != 0)
        return FALSE;
    static const char *const none[] = { NULL };
    return g_strv_equal((const char *const *)S.run->args, args != NULL ? args : none);
}

gboolean gaudit_session_attach(GauditRunProgressFn on_progress, GauditRunDoneFn done,
                               gpointer user_data)
{
    g_return_val_if_fail(done != NULL, FALSE);
    if (S.run == NULL)
        return FALSE;
    Observer o = { on_progress, done, user_data };
    g_array_append_val(S.run->observers, o);
    /* Already past the password: tell it at once, as the run itself was. */
    if (on_progress != NULL && (S.run->user || S.elevated))
        on_progress(user_data);
    return TRUE;
}

void gaudit_session_cancel(void)
{
    Run *run = S.run;
    if (run == NULL)
        return;
    run->cancelled = TRUE;
    if (run->user) {
        if (run->user_orch != NULL)
            gaudit_orchestrator_stop(run->user_orch);  /* our own: ends at once */
        return;
    }
    /* Through the session: while pkexec waits for the password it is ours
     * to stop; once the helper is root it can only be asked to end, and
     * finishes the check under way first (each has its own limit). Either
     * way the session ends, and with it the run. */
    if (S.orch != NULL)
        gaudit_orchestrator_stop(S.orch);
}

gboolean gaudit_session_elevated(void)
{
    return S.elevated;
}

void gaudit_session_set_elevated_listener(void (*fn)(gboolean on, gpointer user_data),
                                          gpointer user_data)
{
    S.listener = fn;
    S.listener_data = user_data;
}

gaudit_verdict gaudit_run_result_verdict(const GauditRunResult *result)
{
    if (result == NULL)
        return GAUDIT_VERDICT_UNKNOWN;
    switch (result->kind) {
    case GAUDIT_RESULT_FIREWALL:  return result->firewall.verdict;
    case GAUDIT_RESULT_INTEGRITY: return result->integrity.verdict;
    case GAUDIT_RESULT_COLLECTION: return GAUDIT_VERDICT_UNKNOWN;
    }
    return GAUDIT_VERDICT_UNKNOWN;
}

void gaudit_session_set_result_listener(void (*fn)(const char *command,
                                                   const GauditRunResult *result,
                                                   gpointer user_data),
                                        gpointer user_data)
{
    S.result_listener = fn;
    S.result_listener_data = user_data;
}

void gaudit_session_drop(void)
{
    if (S.orch != NULL)
        gaudit_orchestrator_send(S.orch, "quit\n");
}

void gaudit_session_end(void)
{
    if (S.orch != NULL)
        gaudit_orchestrator_close_input(S.orch);
}
