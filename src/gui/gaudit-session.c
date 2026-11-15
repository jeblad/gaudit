/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "collector.h"
#include "gaudit-orchestrator.h"
#include "gaudit-session.h"
#include "gaudit-task.h"

#include <string.h>

/* The orchestrator gives a run at most 20 minutes (the integrity check;
 * others less); this is the GUI's own limit on top. */
#define RUN_WATCHDOG_S (52 * 60)  /* an upgrade may take 50 minutes */

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
    /* A compound run ("user <mode> then run <check>"): the collection as
     * the user first, then the check in the helper, whose lines join the
     * same collection. then: the helper's command while it is still to
     * come; collected: the user part's lines once it has given them. */
    char *then;
    GPtrArray *collected;
    /* Its helper part, queued for the session (helper: the command to send).
     * waiting: no administrator rights, so it waits for the user to give
     * the password with the switch, without a time limit; told: the
     * watchers have heard it waits at least once. */
    char *helper;
    gboolean waiting;
    gboolean told;
} Run;

/* Who wants to know when a run starts or stops waiting. */
typedef struct {
    guint id;
    GauditSessionWaitingFn fn;
    gpointer data;
} Watcher;

/* Runs as the user go side by side, each in an orchestrator of its own;
 * the helper's parts go one at a time through the one session, in order. */
static struct {
    GauditOrchestrator *orch;  /* NULL while no session runs */
    gboolean elevated;
    GPtrArray *runs;           /* Run: every run under way */
    GQueue queue;              /* Run: helper parts not yet sent */
    Run *helper_run;           /* the one the session works on */
    gboolean asking;           /* the switch let the queue go: the password is asked for */
    guint watchdog_id;
    void (*listener)(gboolean on, gpointer user_data);
    gpointer listener_data;
    void (*result_listener)(const char *command, const GauditRunResult *result,
                            gpointer user_data);
    gpointer result_listener_data;
    GArray *watchers;          /* Watcher */
    guint next_watcher;
} S;

static gboolean is_live(const Run *run)
{
    return run != NULL && S.runs != NULL && g_ptr_array_find(S.runs, run, NULL);
}

/* Runs of the same task are the same work: one at a time. */
static gboolean same_task(const char *a, const char *b)
{
    const GauditTaskInfo *ta = gaudit_task_for_command(a, NULL);
    const GauditTaskInfo *tb = gaudit_task_for_command(b, NULL);
    return ta != NULL || tb != NULL ? ta == tb : g_strcmp0(a, b) == 0;
}

static Run *run_for(const char *command)
{
    for (guint i = 0; command != NULL && S.runs != NULL && i < S.runs->len; i++) {
        Run *run = g_ptr_array_index(S.runs, i);
        if (same_task(run->command, command))
            return run;
    }
    return NULL;
}

static void notify_waiting(Run *run, gboolean waiting)
{
    gboolean first = waiting && !run->told;
    if (waiting)
        run->told = TRUE;
    if (S.watchers == NULL)
        return;
    /* A copy: a watcher may unwatch while told. */
    g_autoptr(GArray) copy = g_array_copy(S.watchers);
    for (guint i = 0; i < copy->len; i++) {
        Watcher *w = &g_array_index(copy, Watcher, i);
        w->fn(run->command, waiting, first, w->data);
    }
}

static void set_waiting(Run *run, gboolean waiting)
{
    if (run->waiting == waiting)
        return;
    run->waiting = waiting;
    notify_waiting(run, waiting);
}

static void set_elevated(gboolean on)
{
    if (S.elevated == on)
        return;
    S.elevated = on;
    if (S.listener != NULL)
        S.listener(on, S.listener_data);
}

static void pump(void);

static void free_run(Run *run)
{
    g_array_unref(run->observers);
    if (run->collected != NULL)
        g_ptr_array_unref(run->collected);
    g_free(run->then);
    g_free(run->helper);
    if (run->result.lines != NULL)
        g_ptr_array_unref(run->result.lines);
    g_strfreev(run->result.args);
    g_free(run->command);
    g_strfreev(run->args);
    g_free(run);
}

static void end_run(Run *run, gaudit_run_status status)
{
    if (!is_live(run))
        return;
    g_ptr_array_remove(S.runs, run);
    g_queue_remove(&S.queue, run);
    gboolean was_helper = S.helper_run == run;
    if (was_helper) {
        S.helper_run = NULL;
        if (S.watchdog_id != 0) {
            g_source_remove(S.watchdog_id);
            S.watchdog_id = 0;
        }
    }
    set_waiting(run, FALSE);
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
    free_run(run);

    /* The password cancelled or refused: everything waiting for it ends
     * too, so the dialog's Cancel is the way to give up on them. */
    if (was_helper && !S.elevated
        && (status == GAUDIT_RUN_CANCELLED || status == GAUDIT_RUN_DENIED)) {
        Run *next;
        while ((next = g_queue_peek_head(&S.queue)) != NULL) {
            next->cancelled = TRUE;
            end_run(next, GAUDIT_RUN_CANCELLED);
        }
    }
    pump();
}

static gboolean join_collection(Run *run);

static gboolean on_line(const char *line, gpointer user_data)
{
    (void)user_data;
    /* Only the run the session works on hears from it. */
    Run *R = S.helper_run;
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
    case GAUDIT_RUN_EVENT_CONF:
        if (R == NULL || !R->wants_result || R->have_result || R->result.n_files > 0)
            return FALSE;  /* unasked, twice, or after another kind's findings */
        R->have_result = TRUE;
        R->result.kind = GAUDIT_RESULT_CONF;
        R->result.conf = ev.conf;
        return TRUE;
    case GAUDIT_RUN_EVENT_EXEC:
        if (R == NULL || !R->wants_result || R->have_result || R->result.n_files > 0)
            return FALSE;
        R->have_result = TRUE;
        R->result.kind = GAUDIT_RESULT_EXEC;
        R->result.exec = ev.exec;
        return TRUE;
    case GAUDIT_RUN_EVENT_END:
        if (R == NULL)
            return FALSE;
        if (ev.status == GAUDIT_RUN_OK && R->wants_result != R->have_result)
            return FALSE;  /* OK without the result asked for */
        if (ev.status == GAUDIT_RUN_OK && R->collected != NULL && !join_collection(R))
            return FALSE;  /* the helper's part does not fit the collection */
        if (ev.status == GAUDIT_RUN_OK && !R->wants_result && !S.elevated)
            return FALSE;  /* "elevate" ok, but the helper never started */
        end_run(R, ev.status);
        return TRUE;
    default:
        return FALSE;
    }
}

/* A compound run's helper part into its collection: the user part's lines,
 * then the helper's findings and result in their own strict format, each
 * checked by the plugin like every other line. FALSE when they do not fit:
 * the run then fails, rather than give half a collection. */
#define MAX_COLLECTION_LINES 1024

static gboolean join_collection(Run *run)
{
    if (run->result.kind != GAUDIT_RESULT_INTEGRITY || run->collection_line == NULL)
        return FALSE;
    GPtrArray *lines = g_ptr_array_new_with_free_func(g_free);
    for (guint i = 0; i < run->collected->len; i++)
        g_ptr_array_add(lines, g_strdup(g_ptr_array_index(run->collected, i)));
    gboolean ok = TRUE;
    for (guint i = 0; ok && i <= run->result.n_files; i++) {
        gaudit_run_event ev = { 0 };
        if (i < run->result.n_files) {
            ev.type = GAUDIT_RUN_EVENT_INTEGRITY_FILE;
            ev.file = run->result.files[i];
        } else {
            ev.type = GAUDIT_RUN_EVENT_INTEGRITY;
            ev.integrity = run->result.integrity;
        }
        char buf[1024];
        gboolean last = FALSE;
        ok = gaudit_run_format(&ev, buf, sizeof buf) == 0;
        if (ok)
            buf[strcspn(buf, "\n")] = '\0';
        ok = ok && lines->len < MAX_COLLECTION_LINES && run->collection_line(buf, &last);
        if (ok)
            g_ptr_array_add(lines, g_strdup(buf));
    }
    if (!ok) {
        g_ptr_array_unref(lines);
        return FALSE;
    }
    if (run->result.lines != NULL)
        g_ptr_array_unref(run->result.lines);
    run->result.lines = lines;
    run->result.kind = GAUDIT_RESULT_COLLECTION;
    return TRUE;
}

/* --- The helper's parts, one at a time ------------------------------------ */

static void on_done(gboolean broken, gpointer user_data);

static gboolean on_watchdog(gpointer user_data)
{
    (void)user_data;
    S.watchdog_id = 0;
    g_warning("gaudit: a run did not end in time; ending the session");
    if (S.orch != NULL)
        gaudit_orchestrator_stop(S.orch);  /* on_done ends the run */
    return G_SOURCE_REMOVE;
}

/* The session sends it on to the helper, starting the helper first (pkexec
 * asks for the password) when the lease has ended. */
static void send_helper_part(Run *run)
{
    S.helper_run = run;
    S.watchdog_id = g_timeout_add_seconds(RUN_WATCHDOG_S, on_watchdog, NULL);
    if (S.orch == NULL) {
        static const char *const args[] = { "session", NULL };
        S.orch = gaudit_orchestrator_start(args, 0, TRUE, on_line, on_done, NULL);
        if (S.orch == NULL)
            return;  /* on_done has ended the run as failed */
    }
    g_autofree char *line = g_strdup_printf("%s\n", run->helper);
    if (!gaudit_orchestrator_send(S.orch, line)) {
        gaudit_orchestrator_stop(S.orch);  /* on_done ends the run */
        return;
    }
    if (S.elevated && run->on_progress != NULL)
        run->on_progress(run->user_data);  /* the lease is still running: no password */
}

/* The next helper part, if the session is free. Without the lease it never
 * asks for the password itself: every part queued then waits for the
 * switch (gaudit_session_resume). Only "elevate", the switch's own run,
 * goes on to ask. */
static void pump(void)
{
    if (S.helper_run != NULL)
        return;
    Run *head = g_queue_peek_head(&S.queue);
    if (head == NULL)
        return;
    if (!S.elevated && !S.asking && g_strcmp0(head->helper, "elevate") != 0) {
        for (GList *l = S.queue.head; l != NULL; l = l->next)
            set_waiting(l->data, TRUE);
        return;
    }
    g_queue_pop_head(&S.queue);
    S.asking = FALSE;
    set_waiting(head, FALSE);
    send_helper_part(head);
}

static void queue_helper_part(Run *run, const char *command)
{
    g_free(run->helper);
    run->helper = g_strdup(command);
    g_queue_push_tail(&S.queue, run);
    pump();
}

static void on_done(gboolean broken, gpointer user_data)
{
    (void)user_data;
    if (broken)
        g_warning("gaudit: the session broke the protocol; ending it");
    S.orch = NULL;
    set_elevated(FALSE);  /* whatever happened, the helper is gone */
    if (S.helper_run != NULL)
        end_run(S.helper_run, GAUDIT_RUN_FAILED);
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
static gboolean on_user_line(const char *line, gpointer user_data)
{
    Run *run = user_data;
    if (!is_live(run))
        return FALSE;
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
        if (run->have_result || gaudit_sexpr_parse(line, "progress", fields, 2) != 0)
            return FALSE;
        run->progress = (guint64)count;
        g_strlcpy(run->where, where, sizeof run->where);
        return TRUE;
    }
    /* The helper's lines (a check's findings and result) come only from
     * the helper: never from a run as the user, whatever the plugin takes. */
    gaudit_run_event ev;
    if (gaudit_run_parse_line(line, &ev) == 0)
        return FALSE;
    if (run->have_result || run->result.lines->len >= MAX_COLLECTION_LINES
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
    if (!is_live(run))
        return;
    if (broken)
        g_warning("gaudit: a run as the user broke the protocol");
    run->user_orch = NULL;
    if (!broken && run->have_result && run->then != NULL && !run->cancelled) {
        /* The user part is in: now the helper's, through the session. */
        run->collected = g_steal_pointer(&run->result.lines);
        run->have_result = FALSE;
        run->user = FALSE;
        g_autofree char *then = g_steal_pointer(&run->then);
        queue_helper_part(run, then);
        return;
    }
    end_run(run, !broken && run->have_result ? GAUDIT_RUN_OK : GAUDIT_RUN_FAILED);
}

/* --- Starting runs ----------------------------------------------------------- */

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
    if (run_for(command) != NULL)
        return FALSE;  /* the same work is under way */
    if (S.runs == NULL)
        S.runs = g_ptr_array_new();

    Run *run = g_new0(Run, 1);
    run->command = g_strdup(command);
    run->args = extra != NULL ? g_strdupv((char **)extra) : g_new0(char *, 1);
    run->result.full = extra != NULL;
    run->result.args = extra != NULL ? g_strdupv((char **)extra) : NULL;
    run->on_progress = on_progress;
    run->on_done = on_done_fn;
    run->user_data = user_data;
    run->wants_result = g_strcmp0(command, "elevate") != 0;
    run->started = g_get_monotonic_time();
    run->observers = g_array_new(FALSE, FALSE, sizeof(Observer));
    g_ptr_array_add(S.runs, run);

    if (!g_str_has_prefix(command, "user ")) {
        queue_helper_part(run, command);
        return TRUE;
    }
    /* As the user: an orchestrator of its own, with its own timeout. A
     * compound run's helper part comes after it (on_user_done). */
    g_autofree char *user_part = g_strdup(command + strlen("user "));
    char *then = strstr(user_part, " then ");
    if (then != NULL) {
        *then = '\0';
        run->then = g_strdup(then + strlen(" then "));
        if (!g_str_has_prefix(run->then, "run ")) {
            end_run(run, GAUDIT_RUN_FAILED);
            return TRUE;
        }
    }
    const GauditTaskInfo *task = gaudit_task_for_command(command, NULL);
    run->collection_line = task != NULL ? task->collection_line : NULL;
    run->user = TRUE;
    if (run->collection_line == NULL) {
        end_run(run, GAUDIT_RUN_FAILED);  /* no plugin to check its lines */
        return TRUE;
    }
    run->result.lines = g_ptr_array_new_with_free_func(g_free);
    /* The mode and its argument, from the plugin's fixed table, then the
     * run's parameters, each one argument as it is. */
    g_auto(GStrv) fixed = g_strsplit(user_part, " ", 3);
    if (g_strv_length(fixed) > 2) {
        end_run(run, GAUDIT_RUN_FAILED);
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
    if (is_live(run))  /* it may already have ended, if it could not start */
        run->user_orch = orch;
    return TRUE;
}

/* --- Asking about runs --------------------------------------------------------- */

const char *gaudit_session_running_for(const char *command)
{
    Run *run = run_for(command);
    return run != NULL ? run->command : NULL;
}

const char *const *gaudit_session_running_args(const char *command)
{
    Run *run = run_for(command);
    return run != NULL && run->result.full ? (const char *const *)run->args : NULL;
}

gboolean gaudit_session_running_long(void)
{
    for (guint i = 0; S.runs != NULL && i < S.runs->len; i++) {
        Run *run = g_ptr_array_index(S.runs, i);
        if (run->wants_result && g_get_monotonic_time() - run->started > 10 * G_USEC_PER_SEC)
            return TRUE;
    }
    return FALSE;
}

guint64 gaudit_session_progress(const char *command, const char **where)
{
    Run *run = run_for(command);
    if (where != NULL)
        *where = run != NULL && run->where[0] != '\0' ? run->where : NULL;
    return run != NULL ? run->progress : 0;
}

gboolean gaudit_session_running_is(const char *command, const char *const *args)
{
    Run *run = run_for(command);
    if (run == NULL || g_strcmp0(run->command, command) != 0)
        return FALSE;
    static const char *const none[] = { NULL };
    return g_strv_equal((const char *const *)run->args, args != NULL ? args : none);
}

gboolean gaudit_session_attach(const char *command, GauditRunProgressFn on_progress,
                               GauditRunDoneFn done, gpointer user_data)
{
    g_return_val_if_fail(done != NULL, FALSE);
    Run *run = run_for(command);
    if (run == NULL)
        return FALSE;
    Observer o = { on_progress, done, user_data };
    g_array_append_val(run->observers, o);
    /* Already past the password: tell it at once, as the run itself was. */
    if (on_progress != NULL && (run->user || (S.helper_run == run && S.elevated)))
        on_progress(user_data);
    return TRUE;
}

gboolean gaudit_session_waiting_for(const char *command)
{
    Run *run = run_for(command);
    return run != NULL && run->waiting;
}

gboolean gaudit_session_any_waiting(void)
{
    for (GList *l = S.queue.head; l != NULL; l = l->next)
        if (((Run *)l->data)->waiting)
            return TRUE;
    return FALSE;
}

gboolean gaudit_session_resume(void)
{
    if (!gaudit_session_any_waiting() || S.helper_run != NULL)
        return FALSE;
    /* All of them go on: the first asks for the password, the others
     * follow within the lease. */
    for (GList *l = S.queue.head; l != NULL; l = l->next)
        set_waiting(l->data, FALSE);
    S.asking = TRUE;
    pump();
    return TRUE;
}

guint gaudit_session_watch_waiting(GauditSessionWaitingFn fn, gpointer data)
{
    g_return_val_if_fail(fn != NULL, 0);
    if (S.watchers == NULL)
        S.watchers = g_array_new(FALSE, FALSE, sizeof(Watcher));
    Watcher w = { ++S.next_watcher, fn, data };
    g_array_append_val(S.watchers, w);
    return w.id;
}

void gaudit_session_unwatch_waiting(guint id)
{
    for (guint i = 0; S.watchers != NULL && i < S.watchers->len; i++)
        if (g_array_index(S.watchers, Watcher, i).id == id) {
            g_array_remove_index(S.watchers, i);
            return;
        }
}

/* --- Stopping runs -------------------------------------------------------------- */

static void cancel_run(Run *run)
{
    run->cancelled = TRUE;
    if (g_queue_find(&S.queue, run) != NULL) {
        end_run(run, GAUDIT_RUN_CANCELLED);  /* nothing started yet */
        return;
    }
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

void gaudit_session_cancel_for(const char *command)
{
    Run *run = run_for(command);
    if (run != NULL)
        cancel_run(run);
}

void gaudit_session_cancel(void)
{
    /* Those queued first, so none of them starts when the session frees. */
    Run *run;
    while ((run = g_queue_peek_tail(&S.queue)) != NULL) {
        run->cancelled = TRUE;
        end_run(run, GAUDIT_RUN_CANCELLED);
    }
    g_autoptr(GPtrArray) all = S.runs != NULL ? g_ptr_array_copy(S.runs, NULL, NULL) : NULL;
    for (guint i = 0; all != NULL && i < all->len; i++)
        if (is_live(g_ptr_array_index(all, i)))
            cancel_run(g_ptr_array_index(all, i));
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
    case GAUDIT_RESULT_CONF:       return GAUDIT_VERDICT_UNKNOWN;
    case GAUDIT_RESULT_EXEC:       return GAUDIT_VERDICT_UNKNOWN;
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
