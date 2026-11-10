/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "gaudit-orchestrator.h"
#include "gaudit-session.h"

/* A run waits for the password at most 5 minutes in the orchestrator;
 * this is the GUI's own limit on top. */
#define RUN_WATCHDOG_S (6 * 60)

typedef struct {
    char *command;
    GauditRunProgressFn on_progress;
    GauditRunDoneFn on_done;
    gpointer user_data;
    gboolean have_result;
    gaudit_firewall_report result;
} Run;

static struct {
    GauditOrchestrator *orch;  /* NULL while no session runs */
    gboolean elevated;
    Run *run;                  /* the run under way, if any */
    guint watchdog_id;
    void (*listener)(gboolean on, gpointer user_data);
    gpointer listener_data;
    void (*result_listener)(const char *command, const gaudit_firewall_report *result,
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
    const gaudit_firewall_report *result =
        status == GAUDIT_RUN_OK && run->have_result ? &run->result : NULL;
    if (result != NULL && S.result_listener != NULL)
        S.result_listener(run->command, result, S.result_listener_data);
    run->on_done(status, result, run->user_data);
    g_free(run->command);
    g_free(run);
}

static gboolean on_line(const char *line, gpointer user_data)
{
    (void)user_data;
    gaudit_run_event ev;
    if (gaudit_run_parse_line(line, &ev) != 0)
        return FALSE;
    switch (ev.type) {
    case GAUDIT_RUN_EVENT_ELEVATED:
        if (ev.elevated == S.elevated)
            return FALSE;  /* only on, then off */
        set_elevated(ev.elevated);
        if (ev.elevated && S.run != NULL && S.run->on_progress != NULL)
            S.run->on_progress(S.run->user_data);
        return TRUE;
    case GAUDIT_RUN_EVENT_FIREWALL:
        if (S.run == NULL || S.run->have_result)
            return FALSE;  /* unasked, or twice */
        S.run->have_result = TRUE;
        S.run->result = ev.firewall;
        return TRUE;
    case GAUDIT_RUN_EVENT_END:
        if (S.run == NULL)
            return FALSE;
        if (ev.status == GAUDIT_RUN_OK && !S.run->have_result)
            return FALSE;  /* OK without a result */
        end_run(ev.status);
        return TRUE;
    default:
        return FALSE;
    }
}

static void on_done(gboolean broken, gpointer user_data)
{
    (void)user_data;
    if (broken)
        g_warning("gaudit: the session broke the protocol; ending it");
    S.orch = NULL;
    set_elevated(FALSE);  /* whatever happened, the helper is gone */
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
    g_return_val_if_fail(command != NULL && on_done_fn != NULL, FALSE);
    if (S.run != NULL)
        return FALSE;

    Run *run = g_new0(Run, 1);
    run->command = g_strdup(command);
    run->on_progress = on_progress;
    run->on_done = on_done_fn;
    run->user_data = user_data;
    S.run = run;
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

void gaudit_session_set_result_listener(void (*fn)(const char *command,
                                                   const gaudit_firewall_report *result,
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
