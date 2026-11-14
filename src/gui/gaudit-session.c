/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "gaudit-orchestrator.h"
#include "gaudit-session.h"

#include <string.h>

/* The orchestrator gives a run at most 20 minutes (the integrity check;
 * others less); this is the GUI's own limit on top. */
#define RUN_WATCHDOG_S (21 * 60)

typedef struct {
    char *command;
    GauditRunProgressFn on_progress;
    GauditRunDoneFn on_done;
    gpointer user_data;
    gboolean wants_result;  /* FALSE for "elevate", which only starts the helper */
    gboolean user;          /* runs as the user, not through the session */
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
    run->on_done(status, result, run->user_data);
    g_free(run->command);
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

/* The deep scan takes about 10 s on a large home. */
#define USER_RUN_TIMEOUT_S 120

/* A line of "user secrets": findings, then the summary, strictly. */
static gboolean on_user_line(const char *line, gpointer user_data)
{
    Run *run = user_data;
    if (S.run != run || run->have_result)
        return FALSE;  /* nothing after the summary */
    gaudit_secret_finding f;
    gaudit_secrets_summary sum;
    switch (gaudit_secrets_parse_line(line, &f, &sum)) {
    case 1:
        if (run->result.n_secrets >= GAUDIT_SECRETS_MAX_SHOWN)
            return FALSE;
        run->result.secret[run->result.n_secrets++] = f;
        return TRUE;
    case 2:
        if (sum.shown != run->result.n_secrets)
            return FALSE;  /* not the findings it says it sent */
        run->result.kind = GAUDIT_RESULT_SECRETS;
        run->result.secrets = sum;
        run->have_result = TRUE;
        return TRUE;
    default:
        return FALSE;
    }
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
    g_return_val_if_fail(command != NULL && on_done_fn != NULL, FALSE);
    if (S.run != NULL)
        return FALSE;

    Run *run = g_new0(Run, 1);
    run->command = g_strdup(command);
    run->on_progress = on_progress;
    run->on_done = on_done_fn;
    run->user_data = user_data;
    run->wants_result = g_strcmp0(command, "elevate") != 0;
    S.run = run;

    if (g_str_has_prefix(command, "user ")) {
        /* As the user: an orchestrator of its own, with its own timeout. */
        const char *mode = command + strlen("user ");
        if (strcmp(mode, "secrets") != 0) {
            end_run(GAUDIT_RUN_FAILED);
            return TRUE;
        }
        run->user = TRUE;
        const char *args[] = { mode, NULL };
        if (on_progress != NULL)
            on_progress(user_data);  /* no password to wait for */
        gaudit_orchestrator_start(args, USER_RUN_TIMEOUT_S, FALSE, on_user_line, on_user_done, run);
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
    case GAUDIT_RESULT_SECRETS:   return gaudit_secrets_verdict(&result->secrets);
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
