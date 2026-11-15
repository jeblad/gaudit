/* SPDX-License-Identifier: GPL-3.0-only */
/* Runs on request. Runs as the user each have an orchestrator of their
 * own and go side by side; the helper's parts go one at a time through one
 * long-lived orchestrator session, so the helper keeps its elevated rights
 * between them within its lease. The lease itself is decided by the
 * helper. */
#pragma once

#include <glib.h>

#include "gaudit/run.h"

G_BEGIN_DECLS

typedef enum {
    GAUDIT_RESULT_FIREWALL,
    GAUDIT_RESULT_INTEGRITY,
    GAUDIT_RESULT_COLLECTION,  /* collected data for the plugin's rule script */
    GAUDIT_RESULT_CONF,        /* what writing a configuration did */
} GauditResultKind;

/* What a run found: one kind of result, with its findings. */
typedef struct {
    GauditResultKind kind;
    gaudit_firewall_report firewall;
    gaudit_integrity_report integrity;
    gaudit_conf_report conf;
    gaudit_integrity_file files[GAUDIT_INTEGRITY_SHOWN];
    unsigned n_files;
    GPtrArray *lines;  /* COLLECTION: its lines (char *), each checked by the plugin */
    gboolean full;     /* started with the plugin's parameters (Run on Parameters);
                          FALSE for Home's runs, whose reports are simplified */
    GStrv args;        /* full: the parameters it was started with */
} GauditRunResult;

/* The verdict of a result (unknown for a collection: its report decides). */
gaudit_verdict gaudit_run_result_verdict(const GauditRunResult *result);

/* When a run has ended: status, and the result when status is
 * GAUDIT_RUN_OK (NULL otherwise). */
typedef void (*GauditRunDoneFn)(gaudit_run_status status, const GauditRunResult *result,
                                gpointer user_data);

/* When the run has elevated rights and is under way (at once, if the
 * lease is still running). May be NULL. */
typedef void (*GauditRunProgressFn)(gpointer user_data);

/* Starts the run command (e.g. "run firewall"). "elevate" only gets the
 * elevated rights (the password, unless the lease still runs) and ends
 * GAUDIT_RUN_OK without a result. "user <mode>" (e.g. "user secrets") runs
 * as the user, in an orchestrator of its own, without the helper and
 * without a password. FALSE if a run of the same task is under way; then
 * nothing is called. */
gboolean gaudit_session_run(const char *command, GauditRunProgressFn on_progress,
                            GauditRunDoneFn on_done, gpointer user_data);

/* The same, with the run's parameters as arguments (NULL-terminated; NULL
 * for none), passed on as they are; only for runs as the user ("user ..."),
 * e.g. the folders a collection searches. A run given its parameters (even
 * an empty list) is the full one; without, it is Home's, simplified. */
gboolean gaudit_session_run_args(const char *command, const char *const *args,
                                 GauditRunProgressFn on_progress, GauditRunDoneFn on_done,
                                 gpointer user_data);

/* A run that needs administrator rights never asks for the password
 * itself: without the lease its helper part waits, without a time limit,
 * for the user to give it with the switch. Runs as the user go on side by
 * side meanwhile. Told with the run's command when it starts waiting
 * (TRUE; first: the first time for this run) and when it stops (FALSE:
 * going on, or ended). */
typedef void (*GauditSessionWaitingFn)(const char *command, gboolean waiting, gboolean first,
                                       gpointer user_data);
guint gaudit_session_watch_waiting(GauditSessionWaitingFn fn, gpointer user_data);
void gaudit_session_unwatch_waiting(guint id);

/* Whether the run of command's task waits for administrator rights. */
gboolean gaudit_session_waiting_for(const char *command);

/* Whether any run waits for them. */
gboolean gaudit_session_any_waiting(void);

/* The switch: every waiting run goes on; the first asks for the password,
 * the others follow within the lease. FALSE when none waits. A cancelled
 * or refused password ends all of them as cancelled. */
gboolean gaudit_session_resume(void);

/* Runs of one task are one at a time; runs of different tasks go side by
 * side (the helper's parts in turn). The command of the run of command's
 * task under way, or NULL. */
const char *gaudit_session_running_for(const char *command);

/* The parameters of the run of command's task: NULL for Home's (simplified)
 * run, or none under way. */
const char *const *gaudit_session_running_args(const char *command);

/* Whether any run is under way and has gone on for more than 10 seconds:
 * a heavy one, worth asking about before closing. */
gboolean gaudit_session_running_long(void);

/* How far the run of command's task has come: entries looked at, from its
 * progress lines (0 for none, or a run that does not report it), and in
 * *where (may be NULL) the folder it is in, as data from the run. */
guint64 gaudit_session_progress(const char *command, const char **where);

/* Whether the run of command's task is command with exactly these
 * arguments (the same parameters). */
gboolean gaudit_session_running_is(const char *command, const char *const *args);

/* Waits for the run of command's task as well: on_done (and on_progress,
 * may be NULL) are called as for the one who started it. FALSE when none
 * runs. */
gboolean gaudit_session_attach(const char *command, GauditRunProgressFn on_progress,
                               GauditRunDoneFn on_done, gpointer user_data);

/* Stops the run of command's task; it ends as GAUDIT_RUN_CANCELLED. */
void gaudit_session_cancel_for(const char *command);

/* Stops every run under way; each ends as GAUDIT_RUN_CANCELLED. A run as
 * the user stops at once, one waiting for its turn too. One through the
 * helper ends the session: while the password is asked for, at once; once
 * the helper runs as root, after the check under way (it cannot be killed
 * from the user's side). */
void gaudit_session_cancel(void);

/* Whether the helper holds elevated rights now. */
gboolean gaudit_session_elevated(void);

/* Called whenever that changes. */
void gaudit_session_set_elevated_listener(void (*fn)(gboolean on, gpointer user_data),
                                          gpointer user_data);

/* Called for every run that ended with a result, whoever started it,
 * before that run's own on_done. command: as given to gaudit_session_run. */
void gaudit_session_set_result_listener(void (*fn)(const char *command,
                                                   const GauditRunResult *result,
                                                   gpointer user_data),
                                        gpointer user_data);

/* Ends the elevated rights now (the helper ends its lease). */
void gaudit_session_drop(void);

/* Ends the session altogether, e.g. when the last window closes. */
void gaudit_session_end(void);

G_END_DECLS
