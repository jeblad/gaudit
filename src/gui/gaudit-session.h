/* SPDX-License-Identifier: GPL-3.0-only */
/* Runs on request through one long-lived orchestrator session, so the
 * helper can keep its elevated rights between runs within its lease. One
 * run at a time. The lease itself is decided by the helper. */
#pragma once

#include <glib.h>

#include "gaudit/run.h"

G_BEGIN_DECLS

typedef enum {
    GAUDIT_RESULT_FIREWALL,
    GAUDIT_RESULT_INTEGRITY,
    GAUDIT_RESULT_COLLECTION,  /* collected data for the plugin's rule script */
} GauditResultKind;

/* What a run found: one kind of result, with its findings. */
typedef struct {
    GauditResultKind kind;
    gaudit_firewall_report firewall;
    gaudit_integrity_report integrity;
    gaudit_integrity_file files[GAUDIT_INTEGRITY_SHOWN];
    unsigned n_files;
    GPtrArray *lines;  /* COLLECTION: its lines (char *), each checked by the plugin */
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
 * without a password. FALSE if another run is under way; then nothing is
 * called. */
gboolean gaudit_session_run(const char *command, GauditRunProgressFn on_progress,
                            GauditRunDoneFn on_done, gpointer user_data);

/* The same, with the run's parameters as arguments (NULL-terminated, may
 * be NULL), passed on as they are; only for runs as the user ("user ..."),
 * e.g. the folders a collection searches. */
gboolean gaudit_session_run_args(const char *command, const char *const *args,
                                 GauditRunProgressFn on_progress, GauditRunDoneFn on_done,
                                 gpointer user_data);

/* The command of the run under way (e.g. "user secrets quick"), or NULL. */
const char *gaudit_session_running(void);

/* Whether the run under way is command with exactly these arguments (the
 * same parameters). */
gboolean gaudit_session_running_is(const char *command, const char *const *args);

/* Waits for the run under way as well: on_done (and on_progress, may be
 * NULL) are called as for the one who started it. FALSE when none runs. */
gboolean gaudit_session_attach(GauditRunProgressFn on_progress, GauditRunDoneFn on_done,
                               gpointer user_data);

/* Stops the run under way; it ends as GAUDIT_RUN_CANCELLED. A run as the
 * user stops at once. One through the helper ends the session: while the
 * password is asked for, at once; once the helper runs as root, after the
 * check under way (it cannot be killed from the user's side). */
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
