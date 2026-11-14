/* SPDX-License-Identifier: GPL-3.0-only */
/* Runs on request through one long-lived orchestrator session, so the
 * helper can keep its elevated rights between runs within its lease. One
 * run at a time. The lease itself is decided by the helper. */
#pragma once

#include <glib.h>

#include "gaudit/run.h"

G_BEGIN_DECLS

/* What a run found: one kind of result, with its findings. */
typedef struct {
    gaudit_run_event_type kind;  /* GAUDIT_RUN_EVENT_FIREWALL or _INTEGRITY */
    gaudit_firewall_report firewall;
    gaudit_integrity_report integrity;
    gaudit_integrity_file files[GAUDIT_INTEGRITY_SHOWN];
    unsigned n_files;
} GauditRunResult;

/* The verdict of a result. */
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
 * GAUDIT_RUN_OK without a result. FALSE if another run is under way; then
 * nothing is called. */
gboolean gaudit_session_run(const char *command, GauditRunProgressFn on_progress,
                            GauditRunDoneFn on_done, gpointer user_data);

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
