/* SPDX-License-Identifier: GPL-3.0-only */
/* Runs on request through one long-lived orchestrator session, so the
 * helper can keep its elevated rights between runs within its lease. One
 * run at a time. The lease itself is decided by the helper. */
#pragma once

#include <glib.h>

#include "gaudit/run.h"

G_BEGIN_DECLS

/* When a run has ended: status, and the result when status is
 * GAUDIT_RUN_OK (NULL otherwise). */
typedef void (*GauditRunDoneFn)(gaudit_run_status status, const gaudit_firewall_report *result,
                                gpointer user_data);

/* When the run has elevated rights and is under way (at once, if the
 * lease is still running). May be NULL. */
typedef void (*GauditRunProgressFn)(gpointer user_data);

/* Starts the run command (e.g. "run firewall"). FALSE if another run is
 * under way; then nothing is called. */
gboolean gaudit_session_run(const char *command, GauditRunProgressFn on_progress,
                            GauditRunDoneFn on_done, gpointer user_data);

/* Whether the helper holds elevated rights now. */
gboolean gaudit_session_elevated(void);

/* Called whenever that changes. */
void gaudit_session_set_elevated_listener(void (*fn)(gboolean on, gpointer user_data),
                                          gpointer user_data);

/* Ends the elevated rights now (the helper ends its lease). */
void gaudit_session_drop(void);

/* Ends the session altogether, e.g. when the last window closes. */
void gaudit_session_end(void);

G_END_DECLS
