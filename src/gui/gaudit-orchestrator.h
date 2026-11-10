/* SPDX-License-Identifier: GPL-3.0-only */
/* Starting gaudit-orchestrator and reading its answer line by line. Its
 * output is untrusted input: at most 64 KiB, lines below 1 KiB without NUL
 * bytes, a timeout. What a line means is up to the caller. */
#pragma once

#include <glib.h>

G_BEGIN_DECLS

/* One complete line, without the newline. FALSE: the line breaks the
 * protocol; nothing more is read. */
typedef gboolean (*GauditOrchestratorLineFn)(const char *line, gpointer user_data);

/* Called exactly once at the end, also when the orchestrator could not be
 * started. broken: the protocol was broken (by a line, too much output, or
 * output ending mid-line), so nothing from this run can be trusted. A
 * timeout or a failed exit is not broken: answers may just be missing. */
typedef void (*GauditOrchestratorDoneFn)(gboolean broken, gpointer user_data);

typedef struct _GauditOrchestrator GauditOrchestrator;

/* Starts the orchestrator with args (NULL-terminated, may be NULL) and an
 * empty environment except HOME. timeout_s: 0 for none. interactive: its
 * stdin stays open for gaudit_orchestrator_send; otherwise it is closed at
 * once. The application is held until done. The handle is valid until
 * on_done has returned; NULL if it could not be started (on_done has then
 * already been called). */
GauditOrchestrator *gaudit_orchestrator_start(const char *const *args, guint timeout_s,
                                              gboolean interactive,
                                              GauditOrchestratorLineFn on_line,
                                              GauditOrchestratorDoneFn on_done, gpointer user_data);

/* Writes text (lines ending in a newline) to its stdin. FALSE on failure. */
gboolean gaudit_orchestrator_send(GauditOrchestrator *orch, const char *text);

/* Closes its stdin: an interactive orchestrator then finishes and exits
 * on its own (on_done follows). */
void gaudit_orchestrator_close_input(GauditOrchestrator *orch);

/* Ends it at once (on_done follows). */
void gaudit_orchestrator_stop(GauditOrchestrator *orch);

G_END_DECLS
