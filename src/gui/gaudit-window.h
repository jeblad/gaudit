/* SPDX-License-Identifier: GPL-3.0-only */
/* View: presents verdicts. Holds no security logic. */
#pragma once

#include <adwaita.h>

#include "gaudit-session.h"

#include "gaudit/model.h"
#include "gaudit/probe.h"
#include "gaudit/run.h"

G_BEGIN_DECLS

#define GAUDIT_TYPE_WINDOW (gaudit_window_get_type())
G_DECLARE_FINAL_TYPE(GauditWindow, gaudit_window, GAUDIT, WINDOW, AdwApplicationWindow)

GauditWindow *gaudit_window_new(GtkApplication *app);

/* The user/administrator switch before the title follows the helper. */
void gaudit_window_set_elevated(GauditWindow *self, gboolean elevated);

/* Status for Home: probe results plus the overall verdict from the model. */
/* Status on Home, row by row: begin shows every row as being checked,
 * show_probe fills in one row as its answer arrives, finish sets the
 * summary once every row has its answer. */
void gaudit_window_begin_status(GauditWindow *self);
void gaudit_window_show_probe(GauditWindow *self, const gaudit_probe_result *result);
void gaudit_window_finish_status(GauditWindow *self, gaudit_verdict worst);

/* Home's tasks above Quick (home_level), run by the controller when the
 * user picks a level or switches to administrator. The chosen level;
 * running shows a task's row as being checked, failed says why a run gave
 * nothing (GAUDIT_RUN_OK: another run was under way). */
#define GAUDIT_WINDOW_MAX_TASKS 16
guint gaudit_window_home_level(GauditWindow *self);
void gaudit_window_task_running(GauditWindow *self, gsize task_index);
void gaudit_window_task_failed(GauditWindow *self, gsize task_index, gaudit_run_status status);

/* Its run waits for administrator rights, or no longer does. */
void gaudit_window_task_waiting(GauditWindow *self, gsize task_index, gboolean waiting);

/* The switch's disc in the accent colour, while any check waits for it. */
void gaudit_window_set_attention(GauditWindow *self, gboolean on);

/* A result of a task shown on Home, kept for the rest of the session: its
 * row then shows the verdict and what was found. rows (GauditHomeRow, may
 * be NULL): a plugin's condensate of what fails, one row each, copied. */
void gaudit_window_task_report(GauditWindow *self, gsize task_index, gaudit_verdict verdict,
                               const char *title, GPtrArray *rows);

/* A short in-app message at the bottom of the window. */
void gaudit_window_toast(GauditWindow *self, const char *text);

/* The summary at the top of Home, after a result came in. */
void gaudit_window_set_worst(GauditWindow *self, gaudit_verdict worst);

G_END_DECLS
