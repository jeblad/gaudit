/* SPDX-License-Identifier: GPL-3.0-only */
/* View: presents verdicts. Holds no security logic. */
#pragma once

#include <adwaita.h>

#include "gaudit/model.h"
#include "gaudit/probe.h"
#include "gaudit/run.h"

G_BEGIN_DECLS

#define GAUDIT_TYPE_WINDOW (gaudit_window_get_type())
G_DECLARE_FINAL_TYPE(GauditWindow, gaudit_window, GAUDIT, WINDOW, AdwApplicationWindow)

GauditWindow *gaudit_window_new(GtkApplication *app);

/* Show or hide the red disc before the title that marks elevated rights. */
void gaudit_window_set_elevated(GauditWindow *self, gboolean elevated);

/* Status for Home: probe results plus the overall verdict from the model. */
/* Status on Home, row by row: begin shows every row as being checked,
 * show_probe fills in one row as its answer arrives, finish sets the
 * summary once every row has its answer. */
void gaudit_window_begin_status(GauditWindow *self);
void gaudit_window_show_probe(GauditWindow *self, const gaudit_probe_result *result);
void gaudit_window_finish_status(GauditWindow *self, gaudit_verdict worst);

/* Home's checks that need the password (tasks marked home_elevated), run
 * together by the controller: begin shows them as running, result fills
 * in one (by task index), busy says another run is under way, end
 * re-enables the button and updates the summary. */
#define GAUDIT_WINDOW_MAX_TASKS 16
void gaudit_window_elevated_begin(GauditWindow *self);
void gaudit_window_elevated_result(GauditWindow *self, gsize task_index, gaudit_run_status status,
                                   const gaudit_firewall_report *result);
void gaudit_window_elevated_busy(GauditWindow *self);
void gaudit_window_elevated_end(GauditWindow *self, gaudit_verdict worst);

G_END_DECLS
