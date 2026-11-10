/* SPDX-License-Identifier: GPL-3.0-only */
/* View: presents verdicts. Holds no security logic. */
#pragma once

#include <adwaita.h>

#include "gaudit/model.h"
#include "gaudit/probe.h"

G_BEGIN_DECLS

#define GAUDIT_TYPE_WINDOW (gaudit_window_get_type())
G_DECLARE_FINAL_TYPE(GauditWindow, gaudit_window, GAUDIT, WINDOW, AdwApplicationWindow)

GauditWindow *gaudit_window_new(GtkApplication *app);

/* Show or hide the red disc before the title that marks elevated rights. */
void gaudit_window_set_elevated(GauditWindow *self, gboolean elevated);

/* Status for Home: probe results plus the overall verdict from the model. */
void gaudit_window_show_status(GauditWindow *self,
                               const gaudit_probe_result results[GAUDIT_PROBE_COUNT],
                               gaudit_verdict worst);

G_END_DECLS
