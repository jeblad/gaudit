/* SPDX-License-Identifier: GPL-3.0-only */
/* Controller: owns the model, creates and updates the view. */
#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define GAUDIT_TYPE_APP (gaudit_app_get_type())
G_DECLARE_FINAL_TYPE(GauditApp, gaudit_app, GAUDIT, APP, AdwApplication)

GauditApp *gaudit_app_new(void);

G_END_DECLS
