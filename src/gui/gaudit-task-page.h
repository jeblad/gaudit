/* SPDX-License-Identifier: GPL-3.0-only */
/* Content pages for tasks: settings (page 1), run (page 2), missing software. */
#pragma once

#include <adwaita.h>

#include "gaudit-task.h"

G_BEGIN_DECLS

/* Wrap content in a navigation page with its own header bar. */
AdwNavigationPage *gaudit_page_wrap(GtkWidget *content, const char *title, const char *tag);

/* A page explaining that software is missing, with the install command.
 * packages: NULL-terminated, from the backend's fixed table. */
AdwNavigationPage *gaudit_missing_software_page_new(const gaudit_pkg_backend *pkg,
                                                    const char *title,
                                                    const char *const *packages);

/* Page 1 for a task: settings, or an explanation if software is missing. */
AdwNavigationPage *gaudit_task_page_new(const GauditTaskInfo *task,
                                       const gaudit_pkg_backend *pkg);

G_END_DECLS
