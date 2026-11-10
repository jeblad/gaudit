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

/* A command to copy: read-only, selectable, always left-to-right, with a
 * copy button. The text is copied. */
GtkWidget *gaudit_command_field_new(const char *command);

/* An explanation that starts as its own first line, cut off with "…", and
 * opens to the whole text. It reads as the start of something to read on,
 * not as "help", so a capable user is not talked down to. */
GtkWidget *gaudit_teaser_row_new(const char *text);

/* A button that starts something, shaped like a dialog's buttons. It has
 * a chevron when it opens a new page (even one that asks for a password
 * at once), none when it acts in place (e.g. opens a dialog). Accent
 * colour only when it is the page's one obvious default. */
GtkWidget *gaudit_action_button_new(const char *label, gboolean opens_page, gboolean is_default);

/* Page 1 for a task: settings, or an explanation if software is missing. */
AdwNavigationPage *gaudit_task_page_new(const GauditTaskInfo *task,
                                       const gaudit_pkg_backend *pkg);

G_END_DECLS
