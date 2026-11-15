/* SPDX-License-Identifier: GPL-3.0-only */
/* Content pages for tasks: settings (page 1), run (page 2), missing software. */
#pragma once

#include <adwaita.h>

#include "gaudit-task.h"
#include "gaudit/model.h"

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

/* The same, with a button beside the copy button that runs the fix the
 * command shows: run_args are the orchestrator's (a plugin's fixed
 * operation, built from cached data, never from the shown text), run only
 * while the field still shows command. NULL: no such button. */
GtkWidget *gaudit_command_field_new_run(const char *command, const char *const *run_args);

/* Called once a fix run from a command field has succeeded (e.g. to check
 * the finding again). */
typedef void (*GauditFixedFn)(gpointer user_data);

/* An explanation that starts as its own first line, cut off with "…", and
 * opens to the whole text. It reads as the start of something to read on,
 * not as "help", so a capable user is not talked down to. */
GtkWidget *gaudit_teaser_row_new(const char *text);

/* A button that starts something, shaped like a dialog's buttons. It has
 * a chevron when it opens a new page (even one that asks for a password
 * at once), none when it acts in place (e.g. opens a dialog). Accent
 * colour only when it is the page's one obvious default. */
GtkWidget *gaudit_action_button_new(const char *label, gboolean opens_page, gboolean is_default);

/* A verdict as an icon with its own shape (check mark, warning, error,
 * question mark), a tooltip and an accessible label, so it never depends
 * on colour alone. */
GtkWidget *gaudit_verdict_icon_new(gaudit_verdict verdict);

/* A page that fixes one problem a report found, reached through the
 * chevron on the row where the problem is, so the report itself stays a
 * report. problem says what is wrong, how what to do; command (may be
 * NULL) is the manual way, to copy and run; note (may be NULL) comes
 * last, small; run_args (may be NULL) let gAudit run the fix itself, from
 * a button beside the copy button. All plain text. */
AdwNavigationPage *gaudit_fix_page_new(const char *title, const char *problem, const char *how,
                                       const char *command, const char *note,
                                       const char *const *run_args, GauditFixedFn on_fixed,
                                       gpointer data, GDestroyNotify data_free);

/* Page 1 for a task: settings, or an explanation if software is missing. */
AdwNavigationPage *gaudit_task_page_new(const GauditTaskInfo *task,
                                       const gaudit_pkg_backend *pkg);

G_END_DECLS
