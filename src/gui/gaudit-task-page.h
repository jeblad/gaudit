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

/* The same for a file's text, several lines: the copy button at the top,
 * named for copying the text. What is copied is checked the same way. */
GtkWidget *gaudit_file_field_new(const char *text);

/* The same, with a button beside the copy button that runs the fix the
 * command shows: run_args are the orchestrator's (a plugin's fixed
 * operation, built from cached data, never from the shown text), run only
 * while the field still shows command. NULL: no such button. */
GtkWidget *gaudit_command_field_new_run(const char *command, const char *const *run_args);
/* The same, with what to say if the command stops with an error (may be
 * NULL: then a general text). */
GtkWidget *gaudit_command_field_new_step(const char *command, const char *const *run_args,
                                         const char *failed);

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

/* One step of a fix: the command as it runs (shown, copied, and run with
 * run_args, which may be NULL for copy only), and what each part of it
 * does in plain words (NULL-terminated, may be NULL), so the user knows
 * what is done on their behalf. A run_args starting with "session" goes
 * through the session as root (e.g. { "session", "run", "apt-update" }).
 * failed (may be NULL) is what the page says if it stops with an error,
 * when the step knows what that most likely means. */
typedef struct {
    const char *command;
    const char *const *run_args;
    const char *const *explain;
    const char *failed;
} GauditFixStep;

/* A fix page with one or more steps, each with its own field and buttons:
 * never one compound command. on_fixed (may be NULL) is called after any
 * step that ran and succeeded. */
AdwNavigationPage *gaudit_fix_page_new_steps(const char *title, const char *problem,
                                             const char *how, const GauditFixStep *steps,
                                             gsize n_steps, const char *note,
                                             GauditFixedFn on_fixed, gpointer data,
                                             GDestroyNotify data_free);

/* One way of writing gAudit's own configuration, through the helper:
 * label for the button and the confirmation, summary in plain language
 * (what is written where, what it does), command the session's run
 * (e.g. "run automatic-updates-on"). */
typedef struct {
    const char *label;
    const char *summary;
    const char *command;
} GauditConfAction;

/* A fix page that changes configuration with gAudit's own operation:
 * problem and how as on any fix page, then the buttons for undo and apply
 * (either may be NULL), each confirmed with its summary first. Both stay
 * in view, apart; applied: gAudit's setting is in place, so apply is
 * greyed out and undo can be used, and the other way round; after either
 * has run, they swap. The run waits for administrator rights like any
 * other (the switch); the page then says what happened. after (may be
 * NULL) is called once something was written or removed, to check again.
 * Only gAudit's own operations have an undo: what a system tool changes
 * cannot be known in full. The standard for such pages: apply carries its
 * label and the accent, as the default, at the end; undo, to its left, is
 * a plain "Undo", never the default, with undo->label (e.g. "Remove
 * gAudit's Setting") as its tooltip and as the confirmation's heading. */
AdwNavigationPage *gaudit_fix_page_new_conf(const char *title, const char *problem,
                                            const char *how, const char *note,
                                            const GauditConfAction *apply,
                                            const GauditConfAction *undo, gboolean applied,
                                            GauditFixedFn after, gpointer data,
                                            GDestroyNotify data_free);

/* Page 0, information about the plugin: its icon, name and short
 * description, then what it does, in full. Built from the plugin's
 * description, all plain text: no markup and no links, so a plugin cannot
 * look like gAudit. */
typedef enum {
    GAUDIT_INFO_PLAIN,       /* no page of the plugin's to speak of */
    GAUDIT_INFO_PARAMETERS,  /* opened from Parameters */
    GAUDIT_INFO_SIMPLIFIED,  /* opened from the simplified report Home made */
    GAUDIT_INFO_REPORT,      /* opened from the (full) report */
    GAUDIT_INFO_HOME,        /* Home's own information page */
} GauditInfoFrom;

/* from: the page it was opened from, which gets a block of its own. */
AdwNavigationPage *gaudit_plugin_about_page_new(const GauditTaskInfo *task, GauditInfoFrom from);

/* Home's information page, in the same shape: what Home shows, why, and
 * how its levels, groups and password work. */
AdwNavigationPage *gaudit_home_info_page_new(void);

/* The plugin's About dialog: name, icon, version, owner, license, source. */
void gaudit_plugin_about_dialog(const GauditTaskInfo *task, GtkWidget *parent);

/* Page 1 for a task: settings, or an explanation if software is missing. */
AdwNavigationPage *gaudit_task_page_new(const GauditTaskInfo *task,
                                       const gaudit_pkg_backend *pkg);

G_END_DECLS
