/* SPDX-License-Identifier: GPL-3.0-only */
/* Task registry: one entry per sidebar item (Home excluded). */
#pragma once

#include <adwaita.h>
#include <glib.h>

#include "gaudit/backend.h"

G_BEGIN_DECLS

/* Home's report levels; each includes everything the ones below show. */
enum { GAUDIT_LEVEL_QUICK = 0, GAUDIT_LEVEL_NORMAL, GAUDIT_LEVEL_THOROUGH, GAUDIT_LEVEL_COUNT };

/* Only on/off parameters for now. Strings are N_()-marked; translate at use. */
typedef struct {
    const char *id;
    const char *title;
    const char *subtitle;
    gboolean default_value;
} GauditTaskParam;

typedef struct {
    const char *id;
    const char *title;
    const char *summary;   /* one sentence */
    const char *details;   /* longer explanation for non-technical users */
    const char *icon;
    const char *const *capabilities;  /* NULL-terminated, resolved by the backend */
    const GauditTaskParam *params;
    gsize n_params;
    const char *run_command;  /* the orchestrator session's command for a run */
    const char *home_probe;   /* id of the Home row that leads here (e.g. "status.firewall"),
                                 which then stands for the task on Home; NULL for none */
    const char *home_tooltip; /* for the button on that row, N_()-marked */
    guint home_level;         /* a check run in the helper: the Home report level it runs
                                 at (GAUDIT_LEVEL_NORMAL, _THOROUGH); 0: not on Home */
    /* A plugin that collects for its rule script: its collection command
     * per Home report level (NULL where it has none), e.g. [QUICK]
     * "user secrets quick". run_command is then its full collection. */
    const char *home_commands[GAUDIT_LEVEL_COUNT];
    const char *home_title;   /* that row's title, N_()-marked */
    gboolean needs_admin;     /* its run needs administrator rights (the password) */
    /* A plugin whose run is a collection for its rule script (run_command
     * "user <mode>"): checks one line of the collection strictly, and says
     * whether it is the last. NULL for runs that give a result directly. */
    gboolean (*collection_line)(const char *line, gboolean *last);
    const char *text_domain;  /* the plugin's own, for its report and fix pages */
    /* The page for a fix a report row names; item_line is the collection
     * line it is about, from the validated cache. NULL: no fixes. */
    AdwNavigationPage *(*fix_page)(const char *fix_id, const char *item_line);
    const char *backend;      /* only with this package backend (e.g. "debian"); NULL: any */
    const char *run_waiting;  /* page 2 while the password is asked for, N_()-marked */
    const char *run_running;  /* page 2 while the check runs, N_()-marked */
} GauditTaskInfo;

/* The tasks for this system: those whose backend matches the one in use.
 * Indexes into this array are stable for the life of the process. */
const GauditTaskInfo *gaudit_tasks_get(gsize *n_tasks);

/* The command task runs for Home at level: its own command for the
 * nearest level at or below it (the fallback), or NULL when it has no
 * report on Home at that level. */
const char *gaudit_task_home_command(const GauditTaskInfo *task, guint level);

/* The lowest level task has a Home report at; GAUDIT_LEVEL_COUNT for none. */
guint gaudit_task_home_from(const GauditTaskInfo *task);

/* The task that runs command (its own or a Home one), with its index; NULL
 * for none. */
const GauditTaskInfo *gaudit_task_for_command(const char *command, gsize *index);

/* Packages needed by the task that are not installed.
 * Empty array: everything is in place. NULL: the task is not supported on
 * this distro. Only for presentation — the helper re-checks everything. */
GPtrArray *gaudit_task_missing_packages(const GauditTaskInfo *task,
                                        const gaudit_pkg_backend *pkg);

G_END_DECLS
