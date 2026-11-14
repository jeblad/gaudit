/* SPDX-License-Identifier: GPL-3.0-only */
/* Task registry: one entry per sidebar item (Home excluded). */
#pragma once

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
    guint home_level;         /* the Home report level it runs at (GAUDIT_LEVEL_NORMAL,
                                 _THOROUGH), as a row in its group; 0: not on Home */
    const char *home_title;   /* that row's title, N_()-marked */
    const char *backend;      /* only with this package backend (e.g. "debian"); NULL: any */
    const char *run_waiting;  /* page 2 while the password is asked for, N_()-marked */
    const char *run_running;  /* page 2 while the check runs, N_()-marked */
} GauditTaskInfo;

/* The tasks for this system: those whose backend matches the one in use.
 * Indexes into this array are stable for the life of the process. */
const GauditTaskInfo *gaudit_tasks_get(gsize *n_tasks);

/* Packages needed by the task that are not installed.
 * Empty array: everything is in place. NULL: the task is not supported on
 * this distro. Only for presentation — the helper re-checks everything. */
GPtrArray *gaudit_task_missing_packages(const GauditTaskInfo *task,
                                        const gaudit_pkg_backend *pkg);

G_END_DECLS
