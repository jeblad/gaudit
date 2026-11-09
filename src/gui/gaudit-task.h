/* SPDX-License-Identifier: GPL-3.0-only */
/* Task registry: one entry per sidebar item (Home excluded). */
#pragma once

#include <glib.h>

#include "gaudit/backend.h"

G_BEGIN_DECLS

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
} GauditTaskInfo;

const GauditTaskInfo *gaudit_tasks_get(gsize *n_tasks);

/* Packages needed by the task that are not installed.
 * Empty array: everything is in place. NULL: the task is not supported on
 * this distro. Only for presentation — the helper re-checks everything. */
GPtrArray *gaudit_task_missing_packages(const GauditTaskInfo *task,
                                        const gaudit_pkg_backend *pkg);

G_END_DECLS
