/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "gaudit-task.h"
#include "gaudit-plugins.h"

#include <glib/gi18n.h>

/* The built-in plugins, each in its own folder under src/plugins/. */
static const GauditTaskInfo *const tasks[] = {
    &gaudit_plugin_firewall,
    &gaudit_plugin_updates,
    &gaudit_plugin_private_files,
};

const GauditTaskInfo *gaudit_tasks_get(gsize *n_tasks)
{
    static GauditTaskInfo available[G_N_ELEMENTS(tasks)];
    static gsize n_available;
    static gsize once;
    if (g_once_init_enter(&once)) {
        const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
        for (gsize i = 0; i < G_N_ELEMENTS(tasks); i++)
            if (tasks[i]->backend == NULL || (pkg != NULL && g_strcmp0(tasks[i]->backend, pkg->name) == 0))
                available[n_available++] = *tasks[i];
        g_once_init_leave(&once, 1);
    }
    *n_tasks = n_available;
    return available;
}

GPtrArray *gaudit_task_missing_packages(const GauditTaskInfo *task,
                                        const gaudit_pkg_backend *pkg)
{
    g_autoptr(GPtrArray) missing = g_ptr_array_new();

    for (const char *const *c = task->capabilities; c != NULL && *c != NULL; c++) {
        const gaudit_capability *cap = pkg->capability ? pkg->capability(*c) : NULL;
        if (cap == NULL)
            return NULL;
        if (gaudit_capability_present(cap))
            continue;
        for (const char *const *name = cap->packages; *name != NULL; name++)
            if (!g_ptr_array_find_with_equal_func(missing, *name, g_str_equal, NULL))
                g_ptr_array_add(missing, (gpointer)*name);
    }
    return g_steal_pointer(&missing);
}
