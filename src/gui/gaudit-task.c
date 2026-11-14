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

const char *gaudit_task_home_command(const GauditTaskInfo *task, guint level)
{
    if (level >= GAUDIT_LEVEL_COUNT)
        level = GAUDIT_LEVEL_COUNT - 1;
    for (int l = (int)level; l >= 0; l--)
        if (task->home_commands[l] != NULL)
            return task->home_commands[l];
    if (task->home_level > 0 && task->home_level <= level)
        return task->run_command;
    return NULL;
}

guint gaudit_task_home_from(const GauditTaskInfo *task)
{
    for (guint l = 0; l < GAUDIT_LEVEL_COUNT; l++)
        if (gaudit_task_home_command(task, l) != NULL)
            return l;
    return GAUDIT_LEVEL_COUNT;
}

const GauditTaskInfo *gaudit_task_for_command(const char *command, gsize *index)
{
    gsize n_tasks;
    const GauditTaskInfo *all = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; command != NULL && i < n_tasks; i++) {
        gboolean match = g_strcmp0(all[i].run_command, command) == 0;
        for (guint l = 0; !match && l < GAUDIT_LEVEL_COUNT; l++)
            match = g_strcmp0(all[i].home_commands[l], command) == 0;
        if (match) {
            if (index != NULL)
                *index = i;
            return &all[i];
        }
    }
    return NULL;
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
