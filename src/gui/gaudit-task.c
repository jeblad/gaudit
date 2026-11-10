/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include "gaudit-task.h"

#include <glib/gi18n.h>

/* Built-in tasks, written in C until the plugin description format exists;
 * they then move to it and are marked core. */
static const GauditTaskInfo tasks[] = {
    {
        .id = "core.firewall",
        .title = N_("Firewall"),
        .summary = N_("Checks that a firewall is actually filtering incoming network traffic."),
        .details = N_("A firewall decides which connections from other computers may reach "
                      "this one. Having a firewall program installed is not enough: it also "
                      "has to be switched on. This check looks at the rules the system is "
                      "using right now, whichever program set them up.\n\n"
                      "Reading the rules needs the administrator password, because only the "
                      "administrator may look at them. gAudit only reads the rules; it "
                      "changes nothing."),
        .icon = "fire-symbolic",
        .capabilities = NULL,  /* reads the kernel's rules: nothing to install */
        .params = NULL,
        .n_params = 0,
        .run_command = "run firewall",
        .home_probe = "status.firewall",
        .home_tooltip = N_("Thorough check of the firewall"),
        .home_elevated = TRUE,
    },
};

const GauditTaskInfo *gaudit_tasks_get(gsize *n_tasks)
{
    *n_tasks = G_N_ELEMENTS(tasks);
    return tasks;
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
