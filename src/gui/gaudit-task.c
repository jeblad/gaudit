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
        .icon = "gaudit-fire-symbolic",
        .capabilities = NULL,  /* reads the kernel's rules: nothing to install */
        .params = NULL,
        .n_params = 0,
        .run_command = "run firewall",
        .home_probe = "status.firewall",
        .home_tooltip = N_("Thorough check of the firewall"),
        .home_level = GAUDIT_LEVEL_NORMAL,  /* under a second */
        .home_title = N_("Firewall rules"),
        .run_waiting = N_("Reading the firewall rules needs the administrator password."),
        .run_running = N_("Checking the firewall…"),
    },
    {
        .id = "core.updates",
        .title = N_("Updates"),
        .summary = N_("Checks that your software is kept up to date, and that the files it was "
                      "installed with have not been changed since."),
        .details = N_("Home shows whether updates are found and installed. The thorough check "
                      "here goes further.\n\n"
                      "Every program installed from a package comes with a list of its files "
                      "and a checksum for each. This check reads every one of those files and "
                      "compares it with its checksum, so a changed or missing file shows up, "
                      "whether a person, a program or malware changed it. Your own settings "
                      "in /etc are not counted: changing them is normal.\n\n"
                      "It reads tens of thousands of files and can take from half a minute to "
                      "several minutes. Reading all of them needs the administrator password. "
                      "gAudit only reads; it changes nothing.\n\n"
                      "A clean result means no changes were found, not that the computer is "
                      "proven clean: the checksums are not signed once installed, so someone "
                      "with full control of the computer could change them too."),
        .icon = "gaudit-packages-symbolic",
        .capabilities = NULL,
        .params = NULL,
        .n_params = 0,
        .run_command = "run integrity",
        .home_probe = NULL,
        .home_tooltip = NULL,
        .home_level = GAUDIT_LEVEL_THOROUGH,  /* a minute or more */
        .home_title = N_("Package files"),
        .backend = "debian",  /* reads dpkg's md5sums */
        .run_waiting = N_("Reading every package file needs the administrator password."),
        .run_running = N_("Checking the package files… This can take a few minutes."),
    },
};

const GauditTaskInfo *gaudit_tasks_get(gsize *n_tasks)
{
    static GauditTaskInfo available[G_N_ELEMENTS(tasks)];
    static gsize n_available;
    static gsize once;
    if (g_once_init_enter(&once)) {
        const gaudit_pkg_backend *pkg = gaudit_pkg_backend_default();
        for (gsize i = 0; i < G_N_ELEMENTS(tasks); i++)
            if (tasks[i].backend == NULL || (pkg != NULL && g_strcmp0(tasks[i].backend, pkg->name) == 0))
                available[n_available++] = tasks[i];
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
