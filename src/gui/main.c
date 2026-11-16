/* SPDX-License-Identifier: GPL-3.0-only */
#include "config.h"

#include <glib/gi18n.h>
#include <locale.h>

#include "gaudit-app.h"
#include "gaudit-environ.h"
#include "gaudit-task.h"

int main(int argc, char *argv[])
{
    /* Before anything is loaded: no code from the caller's environment. */
    gaudit_environ_clean(argv);
    setlocale(LC_ALL, "");
    /* Compiled-in path only: a user-controlled translation catalog could make
     * a red finding read as green. */
    bindtextdomain(GETTEXT_PACKAGE, GAUDIT_LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
    textdomain(GETTEXT_PACKAGE);
    /* Each plugin's own domain, from the same compiled-in directory. */
    gsize n_tasks;
    const GauditTaskInfo *tasks = gaudit_tasks_get(&n_tasks);
    for (gsize i = 0; i < n_tasks; i++)
        if (tasks[i].text_domain != NULL) {
            bindtextdomain(tasks[i].text_domain, GAUDIT_LOCALEDIR);
            bind_textdomain_codeset(tasks[i].text_domain, "UTF-8");
        }
    g_set_application_name(GAUDIT_APP_NAME);

    g_autoptr(GauditApp) app = gaudit_app_new();
    return g_application_run(G_APPLICATION(app), argc, argv);
}
